"""Recovery survives restarts without silently exporting or changing source evidence."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from threading import Event
import unittest
import zipfile
from unittest.mock import patch

from PySide6.QtWidgets import QApplication
from artifacts.file_collector import FileCollector
from controllers.scan_controller import ScanEngine
from controllers.export_controller import ZipExporter
from interface.main_window import MainWindow
from interface.widgets.recovery_options import RecoveryOptions
from reporting.coverage import build_summary
from storage.memory_store import MemoryStore
from storage.recovery import load_session
from tests.test_scan import configuration
from shiboken6 import delete


class PersistentRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.app=QApplication.instance() or QApplication([])
    def setUp(self):
        self.target = tempfile.TemporaryDirectory(); self.addCleanup(self.target.cleanup)
        self.destination = tempfile.TemporaryDirectory(); self.addCleanup(self.destination.cleanup)
        self.root, self.dest = Path(self.target.name), Path(self.destination.name)
        for index in range(3): (self.root/f'file{index}.txt').write_bytes(f'evidence {index}'.encode())
        self.path = self.dest/'progress.terra-session'
    def paused(self, cache=True):
        config=configuration(); config['recovery']={'path': str(self.path)}
        cancelled=Event()
        engine=ScanEngine({'paths':[str(self.root)]}, config, MemoryStore(), cancelled,
                          on_finding=lambda row:cancelled.set(), collector=FileCollector() if cache else FileCollector(max_file_bytes=0))
        summary=engine.run()
        self.assertEqual(summary['status'],'stopped',engine.store.diagnostics)
        self.assertEqual(len(engine.store.records),1)
        return engine

    def test_mount_snapshot_survives_recovery_and_older_sessions_remain_loadable(self):
        original = self.paused()
        restored, _, _ = load_session(self.path)
        self.assertEqual(restored.volume_metadata, original.volume_metadata)
        with sqlite3.connect(self.path) as connection:
            state = json.loads(connection.execute('SELECT state FROM session WHERE id=1').fetchone()[0])
            state.pop('volume_metadata')
            if state.get('summary'):
                state['summary'].pop('volume_metadata', None)
            encoded = json.dumps(state)
            connection.execute('UPDATE session SET state=?, sha256=? WHERE id=1',
                               (encoded, hashlib.sha256(encoded.encode()).hexdigest()))
        older, _, _ = load_session(self.path)
        self.assertEqual(older.volume_metadata, [])
        self.assertEqual(older.run()['status'], 'completed')

    def test_unselected_recovery_does_not_write_progress(self):
        ScanEngine({'paths':[str(self.root)]}, configuration(), MemoryStore()).run()
        self.assertFalse(list(self.dest.iterdir()))
        self.assertEqual(len(list(self.root.iterdir())),3)

    def test_roundtrip_after_new_engine_skips_completed_and_preserves_original_bytes(self):
        original=self.paused()
        restored, context, summary=load_session(self.path)
        self.assertIsNot(restored,original)
        self.assertEqual(restored.store.records[0]['data'],original.store.records[0]['data'])
        self.assertEqual(restored.finished_paths,original.finished_paths)
        self.assertEqual(restored.run()['status'],'completed')
        self.assertEqual(len(restored.store.records),3)
        self.assertEqual(restored.counts['examined'],3)
        again,_,summary=load_session(self.path)
        self.assertEqual(summary['status'],'completed')
        self.assertEqual(len(again.finished_paths),3)
        self.assertEqual(self.path.stat().st_mode & 0o777,0o600)

    def test_changed_cached_file_is_researched_and_both_versions_export_without_collision(self):
        self.paused()
        restored,_,_=load_session(self.path)
        changed=Path(restored.store.records[0]['path']); old=changed.read_bytes()
        changed.write_bytes(b'new evidence')
        summary=restored.run()
        self.assertEqual(summary['status'],'completed')
        revisions=[row for row in restored.store.records if row['path']==str(changed)]
        self.assertEqual(len(revisions),2)
        records,logs,count=restored.store.snapshot()
        output=self.dest/'evidence.zip'
        ZipExporter(records,logs,count,{'targets':restored.targets,'scan_summary':summary}).save(output)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(len(archive.namelist()),len(set(archive.namelist())))
            historical=next(name for name in archive.namelist() if name.startswith('terra/evidence-versions/') and name.endswith(changed.name))
            current=next(name for name in archive.namelist() if name.startswith('evidence/') and name.endswith(changed.name))
            self.assertEqual(archive.read(historical),old)
            self.assertEqual(archive.read(current),b'new evidence')

    def test_changed_uncached_file_keeps_metadata_without_claiming_old_bytes_exported(self):
        self.paused(cache=False)
        restored,_,_=load_session(self.path)
        Path(restored.store.records[0]['path']).write_bytes(b'changed')
        summary=restored.run()
        self.assertTrue(restored.store.records[0]['original_bytes_unavailable'])
        records,logs,count=restored.store.snapshot()
        result=ZipExporter(records,logs,count,{'targets':restored.targets,'scan_summary':summary}).save(self.dest/'export.zip')
        self.assertEqual(result['file_count'],3)
        self.assertEqual(result['coverage_summary']['original_files_unavailable'],1)
        with zipfile.ZipFile(result['path']) as archive:
            manifest=json.loads(archive.read('terra/manifest.json'))
            self.assertEqual(manifest['entries'][0]['export_status'],'original_bytes_unavailable')
            self.assertIsNone(manifest['entries'][0]['archive_path'])

    def test_checkpoint_corruption_is_rejected_before_gui_acceptance(self):
        self.paused()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("UPDATE records SET data=? WHERE id=0", (b'changed',))
        with self.assertRaisesRegex(ValueError,'Corrupt'): load_session(self.path)

    def test_hot_journal_after_process_crash_recovers_last_committed_session(self):
        self.paused()
        code='''import os,sqlite3,sys
connection=sqlite3.connect(sys.argv[1])
connection.execute('PRAGMA cache_size=1')
connection.execute('BEGIN IMMEDIATE')
connection.execute('UPDATE records SET data=zeroblob(200000) WHERE id=0')
os._exit(0)
'''
        import sys
        subprocess.run([sys.executable,'-c',code,str(self.path)],check=True)
        restored,_,summary=load_session(self.path)
        self.assertEqual(summary['status'],'stopped')
        self.assertEqual(len(restored.store.records),1)
        self.assertEqual(hashlib.sha256(restored.store.records[0]['data']).hexdigest(),restored.store.records[0]['sha256'])

    def test_new_progress_does_not_overwrite_and_target_acknowledgement_is_required(self):
        self.path.write_bytes(b'existing evidence')
        cfg=configuration();cfg['recovery']={'path':str(self.path)}
        result=ScanEngine({'paths':[str(self.root)]},cfg,MemoryStore()).run()
        self.assertEqual(result['status'],'failed')
        self.assertEqual(self.path.read_bytes(),b'existing evidence')
        on_target=self.root/'progress.terra-session'
        cfg['recovery']={'path':str(on_target)}
        self.assertEqual(ScanEngine({'paths':[str(self.root)]},cfg,MemoryStore()).run()['status'],'failed')
        self.assertFalse(on_target.exists())
        widget=RecoveryOptions();widget.targets={'paths':[str(self.root)]};widget.enabled.setChecked(True)
        widget.path.setText(str(on_target))
        with self.assertRaises(ValueError): widget.values()
        widget.acknowledgement.setChecked(True)
        self.assertTrue(widget.values()['allow_target'])
        widget.deleteLater()

    def test_missing_target_stops_resume_and_retains_findings(self):
        self.paused(); restored,_,_=load_session(self.path)
        renamed=self.root.with_name(self.root.name+'-moved')
        self.root.rename(renamed)
        try:
            self.assertEqual(restored.run()['status'],'stopped')
            self.assertEqual(len(restored.store.records),1)
        finally: renamed.rename(self.root)
        restored.cancel.clear()
        self.assertEqual(restored.run()['status'],'completed')

    def test_restore_gui_and_resume_preserve_configuration_without_ram_reacquisition(self):
        self.paused(); engine,ctx,summary=load_session(self.path)
        window=MainWindow();self.addCleanup(delete,window)
        with patch.object(window.ram_controller,'start') as ram:
            window.recovery_loaded(dict(status='loaded',engine=engine,context=ctx,summary=summary))
            ram.assert_not_called()
        self.assertIs(window.stack.currentWidget(),window.analysis)
        self.assertIs(window.scan_controller.store,engine.store)
        self.assertFalse(window.analysis.resume_button.isHidden())
        with patch.object(window.scan_controller,'resume') as resume:
            window.analysis.resume_button.click();resume.assert_called_once()

    def test_export_summary_has_logs_and_is_shown_only_after_success(self):
        from interface.pages.export import ExportPage
        engine=self.paused()
        engine.log('locked.zip','encrypted member could not be searched','warning')
        summary=dict(engine.last_summary,coverage=engine.coverage_summary())
        records,logs,count=engine.store.snapshot()
        result=ZipExporter(records,logs,count,{'targets':engine.targets,'scan_summary':summary,'partial_scan':True}).save(self.dest/'partial.zip')
        page=ExportPage();self.assertTrue(page.coverage.isHidden())
        page.finish(result);self.assertFalse(page.coverage.isHidden())
        self.assertIn('Protected inputs',page.coverage.toPlainText())
        with zipfile.ZipFile(result['path']) as archive:
            self.assertIn('terra/reports/collection-summary.txt',archive.namelist())
            self.assertIn('terra/reports/collection-summary.json',archive.namelist())
            coverage=json.loads(archive.read('terra/reports/collection-summary.json'))
            self.assertTrue(coverage['partial_collection'])
            self.assertEqual(coverage['diagnostic_events']['protected_inputs'],1)
        page.deleteLater()

    def test_moved_recovery_requires_target_write_acknowledgement_and_restores_back_controls(self):
        self.paused()
        moved = self.root/'moved.terra-session'
        self.path.rename(moved)
        engine,ctx,summary = load_session(moved)
        window = MainWindow(); self.addCleanup(delete,window)
        window.recovery_loaded(dict(status='loaded',engine=engine,context=ctx,summary=summary))
        self.assertFalse(window.analysis.recovery_acknowledgement.isHidden())
        self.assertEqual(window.configuration.recovery.path.text(),str(moved))
        self.assertEqual(window.targets.folders.item(0).text(),str(self.root))
        with patch.object(window.scan_controller,'resume') as resume:
            window.resume_triage(); resume.assert_not_called()
            window.analysis.recovery_acknowledgement.setChecked(True)
            window.resume_triage(); resume.assert_called_once()
