import errno
import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ['QT_QPA_PLATFORMTHEME'] = 'generic'

from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox
from artifacts.file_collector import FileCollector
from controllers.scan_controller import ScanEngine
from controllers.export_controller import ZipExporter, ExportCancelled, ExportController, ArchivePaths
from interface.main_window import MainWindow
from interface.pages.export import ExportPage
from storage.memory_store import MemoryStore


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.target = self.root / 'target'
        self.target.mkdir()
        self.destination = self.root / 'result.zip'
        self.targets = {'paths': [str(self.target)], 'acquire_ram': False}
        self.config = {'options': dict(folder_names=False, file_names=False, file_contents=False, hash_matches=False),
                       'collection_mode': 'all_supported', 'hashes': [], 'keywords': []}
        self.case = {'id': 'CASE-42', 'name': 'Example Case', 'examiner': 'Examiner'}

    def file(self, name, data=b'evidence'):
        path = self.target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def scan(self, collector=None):
        self.store = MemoryStore()
        self.summary = ScanEngine(self.targets, self.config, self.store, collector=collector).run()
        self.context = {'targets': self.targets, 'case': self.case, 'configuration': self.config, 'scan_summary': self.summary}
        records, diagnostics, count = self.store.snapshot()
        return ZipExporter(records, diagnostics, count, self.context)

    def assert_no_partial_export(self):
        self.assertFalse(self.destination.exists())
        self.assertFalse(list(self.root.glob('.terra-export-*.part')))

    def test_finish_without_export_requires_confirmation(self):
        window = MainWindow()
        window.from_case = True
        for answer in (QMessageBox.StandardButton.No, QMessageBox.StandardButton.Yes):
            with self.subTest(answer=answer), patch('interface.main_window.QMessageBox.question', return_value=answer) as prompt, patch.object(window, 'close') as close:
                window.export.finish_button.click()
                prompt.assert_called_once()
                self.assertEqual(close.called, answer == QMessageBox.StandardButton.Yes)
                self.assertEqual(prompt.call_args.args[-1], QMessageBox.StandardButton.No)
        window.deleteLater()

    def test_successful_export_finishes_without_prompt_even_after_destination_change(self):
        window = MainWindow()
        window.export_completed(dict(status='saved', file_count=0, path='/tmp/results.zip', archive_sha256='abc'))
        window.export.destination.setText('/tmp/another.zip')
        with patch('interface.main_window.QMessageBox.question') as prompt, patch.object(window, 'close') as close:
            window.export.finish_button.click()
            prompt.assert_not_called()
            close.assert_called_once()
        window.deleteLater()

    def test_failed_export_still_requires_finish_confirmation(self):
        window = MainWindow()
        window.export_completed(dict(status='failed', error='Destination unavailable'))
        with patch('interface.main_window.QMessageBox.question', return_value=QMessageBox.StandardButton.No) as prompt, patch.object(window, 'close') as close:
            window.export.finish_button.click()
            prompt.assert_called_once()
            close.assert_not_called()
        window.deleteLater()

    def test_save_complete_zip_manifest_report_logs_and_checksums(self):
        self.file('.mozilla/firefox/profile/places.sqlite', b'database')
        self.file('.mozilla/firefox/profile/places.sqlite-wal', b'sidecar')
        self.file('documents/test.txt', b'full source contents\r\n')
        exporter = self.scan()
        exporter.diagnostics.append({'level': 'info', 'message': 'test diagnostic'})
        exporter.diagnostic_count += 1
        result = exporter.save(str(self.destination))
        self.assertEqual(result['status'], 'saved')
        self.assertEqual(result['file_count'], 3)
        self.assertEqual(result['archive_sha256'], hashlib.sha256(self.destination.read_bytes()).hexdigest())
        with zipfile.ZipFile(self.destination) as archive:
            self.assertIsNone(archive.testzip())
            manifest = json.loads(archive.read('terra/manifest.json'))
            self.assertEqual(manifest['case'], self.case)
            self.assertEqual(manifest['targets'], self.targets)
            self.assertEqual(manifest['file_count'], 3)
            for entry in manifest['entries']:
                actual = archive.read(entry['archive_path'])
                self.assertEqual(actual, Path(entry['source_path']).read_bytes())
                self.assertEqual(hashlib.sha256(actual).hexdigest(), entry['sha256'])
            database = next(entry for entry in manifest['entries'] if entry['source_path'].endswith('places.sqlite'))
            self.assertEqual(database['archive_path'], ArchivePaths(self.targets).path_for(database['source_path'], database['device']))
            self.assertTrue(archive.read(manifest['report_path']).startswith(b'%PDF-'))
            html_report = archive.read(manifest['html_report_path']).decode('utf-8')
            self.assertEqual(manifest['html_report_path'], manifest['report_path'].removesuffix('.pdf') + '.html')
            self.assertTrue(html_report.startswith('<!doctype html>'))
            self.assertIn(database['sha256'], html_report)
            self.assertIn('Collection coverage', html_report)
            self.assertIn('Example Case', html_report)
            self.assertIn('Content-Security-Policy', html_report)
            from reporting.html_report import build_html_report
            manifest['case']['name'] = '<script>alert("test")</script> مرحبا'
            safe_report = build_html_report(manifest).decode('utf-8')
            self.assertNotIn('<script>', safe_report)
            self.assertIn('&lt;script&gt;', safe_report)
            self.assertIn('مرحبا', safe_report)
            self.assertIn('Example_Case-', manifest['report_path'])
            self.assertIn('test diagnostic', archive.read('terra/logs/diagnostics.jsonl').decode())
            for line in archive.read('terra/checksums.sha256').decode().splitlines():
                digest, name = line.split('  ', 1)
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), digest)

    def test_uncached_file_exports_complete_bytes_without_ram_limit(self):
        source = self.file('large.bin', bytes(range(256)) * 5000)
        exporter = self.scan(FileCollector(max_file_bytes=4))
        self.assertFalse(self.store.records[0]['content_retained'])
        exporter.save(str(self.destination))
        with zipfile.ZipFile(self.destination) as archive:
            manifest = json.loads(archive.read('terra/manifest.json'))
            self.assertEqual(archive.read(manifest['entries'][0]['archive_path']), source.read_bytes())

    def test_changed_uncached_source_aborts_and_cleans_destination(self):
        source = self.file('source.txt')
        exporter = self.scan(FileCollector(max_file_bytes=4))
        source.write_bytes(b'changed source')
        with self.assertRaisesRegex(ValueError, 'changed or was replaced'):
            exporter.save(str(self.destination))
        self.assert_no_partial_export()

    def test_missing_uncached_source_aborts(self):
        source = self.file('source.txt')
        exporter = self.scan(FileCollector(max_file_bytes=4))
        source.unlink()
        with self.assertRaisesRegex(ValueError, 'Cannot export'):
            exporter.save(str(self.destination))
        self.assert_no_partial_export()

    def test_cached_snapshot_exports_original_when_source_removed(self):
        source = self.file('source.txt', b'original')
        exporter = self.scan()
        source.unlink()
        exporter.save(str(self.destination))
        with zipfile.ZipFile(self.destination) as archive:
            self.assertEqual(archive.read(ArchivePaths(self.targets).path_for(str(self.target / 'source.txt'))), b'original')

    def test_never_overwrites_existing_archive(self):
        self.file('source.txt')
        exporter = self.scan()
        self.destination.write_bytes(b'existing evidence')
        with self.assertRaises(FileExistsError):
            exporter.save(str(self.destination))
        self.assertEqual(self.destination.read_bytes(), b'existing evidence')
        self.assertFalse(list(self.root.glob('.terra-export-*.part')))

    def test_bad_destination_and_permission_failure(self):
        self.file('source.txt')
        exporter = self.scan()
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            exporter.save(str(self.root / 'missing' / 'result.zip'))
        with self.assertRaisesRegex(ValueError, '.zip'):
            exporter.save(str(self.root / 'result.txt'))
        with patch('controllers.export_controller.os.open', side_effect=PermissionError('Destination is read-only')):
            with self.assertRaises(PermissionError):
                exporter.save(str(self.destination))
        self.assert_no_partial_export()

    def test_disk_full_and_failed_verification_leave_no_partial_archive(self):
        self.file('source.txt')
        exporter = self.scan()
        with patch.object(exporter, 'write_archive', side_effect=OSError(errno.ENOSPC, 'No space left on device')):
            with self.assertRaises(OSError):
                exporter.save(str(self.destination))
        self.assert_no_partial_export()
        with patch.object(exporter, 'verify_archive', side_effect=ValueError('Archive verification failed')):
            with self.assertRaises(ValueError):
                exporter.save(str(self.destination))
        self.assert_no_partial_export()

    def test_cancel_export_cleans_files(self):
        self.file('source.txt')
        exporter = self.scan()
        exporter.progress = lambda value: exporter.cancel.set()
        with self.assertRaises(ExportCancelled):
            exporter.save(str(self.destination))
        self.assert_no_partial_export()

    def test_target_destination_requires_explicit_acknowledgement(self):
        self.file('source.txt')
        exporter = self.scan()
        destination = self.target / 'export.zip'
        with self.assertRaisesRegex(ValueError, 'acknowledge'):
            exporter.save(str(destination))
        self.assertFalse(destination.exists())
        result = exporter.save(str(destination), allow_target=True)
        self.assertEqual(result['status'], 'saved')

    def test_portable_paths_do_not_collide_or_escape_archive(self):
        for name in ('CON.txt', 'sub/unsafe:?.txt', 'Case/file.txt', 'case/FILE.txt', 'file%.txt'):
            self.file(name)
        exporter = self.scan()
        exporter.save(str(self.destination))
        with zipfile.ZipFile(self.destination) as archive:
            names = [name for name in archive.namelist() if name.startswith('evidence/')]
            self.assertEqual(len(names), len(set(name.casefold() for name in names)))
            self.assertFalse(any('..' in Path(name).parts or name.startswith('/') or ':' in name for name in names))
            self.assertIn(ArchivePaths(self.targets).path_for(str(self.target / 'sub/unsafe:?.txt')), names)
            self.assertIn(ArchivePaths(self.targets).path_for(str(self.target / 'CON.txt')), names)

    def test_records_outside_targets_are_rejected(self):
        paths = ArchivePaths(self.targets)
        with self.assertRaises(ValueError):
            paths.path_for(str(self.root / 'outside.txt'))

    def test_empty_export_and_folder_findings_are_recorded(self):
        exporter = self.scan()
        exporter.records.append({'id': 0, 'kind': 'directory', 'category': 'Folder Name Matches',
                                 'path': str(self.target), 'size': 0, 'matches': {'folder_names': ['target']}})
        result = exporter.save(str(self.destination))
        self.assertEqual(result['file_count'], 0)
        with zipfile.ZipFile(self.destination) as archive:
            manifest = json.loads(archive.read('terra/manifest.json'))
            self.assertEqual(manifest['directory_count'], 1)
            self.assertEqual(manifest['entries'][0]['export_status'], 'directory_metadata')

    def wait_export(self, controller, action):
        loop = QEventLoop()
        results = []
        controller.completed.connect(results.append)
        controller.completed.connect(loop.quit)
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        timer.start(5000)
        action()
        loop.exec()
        timer.stop()
        if controller.running:
            controller.stop()
            controller.worker.wait(5000)
            self.app.processEvents()
        self.assertTrue(results, 'Export did not finish')
        return results[0]

    def test_export_controller_runs_in_background(self):
        self.file('source.txt')
        self.scan()
        controller = ExportController()
        result = self.wait_export(controller, lambda: controller.start(str(self.destination), self.store, self.context))
        self.assertEqual(result['status'], 'saved')
        self.assertFalse(controller.running)

    def test_gui_destination_cancel_and_target_acknowledgement(self):
        page = ExportPage()
        self.addCleanup(page.deleteLater)
        page.prepare(self.targets, self.case, [])
        with patch('interface.pages.export.choose_save_destination', return_value=''):
            page.choose_destination()
        self.assertFalse(page.destination.text())
        signals = []
        page.export_requested.connect(lambda path, allowed: signals.append((path, allowed)))
        page.destination.setText(str(self.target / 'export.zip'))
        page.submit()
        self.assertFalse(signals)
        page.target_acknowledgement.setChecked(True)
        page.submit()
        self.assertEqual(signals, [(str(self.target / 'export.zip'), True)])

    def test_gui_scan_to_export_destination_and_back(self):
        self.file('source.txt')
        self.scan()
        window = MainWindow()
        self.addCleanup(window.deleteLater)
        window.target_selection = self.targets
        window.triage_configuration = self.config
        window.scan_controller.store = self.store
        window.analysis.finish(self.summary)
        window.navigation.open(window.analysis)
        window.analysis.next_button.click()
        self.assertIs(window.stack.currentWidget(), window.export)
        window.export.destination.setText(str(self.destination))
        result = self.wait_export(window.export_controller, window.export.export_button.click)
        self.assertEqual(result['status'], 'saved')
        self.assertIn('Saved and verified', window.export.status.text())
        self.assertFalse(window.export.busy)
        window.export.back_button.click()
        self.assertIs(window.stack.currentWidget(), window.analysis)
