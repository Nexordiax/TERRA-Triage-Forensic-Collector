"""Automatic case saves, logical hierarchy, separate RAM and usable navigation."""
import hashlib
import json
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from PySide6.QtWidgets import QApplication, QLineEdit
from shiboken6 import delete
from controllers.case_controller import case_export_path, cases_directory
from controllers.export_controller import ZipExporter, ArchivePaths
from controllers.scan_controller import ScanEngine
from interface.main_window import MainWindow
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


class CaseExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app=QApplication.instance() or QApplication([])

    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.appdir=self.root/'TERRA';self.appdir.mkdir()
        patcher=patch('controllers.case_controller.APPLICATION_DIRECTORY',self.appdir)
        patcher.start();self.addCleanup(patcher.stop)

    def window(self):
        window=MainWindow();self.addCleanup(delete,window)
        window.from_case=True
        for field,value in zip(window.case.findChildren(QLineEdit),('ID-42','Example Case','Examiner')):
            field.setText(value)
        window.target_selection={'paths':[str(self.root/'target')],'acquire_ram':False}
        window.triage_configuration=configuration()
        return window

    def test_case_creation_and_safe_filename(self):
        window=self.window();self.assertFalse((self.appdir/'cases').exists())
        window.create_case()
        self.assertTrue((self.appdir/'cases').is_dir())
        self.assertIs(window.stack.currentWidget(),window.privileges)
        stamp=datetime(2026,10,10,12,30,tzinfo=timezone.utc)
        path=case_export_path({'id':'../ID/42','name':'Example Case'},stamp)
        self.assertEqual(path.name,'ID_42-Example_Case-2026-10-10_12-30-00-000000-.zip')
        self.assertEqual(path.parent,self.appdir/'cases')
        self.assertEqual(cases_directory(),path.parent)

    def test_complete_and_stopped_case_exports_preserve_hierarchy_without_ram(self):
        for status in ('completed','stopped'):
            with self.subTest(status=status):
                window=self.window();target=self.root/'target';target.mkdir(exist_ok=True)
                profile=target/'home/examiner/.mozilla/firefox/profile';profile.mkdir(parents=True,exist_ok=True)
                source=profile/'places.sqlite';data=b'original SQLite fixture';source.write_bytes(data)
                wal=profile/'places.sqlite-wal';wal.write_bytes(b'original WAL fixture')
                store=MemoryStore();ScanEngine(window.target_selection,configuration(),store).run()
                ram=self.root/'RAM.lime';ram.write_bytes(b'large RAM fixture')
                memory=dict(path=str(ram),kind='file',category='Physical RAM',size=ram.stat().st_size,
                            sha256=hashlib.sha256(ram.read_bytes()).hexdigest(),matches={},memory_image=True,
                            content_retained=False,complete_physical_ram=True,collection='full physical RAM image')
                window.scan_controller.store=store;window.ram_result={'status':'saved','record':memory}
                calls=[]
                def start(filename,store,context,allow_target=False):
                    calls.append(filename)
                    records,diagnostics,count=store.snapshot()
                    result=ZipExporter(records,diagnostics,count,context).save(filename,allow_target)
                    window.export_completed(result)
                summary=dict(status=status,examined=2,collected=2,errors=0,diagnostic_count=0)
                with patch.object(window.export_controller,'start',side_effect=start):
                    window.scan_completed(summary)
                    self.assertEqual(calls,[])
                    if status == 'stopped':
                        window.export.submit()
                    else:
                        window.finish_export()
                self.assertEqual(Path(calls[0]).parent,self.appdir/'cases')
                self.assertTrue(Path(calls[0]).name.startswith('ID-42-Example_Case-'))
                with zipfile.ZipFile(calls[0]) as archive:
                    self.assertIsNone(archive.testzip())
                    self.assertFalse(any(name.startswith('terra/memory/') for name in archive.namelist()))
                    manifest=json.loads(archive.read('terra/manifest.json'))
                    self.assertEqual(manifest['partial_scan'],status=='stopped')
                    self.assertEqual(manifest['file_count'],2)
                    self.assertEqual(manifest['memory_acquisition']['record']['path'],str(ram))
                    name=next(row['archive_path'] for row in manifest['entries'] if row['source_path']==str(source))
                    self.assertEqual(archive.read(name),data)
                    self.assertEqual(archive.read(name+'-wal'),wal.read_bytes())
                    self.assertTrue(archive.read(manifest['report_path']).startswith(b'%PDF-'))
                    self.assertIn(b'AXIOM Process',archive.read('terra/IMPORT.txt'))

    def test_stopped_triage_navigation_does_not_automatically_export(self):
        window=self.window();window.from_case=False;window.ram_destination=str(self.root/'RAM.lime')
        window.navigation.open(window.configuration);window.navigation.open(window.analysis)
        window.scan_controller.store=MemoryStore()
        summary=dict(status='stopped',examined=0,collected=0,errors=0,diagnostic_count=0)
        with patch.object(window.export_controller,'start') as start:
            window.scan_completed(summary)
        start.assert_not_called()
        try:
            window.analysis.next_button.click()
            self.assertIs(window.stack.currentWidget(),window.export)
            self.assertTrue(window.export.back_button.isEnabled())
            window.export.back_button.click()
            self.assertIs(window.stack.currentWidget(),window.analysis)
            window.analysis.back_button.click()
            self.assertIs(window.stack.currentWidget(),window.configuration)
            self.assertFalse(window.analysis.resume_button.isHidden())
        finally:
            window.export_controller.worker=None

    def test_native_unicode_and_space_names_and_scope(self):
        target=self.root/'target';target.mkdir()
        paths=ArchivePaths({'paths':[str(target)]},source_tree=True)
        source=target/'home/Examiner Name/Documents/café.txt'
        name=paths.path_for(str(source))
        self.assertTrue(name.endswith('/home/Examiner Name/Documents/café.txt'))
        with self.assertRaises(ValueError):paths.path_for(str(self.root/'outside'))

    def test_export_failure_keeps_navigation_and_evidence_available(self):
        window=self.window();window.navigation.open(window.analysis)
        summary=dict(status='completed',examined=0,collected=0,errors=0,diagnostic_count=0)
        with patch('controllers.case_controller.case_export_path',side_effect=PermissionError('read-only destination')):
            window.scan_completed(summary)
        self.assertIsNone(window.case_export_default)
        self.assertTrue(window.analysis.back_button.isEnabled())
        window.analysis.next_button.click()
        self.assertIs(window.stack.currentWidget(),window.export)
        self.assertIn('read-only destination',window.export.status.text())
        self.assertFalse(window.case_export_saved)

    def test_custom_destination_is_used_instead_of_default(self):
        window=self.window();window.scan_controller.store=MemoryStore()
        summary=dict(status='completed',examined=0,collected=0,errors=0,diagnostic_count=0)
        window.scan_completed(summary)
        custom=self.root/'examiner-choice.zip'
        window.export.destination.setText(str(custom))
        with patch.object(window.export_controller,'start') as start:
            window.finish_export()
        self.assertEqual(start.call_args.args[0],str(custom))
        self.assertFalse(start.call_args.args[3])
        self.assertFalse(list((self.appdir/'cases').glob('*.zip')))

    def test_owned_cases_directory_is_excluded_from_scanning(self):
        cases=cases_directory();(cases/'old-case.zip').write_bytes(b'previous output')
        (self.appdir/'document.txt').write_bytes(b'current evidence')
        store=MemoryStore()
        ScanEngine({'paths':[str(self.appdir)],'excluded_directories':[str(cases)]},configuration(),store).run()
        self.assertEqual([Path(record['path']).name for record in store.records],['document.txt'])
