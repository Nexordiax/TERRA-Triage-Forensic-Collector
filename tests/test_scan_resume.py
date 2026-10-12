"""Stopped triage stays in RAM, resumes without duplicate reads, and exports optionally."""
import tempfile
import unittest
from pathlib import Path
from threading import Event
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication
from shiboken6 import delete
from artifacts.file_collector import FileCollector
from controllers.scan_controller import ScanEngine, ScanController
from interface.main_window import MainWindow
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


class CountingCollector(FileCollector):
    def __init__(self):
        super().__init__(); self.read_paths=[]
    def collect(self, path, *args, **kwargs):
        self.read_paths.append(str(path))
        return super().collect(path,*args,**kwargs)


class ResumeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])

    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        for index in range(3):(self.root/f'file{index}.txt').write_bytes(f'evidence {index}'.encode())

    def paused(self):
        store=MemoryStore();cancel=Event();collector=CountingCollector()
        engine=ScanEngine({'paths':[str(self.root)]},configuration(),store,cancel,
                          on_finding=lambda record:cancel.set(),collector=collector)
        summary=engine.run();self.assertEqual(summary['status'],'stopped')
        self.assertEqual(len(store.records),1)
        return engine,collector,summary

    def test_controller_resume_preserves_store_and_skips_completed_files(self):
        engine,collector,summary=self.paused()
        controller=ScanController();self.addCleanup(delete,controller)
        controller.store=engine.store;controller.paused_engine=engine
        original_store=controller.store
        loop=QEventLoop();results=[]
        controller.completed.connect(lambda result:(results.append(result),loop.quit()))
        controller.resume();QTimer.singleShot(5000,loop.quit);loop.exec()
        if controller.running:
            controller.stop();controller.worker.wait();self.app.processEvents()
        self.assertTrue(results)
        self.assertEqual(results[0]['status'],'completed')
        self.assertIs(controller.store,original_store)
        self.assertEqual(len(controller.store.records),3)
        self.assertEqual(len(set(row['path'] for row in controller.store.records)),3)
        self.assertEqual(len(collector.read_paths),3)
        self.assertIsNone(controller.paused_engine)
        with self.assertRaises(RuntimeError):controller.resume()

    def test_interrupted_file_is_retried_not_marked_finished(self):
        store=MemoryStore();cancel=Event()
        class Interrupted(CountingCollector):
            interrupt=True
            def collect(inner,path,*args,**kwargs):
                if inner.interrupt:
                    inner.interrupt=False;cancel.set()
                return super().collect(path,*args,**kwargs)
        collector=Interrupted()
        engine=ScanEngine({'paths':[str(self.root)]},configuration(),store,cancel,collector=collector)
        self.assertEqual(engine.run()['status'],'stopped')
        self.assertEqual(engine.finished_paths,set())
        cancel.clear();engine.visited.clear()
        self.assertEqual(engine.run()['status'],'completed')
        self.assertEqual(len(store.records),3)
        self.assertEqual(len(collector.read_paths),4)

    def test_resume_keeps_results_and_stopped_finish_does_not_save_case(self):
        from unittest.mock import patch
        engine,collector,summary=self.paused()
        window=MainWindow();self.addCleanup(delete,window)
        window.target_selection=engine.targets;window.triage_configuration=configuration()
        window.scan_controller.store=engine.store;window.scan_controller.paused_engine=engine
        for row in engine.store.records:window.analysis.add_finding(row)
        window.ram_destination=str(self.root/'previous-RAM.lime')
        with patch.object(window.export_controller,'start') as export:
            window.scan_completed(summary);export.assert_not_called()
        item_count=window.analysis.results.topLevelItemCount()
        with patch.object(window.scan_controller,'resume') as resume:
            window.analysis.resume_button.click();resume.assert_called_once()
        self.assertEqual(window.analysis.results.topLevelItemCount(),item_count)
        self.assertIsNone(window.analysis.summary)
        window.analysis.finish(summary);window.from_case=True
        with patch.object(window.export_controller,'start') as export:
            window.finish_export();export.assert_not_called()
