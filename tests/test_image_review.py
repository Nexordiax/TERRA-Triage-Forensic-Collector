"""Defaults, actionable worker failures, fair presentation and image analysis."""
import atexit
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ['ORT_DISABLE_TELEMETRY'] = '1'
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt, QCoreApplication, QEvent
from shiboken6 import delete
from PIL import Image
import numpy as np

from analyzers.content import analyze, eligible
from analyzers.content_worker import analyze as worker_analysis
from analyzers.ocr.analyzer import installed_languages
from controllers.configuration_controller import ConfigurationController, ConfigurationError
from controllers.scan_controller import ScanEngine
from interface.pages.analysis import AnalysisPage
from interface.pages.configuration import ConfigurationPage
from interface.widgets.media_preview import MediaPreview
from interface.widgets.file_details import FileDetails
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


def _flush_gui_deletions():
    # Several existing GUI fixtures use deleteLater without a persistent event loop.
    # Complete those deletions while Python callbacks/bindings are still alive.
    if QApplication.instance() is not None:
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


atexit.register(_flush_gui_deletions)


class ImageReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def png(self):
        with Image.new('RGB', (100, 60), 'white') as image:
            output = io.BytesIO()
            image.save(output, format='PNG')
        return output.getvalue()

    def test_picture_screening_defaults_and_controls_remain_editable(self):
        page = ConfigurationPage()
        self.addCleanup(delete, page)
        controls = page.content_analysis
        self.assertTrue(controls.ocr.isChecked())
        self.assertTrue(controls.skin.isChecked())
        self.assertNotIn('weapon_detection', controls.values())
        for checkbox in (controls.extract, controls.ocr_pdf, controls.ocr_all_pages):
            self.assertFalse(checkbox.isChecked())
        self.assertTrue(controls.languages.isEnabled())
        self.assertTrue(controls.threshold.isEnabled())
        controls.languages.setText('eng+deu+fra')
        controls.threshold.setValue(65)
        for box in page.options.values():
            box.setChecked(False)
        emitted = []
        page.start_requested.connect(emitted.append)
        page.submit()
        self.assertEqual(emitted[0]['analysis_options']['ocr_languages'], 'eng+deu+fra')
        self.assertEqual(emitted[0]['analysis_options']['skin_threshold'], 65)
        self.assertFalse(eligible('text.pdf', emitted[0]['analysis_options']))
        self.assertTrue(eligible('picture.png', emitted[0]['analysis_options']))
        controls.document_images.setChecked(True)
        self.assertTrue(eligible('text.pdf', controls.values()))
        controls.ocr_pdf.setChecked(True)
        self.assertTrue(controls.ocr_all_pages.isEnabled())
        controls.ocr.setChecked(False)
        self.assertFalse(controls.ocr_all_pages.isChecked())
        self.assertFalse(controls.ocr_pdf.isChecked())

    def test_picture_preview_fits_resizing_and_fullscreen(self):
        for dimensions in ((1200, 600), (600, 1200)):
            with self.subTest(dimensions=dimensions):
                path = self.root / 'preview.png'
                with Image.new('RGB', dimensions, 'white') as image:
                    image.save(path)
                original_bytes = path.read_bytes()
                preview = MediaPreview({'path': str(path), 'category': 'Pictures',
                                        'data': original_bytes, 'content_retained': True})
                try:
                    preview.show()
                    self.assertTrue(preview.fullscreen_button.isHidden())
                    for size in ((760, 540), (1000, 700), (500, 400)):
                        preview.resize(*size)
                        self.app.processEvents()
                        self.assert_picture_fits(preview)
                    preview.toggle_fullscreen()
                    self.app.processEvents()
                    self.assertTrue(preview.isFullScreen())
                    self.assert_picture_fits(preview)
                    preview.toggle_fullscreen()
                    self.app.processEvents()
                    self.assert_picture_fits(preview)
                    self.assertEqual(preview.picture.original_pixmap.width(), dimensions[0])
                    self.assertEqual(preview.picture.original_pixmap.height(), dimensions[1])
                    self.assertEqual(path.read_bytes(), original_bytes)
                finally:
                    preview.close()
                    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    def assert_picture_fits(self, preview):
        picture = preview.picture
        expected = picture.original_pixmap.size().scaled(
            picture.contentsRect().size(), Qt.AspectRatioMode.KeepAspectRatio)
        self.assertEqual(picture.pixmap().size(), expected)
        self.assertGreater(expected.width(), 0)
        self.assertGreater(expected.height(), 0)

    def test_default_picture_ocr_does_not_import_or_decode_pdf(self):
        # Document-image searches require explicit opt-in, including backend callers.
        with patch('analyzers.ocr.analyzer.recognize', side_effect=AssertionError('PDF OCR must stay disabled')):
            result = worker_analysis(b'not-a-PDF', '.pdf', {'ocr': True, 'ocr_pdf': False})
        self.assertEqual(result['entries'], [])
        self.assertFalse(eligible('report.pdf', {'ocr': True, 'ocr_pdf': False}))
        self.assertFalse(eligible('report.pdf', {'ocr': True}))
        self.assertTrue(eligible('report.pdf', {'ocr': True, 'document_images': True}))

    def test_picture_target_details_hides_fullscreen_button(self):
        payload = self.png()
        record = dict(path=str(self.root / 'picture.png'), category='Pictures', kind='file',
                      size=len(payload), matches={}, data=payload, content_retained=True)
        details = FileDetails(record)
        self.addCleanup(delete, details)
        self.assertTrue(details.fullscreen_button.isHidden())

    def test_language_query_and_gui_show_available_codes_without_writes(self):
        binary = self.root / 'tesseract'
        output = Mock(returncode=0, stdout=b'List of available languages (3):\neng\ndeu\nfra\n', stderr=b'')
        with patch('analyzers.ocr.analyzer.installation', return_value=(binary, None, None)), patch('analyzers.ocr.analyzer.subprocess.run', return_value=output) as run:
            self.assertEqual(installed_languages(), ['deu', 'eng', 'fra'])
        self.assertEqual(run.call_args.args[0], [str(binary), '--list-langs'])
        page = ConfigurationPage()
        self.addCleanup(delete, page)
        with patch('analyzers.ocr.analyzer.installed_languages', return_value=['eng', 'deu']), patch('interface.widgets.content_options.QMessageBox.information') as message:
            page.content_analysis.show_languages()
        self.assertIn('eng, deu', message.call_args.args[2])

    def test_missing_pillow_is_structured_and_worker_exits_normally(self):
        process = subprocess.run([sys.executable, '-S', '-m', 'analyzers.content_worker', '{}', '.png'],
                                 input=b'fixture', stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=Path(__file__).resolve().parent.parent)
        self.assertEqual(process.returncode, 0)
        result = json.loads(process.stdout)
        self.assertEqual(result['status'], 'failed')
        self.assertIn('Pillow', result['limitations'][0])
        self.assertIn('requirements-forensics.txt', result['limitations'][0])

    def test_worker_nonzero_includes_cause_and_signal(self):
        process = Mock(returncode=1)
        process.poll.return_value = 1
        process.communicate.return_value = (b'', b'ModuleNotFoundError: No module named PIL')
        with patch('analyzers.content.subprocess.Popen', return_value=process):
            result = analyze('fixture.png', {'size': 1, 'sha256': 'x'}, b'x', None, {}, lambda: False)
        self.assertIn('No module named PIL', result['limitations'][0])
        self.assertEqual(result['worker_exit_code'], 1)
        process.returncode = -9
        process.poll.return_value = -9
        process.communicate.return_value = (b'', b'')
        with patch('analyzers.content.subprocess.Popen', return_value=process):
            result = analyze('fixture.png', {'size': 1, 'sha256': 'x'}, b'x', None, {}, lambda: False)
        self.assertIn('SIGKILL', result['limitations'][0])

    def test_worker_resource_setup_failure_is_structured(self):
        from analyzers.content_worker import main
        output = io.BytesIO()
        stream = Mock(buffer=output)
        with patch('analyzers.content_worker.run', side_effect=PermissionError('resource limit unavailable')), patch('analyzers.content_worker.sys.stdout', stream):
            main()
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'failed')
        self.assertIn('resource limit unavailable', result['limitations'][0])

    def test_priority_categories_and_files_preserve_other_live_findings(self):
        page = AnalysisPage()
        self.addCleanup(delete, page)
        common = dict(category='Pictures', size=1, collection='verified source file')
        records = [dict(common, id=0, path='ordinary.png', matches={}),
                   dict(common, id=1, path='skin.png', matches={}, additional_categories=['Skin-colour Review']),
                   dict(common, id=2, path='ocr.png', matches={'ocr': ['entry']}),
                   dict(common, id=3, path='content.png', matches={'file_contents': ['word']}),
                   dict(common, id=4, path='hash.png', matches={'hashes': {'md5': 'digest'}})]
        for record in records:
            page.add_finding(record)
        order = [page.results.topLevelItem(index).text(0).split(' (')[0] for index in range(page.results.topLevelItemCount())]
        self.assertEqual(order, ['Hash Matches', 'File Content Matches', 'OCR Matches', 'Skin-colour Review', 'Pictures'])
        pictures = page.categories['Pictures']
        self.assertEqual([pictures.child(index).data(0, Qt.ItemDataRole.UserRole) for index in range(pictures.childCount())], [4, 3, 2, 1, 0])
        self.assertTrue(all(not node.isExpanded() for node in page.categories.values()))
        pictures.setExpanded(True)
        page.add_finding(dict(common, id=6, path='another.png', matches={}))
        self.assertTrue(pictures.isExpanded())
        self.assertEqual(pictures.childCount(), 6)









if __name__ == '__main__':
    unittest.main()
