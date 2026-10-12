import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import Mock, patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtWidgets import QApplication
from PIL import Image, ImageDraw, ImageFont

from analyzers.content import analyze, eligible
from analyzers.content_worker import analyze as worker_analysis
from analyzers.documents import extract
from analyzers.image_classification.analyzer import screen
from analyzers.ocr.analyzer import installation, recognize
from artifacts.file_collector import FileCollector, CollectionCancelled
from controllers.configuration_controller import ConfigurationController, ConfigurationError
from controllers.export_controller import ZipExporter
from controllers.scan_controller import ScanEngine
from interface.pages.configuration import ConfigurationPage
from interface.widgets.media_preview import MediaPreview
from interface.widgets.file_details import FileDetails
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


def office(members):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return output.getvalue()


def text_pdf():
    content = b'BT /F1 30 Tf 40 100 Td (TERRA forensic sample) Tj ET'
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>',
               b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
               b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
               b'<< /Length ' + str(len(content)).encode() + b' >>\nstream\n' + content + b'\nendstream']
    document, offsets = bytearray(b'%PDF-1.4\n'), [0]
    for number, item in enumerate(objects, 1):
        offsets.append(len(document))
        document.extend(str(number).encode() + b' 0 obj\n' + item + b'\nendobj\n')
    xref = len(document)
    document.extend(f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode())
    for offset in offsets[1:]:
        document.extend(f'{offset:010d} 00000 n \n'.encode())
    document.extend(f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    return bytes(document)


def png(colour=(210, 150, 110)):
    with Image.new('RGB', (100, 100), colour) as image:
        stream = io.BytesIO()
        image.save(stream, format='PNG')
        return stream.getvalue()


class ContentAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def fixture(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def scan(self, options, mode='all_supported', keywords=None, hashes=None, retain=True):
        config = configuration(mode, keywords=keywords or [], hashes=hashes or [],
                               file_contents=bool(keywords), hash_matches=bool(hashes))
        config['analysis_options'] = options
        store = MemoryStore(max_bytes=256 * 1024 * 1024 if retain else 0)
        summary = ScanEngine({'paths': [str(self.root)]}, config, store).run()
        return summary, store

    def test_ooxml_compressed_runs_headers_notes_and_macro_exclusion(self):
        data = office({'word/document.xml': '<w:document xmlns:w="word"><w:p><w:r><w:t>secret </w:t></w:r><w:r><w:t>phrase</w:t></w:r></w:p></w:document>',
                      'word/header1.xml': '<w:p xmlns:w="word"><w:t>header text</w:t></w:p>',
                      'word/vbaProject.bin': 'never run this program'})
        rows = extract(data, 'case.docx')
        self.assertEqual(len(rows), 2)
        self.assertIn('secret phrase', rows[0]['text'])
        self.assertFalse(any('never run' in row['text'] for row in rows))
        self.fixture('case.docx', data)
        summary, store = self.scan({'extract_documents': True}, 'matches_only', keywords=['secret phrase'])
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(len(store.records), 1)
        record = store.records[0]
        self.assertEqual(record['matches']['file_contents'], ['secret phrase'])
        self.assertEqual(record['content_match_sources'][0]['type'], 'document_text')
        self.assertEqual(record['data'], data)
        self.assertEqual(record['sha256'], hashlib.sha256(data).hexdigest())

    def test_opendocument_inline_order_whitespace_and_ooxml_variants(self):
        data = office({'content.xml': '<r xmlns:t="text"><t:p>secret <t:span>phrase</t:span> end<t:s t:c="3"/>tail</t:p></r>'})
        self.assertIn('secret phrase end   tail', extract(data, 'case.odt')[0]['text'])
        for suffix, member in (('.xlsx', 'xl/sharedStrings.xml'), ('.pptx', 'ppt/slides/slide1.xml')):
            rows = extract(office({member: '<r><t>stored text</t></r>'}), 'case' + suffix)
            self.assertIn('stored text', rows[0]['text'])

    def test_xml_entities_duplicate_members_and_expansion_limit_rejected(self):
        data = office({'word/document.xml': '<!DOCTYPE x [<!ENTITY e "text">]><r>&e;</r>'})
        with self.assertRaises(ValueError):
            extract(data, 'case.docx')
        utf16 = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY e "text">]><r>&e;</r>'.encode('utf-16')
        with self.assertRaises(ValueError):
            extract(office({'word/document.xml': utf16}), 'case.docx')
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('word/document.xml', '<r/>')
            with self.assertWarns(UserWarning):
                archive.writestr('word/document.xml', '<r/>')
        with self.assertRaises(ValueError):
            extract(stream.getvalue(), 'case.docx')
        data = office({'word/document.xml': '<r><t>stored text</t></r>'})
        with patch('analyzers.documents.MAX_XML_BYTES', 1):
            with self.assertRaises(ValueError):
                extract(data, 'case.docx')

    def test_rtf_unicode_controls_and_embedded_objects_ignored(self):
        rows = extract(br'{\rtf1\ansi\ansicpg1252{\fonttbl hidden font}secret\tab phrase\par \u233? {\*\private hidden payload}}', 'case.rtf')
        self.assertEqual(rows[0]['text'], 'secret\tphrase\né ')
        with self.assertRaises(ValueError):
            extract(br'{\rtf1\ansi\ansicpg1251 words}', 'case.rtf')

    def test_skin_percent_threshold_transparency_and_multiple_colour_ranges(self):
        for colour, expected in (((210, 150, 110), 100), ((80, 50, 35), 100), ((30, 120, 230), 0), ((255, 255, 255), 0)):
            with Image.new('RGB', (20, 20), colour) as image:
                row = screen(image)
            self.assertEqual(row['skin_like_percent'], expected)
            self.assertEqual(row['review_candidate'], expected >= 30)
        with Image.new('RGBA', (20, 20), (210, 150, 110, 0)) as image:
            with self.assertRaises(ValueError):
                screen(image)
        with Image.new('RGBA', (20, 20), (210, 150, 110, 0)) as image:
            ImageDraw.Draw(image).rectangle((0, 0, 9, 19), fill=(30, 120, 230, 255))
            row = screen(image)
            self.assertEqual(row['eligible_pixels'], 200)
            self.assertEqual(row['skin_like_percent'], 0)
        with Image.new('RGB', (10, 10), (30, 120, 230)) as image:
            ImageDraw.Draw(image).rectangle((0, 0, 4, 9), fill=(210, 150, 110))
            self.assertTrue(screen(image, 50)['review_candidate'])
            self.assertFalse(screen(image, 51)['review_candidate'])

    def test_skin_review_does_not_replace_hash_keyword_scope(self):
        data = png()
        self.fixture('colour.png', data)
        options = {'skin_tone': True, 'skin_threshold': 30}
        summary, store = self.scan(options)
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(store.records[0]['additional_categories'], ['Skin-colour Review'])
        self.assertEqual(store.records[0]['parsed_artifact']['entries'][0]['skin_like_percent'], 100)
        _, store = self.scan(options, 'matches_only', hashes=['f' * 32])
        self.assertEqual(store.records, [])
        _, store = self.scan(options, 'matches_only', hashes=[hashlib.md5(data).hexdigest()])
        self.assertIn('hashes', store.records[0]['matches'])
        self.assertEqual(store.records[0]['data'], data)

    def test_media_preview_exposes_analysis_and_preserves_fullscreen(self):
        data = png()
        self.fixture('colour.png', data)
        _, store = self.scan({'skin_tone': True})
        preview = MediaPreview(store.records[0])
        self.addCleanup(preview.close)
        self.assertTrue(hasattr(preview, 'fullscreen_button'))
        self.assertTrue(hasattr(preview, 'analysis_button'))
        preview.analysis_button.click()
        details = preview.findChildren(FileDetails)
        self.assertEqual(len(details), 1)
        self.addCleanup(details[0].close)
        self.assertEqual(details[0].record['parsed_artifact']['entries'][0]['type'], 'skin_colour_screen')

    def test_disabled_analysis_preserves_existing_behavior(self):
        self.fixture('colour.png', png())
        _, store = self.scan({})
        self.assertNotIn('parsed_artifact', store.records[0])
        self.assertFalse(eligible('sample.png', {}))
        self.assertFalse(eligible('sample.mp4', {'skin_tone': True, 'ocr': True}))

    def test_no_cache_analysis_reverifies_source_and_does_not_write(self):
        data = office({'word/document.xml': '<r><t>secret phrase</t></r>'})
        path = self.fixture('case.docx', data)
        _, store = self.scan({'extract_documents': True}, 'matches_only', keywords=['secret phrase'], retain=False)
        self.assertEqual(store.records[0]['matches']['file_contents'], ['secret phrase'])
        self.assertFalse(store.records[0]['content_retained'])
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(set(path.name for path in self.root.iterdir()), {'case.docx'})

    def test_changed_source_cannot_be_used_for_uncached_analysis(self):
        path = self.fixture('case.docx', office({'word/document.xml': '<r><t>original</t></r>'}))
        data, metadata = FileCollector(max_file_bytes=0).collect(str(path), lambda: False)
        path.write_bytes(office({'word/document.xml': '<r><t>changed</t></r>'}))
        with self.assertRaises(ValueError):
            analyze(str(path), metadata, data, None, {'extract_documents': True}, lambda: False)

    def test_missing_ocr_can_preserve_independent_skin_result(self):
        with patch('analyzers.ocr.analyzer.recognize', side_effect=ValueError('OCR unavailable')):
            result = worker_analysis(png(), '.png', {'ocr': True, 'skin_tone': True})
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['entries'][0]['type'], 'skin_colour_screen')
        self.assertIn('OCR unavailable', result['limitations'])

    def test_corrupt_image_and_large_analysis_limit_keep_full_hash_matching(self):
        data = b'corrupt image'
        self.fixture('broken.png', data)
        summary, store = self.scan({'skin_tone': True}, hashes=[hashlib.md5(data).hexdigest()])
        self.assertEqual(summary['hash_matches'], 1)
        self.assertEqual(store.records[0]['parsed_artifact']['status'], 'failed')
        self.assertEqual(store.records[0]['data'], data)
        with patch('analyzers.content.subprocess.Popen') as process:
            result = analyze('large.png', {'size': 65 * 1024 * 1024, 'sha256': 'x'}, b'', None, {'skin_tone': True}, lambda: False)
        self.assertEqual(result['status'], 'failed')
        process.assert_not_called()

    def test_cancellation_kills_analysis_process_group(self):
        process = Mock(pid=123456)
        process.poll.return_value = None
        process.communicate.return_value = (b'', b'')
        checks = iter([False, True])
        with patch('analyzers.content.subprocess.Popen', return_value=process), patch('analyzers.content.os.killpg') as kill:
            with self.assertRaises(CollectionCancelled):
                analyze('case.png', {'size': 1, 'sha256': 'x'}, b'x', None, {}, lambda: next(checks))
        kill.assert_called_once()
        process.communicate.assert_called_once()

    def test_analysis_timeout_is_diagnostic_and_kills_worker(self):
        process = Mock(pid=123456)
        process.poll.return_value = None
        process.communicate.return_value = (b'', b'')
        with patch('analyzers.content.subprocess.Popen', return_value=process), patch('analyzers.content.os.killpg') as kill:
            result = analyze('case.png', {'size': 1, 'sha256': 'x'}, b'x', None, {}, lambda: False, timeout=-1)
        self.assertEqual(result['status'], 'failed')
        self.assertIn('timeout', result['limitations'][0])
        kill.assert_called_once()

    def test_total_analysis_budget_does_not_stop_original_hash_search(self):
        data = png()
        self.fixture('colour.png', data)
        config = configuration(hashes=[hashlib.md5(data).hexdigest()], hash_matches=True)
        config['analysis_options'] = {'skin_tone': True}
        store = MemoryStore()
        engine = ScanEngine({'paths': [str(self.root)]}, config, store)
        engine.analysis_max_bytes = 0
        summary = engine.run()
        self.assertEqual(summary['hash_matches'], 1)
        self.assertEqual(store.records[0]['data'], data)
        self.assertEqual(store.records[0]['parsed_artifact']['status'], 'failed')
        self.assertTrue(any('budget reached' in entry['message'] for entry in store.diagnostics))

    def test_configuration_controls_validation_and_navigation_payload(self):
        page = ConfigurationPage()
        self.addCleanup(page.close)
        for checkbox in page.options.values():
            checkbox.setChecked(False)
        self.assertFalse(page.content_analysis.extract.isChecked())
        self.assertTrue(page.content_analysis.ocr.isChecked())
        self.assertFalse(page.content_analysis.ocr_pdf.isChecked())
        self.assertTrue(page.content_analysis.skin.isChecked())
        page.content_analysis.ocr.setChecked(True)
        self.assertTrue(page.content_analysis.languages.isEnabled())
        page.content_analysis.skin.setChecked(True)
        self.assertTrue(page.content_analysis.threshold.isEnabled())
        emitted = []
        page.start_requested.connect(emitted.append)
        page.submit()
        self.assertTrue(emitted[0]['analysis_options']['skin_tone'])
        page.content_analysis.languages.setText('eng;execute')
        page.submit()
        self.assertIn('OCR languages', page.error.text())
        self.assertEqual(len(emitted), 1)

    def test_derived_text_export_and_original_source_hash(self):
        data = office({'word/document.xml': '<r><t>secret phrase</t></r>'})
        self.fixture('case.docx', data)
        _, store = self.scan({'extract_documents': True})
        destination = tempfile.TemporaryDirectory()
        self.addCleanup(destination.cleanup)
        output = Path(destination.name) / 'analysis.zip'
        records, logs, count = store.snapshot()
        ZipExporter(records, logs, count, {'targets': {'paths': [str(self.root)]}}).save(output)
        with zipfile.ZipFile(output) as archive:
            path = next(name for name in archive.namelist() if name.endswith('/records.jsonl'))
            row = json.loads(archive.read(path).splitlines()[0])
            self.assertIn('secret phrase', row['text'])
            raw = next(name for name in archive.namelist() if name.startswith('evidence/') and name.endswith('case.docx'))
            self.assertEqual(archive.read(raw), data)


class NativeOcrTests(unittest.TestCase):
    # Keep native end-to-end checks separate from backend-independent unit checks.
    fixture = ContentAnalysisTests.fixture
    scan = ContentAnalysisTests.scan

    def setUp(self):
        ContentAnalysisTests.setUp(self)
        try:
            installation()
        except ValueError as error:
            self.skipTest(str(error))

    def text_image(self):
        image = Image.new('RGB', (1100, 180), 'white')
        font = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
        if not font.is_file():
            self.skipTest('Native OCR fixture font unavailable')
        ImageDraw.Draw(image).text((25, 50), 'TERRA forensic sample', font=ImageFont.truetype(str(font), 60), fill='black')
        return image

    def test_native_image_ocr_keyword_match_and_original_md5(self):
        with self.text_image() as image:
            stream = io.BytesIO()
            image.save(stream, format='PNG')
        data = stream.getvalue()
        self.fixture('scan.png', data)
        summary, store = self.scan({'ocr': True, 'ocr_languages': 'eng'}, 'matches_only', keywords=['forensic sample'], hashes=[hashlib.md5(data).hexdigest()])
        self.assertEqual(summary['hash_matches'], 1)
        self.assertEqual(store.records[0]['matches']['file_contents'], ['forensic sample'])
        row = store.records[0]['parsed_artifact']['entries'][0]
        self.assertIn('TERRA forensic sample', row['text'])
        self.assertTrue(row['words'])
        self.assertEqual(len(row['words'][0]['box']), 4)
        self.assertEqual(store.records[0]['sha256'], hashlib.sha256(data).hexdigest())

    def test_native_scanned_pdf_ocr_and_stored_pdf_text(self):
        try:
            import pypdfium2
        except ImportError:
            self.skipTest('PDFium dependency unavailable')
        with self.text_image() as image:
            stream = io.BytesIO()
            image.save(stream, format='PDF')
        self.fixture('scanned.pdf', stream.getvalue())
        self.fixture('text.pdf', text_pdf())
        _, store = self.scan({'document_images': True, 'extract_documents': True, 'ocr': True, 'ocr_languages': 'eng'}, 'matches_only', keywords=['forensic sample'])
        self.assertEqual(len(store.records), 2)
        kinds = {Path(row['path']).name: row['parsed_artifact']['entries'][0]['type'] for row in store.records}
        self.assertEqual(kinds, {'scanned.pdf': 'ocr_text', 'text.pdf': 'document_text'})
        data = text_pdf()
        metadata = dict(size=len(data), sha256=hashlib.sha256(data).hexdigest(), content_retained=True)
        result = analyze('text.pdf', metadata, data, None,
                         {'document_images': True, 'extract_documents': True, 'ocr': True, 'ocr_all_pdf_pages': True}, lambda: False)
        self.assertEqual([row['type'] for row in result['entries']], ['document_text', 'ocr_text'])
        self.assertIn('forensic sample', result['entries'][1]['text'])


if __name__ == '__main__':
    unittest.main()
