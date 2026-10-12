import hashlib
import io
import unittest
import zipfile
from analyzers.content_worker import analyze
from analyzers.containers import search


class ContainerSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def archive(self, members):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        return output.getvalue()

    def test_member_hash_content_and_nested_locator(self):
        payload = b'critical keyword'
        inner = self.archive({'../../evidence.txt': payload})
        result = analyze(self.archive({'nested.zip': inner}), '.zip', {
            'container_hashes': [hashlib.md5(payload).hexdigest()], 'container_keywords': ['keyword']})
        row = next(row for row in result['entries'] if row.get('member_name') == '../../evidence.txt')
        self.assertEqual(row['matched_hashes']['md5'], hashlib.md5(payload).hexdigest())
        self.assertEqual(row['matched_content'], ['keyword'])
        self.assertIn('member:nested.zip/member:', row['locator'])

    def test_office_embedded_picture_uses_existing_screen(self):
        from PIL import Image
        picture = io.BytesIO()
        Image.new('RGB', (10, 10), (180, 120, 90)).save(picture, 'PNG')
        result = analyze(self.archive({'word/media/image1.png': picture.getvalue()}), '.docx',
                         {'document_images': True, 'skin_tone': True, 'skin_method': 'colour', 'skin_threshold': 30})
        row = next(row for row in result['entries'] if row['type'] == 'skin_colour_screen')
        self.assertTrue(row['review_candidate'])
        self.assertIn('word/media/image1.png', row['locator'])

    def test_expansion_limit_is_logged(self):
        result = search(self.archive({'big.txt': b'x' * 100}), '.zip', {}, analyze,
                        budget={'bytes': 10, 'members': 1})
        self.assertTrue(result['limitations'])
        self.assertFalse(result['entries'])

    def test_nesting_limit_is_logged(self):
        payload = b'abc'
        for index in range(5):
            payload = self.archive({'nested.zip': payload})
        result = analyze(payload, '.zip', {})
        self.assertTrue(any('nesting limit' in item for item in result['limitations']))

    def test_matches_only_scan_retains_container_and_member_provenance(self):
        import tempfile
        from pathlib import Path
        from controllers.scan_controller import ScanEngine
        from storage.memory_store import MemoryStore
        from tests.test_scan import configuration
        payload = b'contained evidence'
        original = self.archive({'evidence.bin': payload})
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as export_directory:
            path = Path(directory) / 'evidence.zip'
            path.write_bytes(original)
            store = MemoryStore()
            config = configuration('matches_only', hashes=[hashlib.md5(payload).hexdigest()], hash_matches=True)
            ScanEngine({'paths': [directory]}, config, store).run()
            self.assertEqual(len(store.records), 1)
            record = store.records[0]
            self.assertEqual(record['sha256'], hashlib.sha256(original).hexdigest())
            self.assertIn('Hash Matches', record['additional_categories'])
            self.assertEqual(record['matches']['archive_hashes'][0]['hashes']['md5'], hashlib.md5(payload).hexdigest())
            from controllers.export_controller import ZipExporter
            store.log({'time': 'test', 'level': 'warning', 'path': 'container', 'message': 'test diagnostic'})
            records, logs, count = store.snapshot()
            destination = Path(export_directory) / 'export.zip'
            ZipExporter(records, logs, count, {'targets': {'paths': [directory]}}).save(destination)
            with zipfile.ZipFile(destination) as archive:
                self.assertIn(b'test diagnostic', archive.read('terra/logs/diagnostics.log'))
                self.assertIn(b'test diagnostic', archive.read('terra/logs/diagnostics.jsonl'))

    def test_pdf_embedded_picture_skin_screen(self):
        from PIL import Image
        stream = io.BytesIO()
        Image.new('RGB', (40, 40), (180, 120, 90)).save(stream, 'PDF')
        result = analyze(stream.getvalue(), '.pdf', {'document_images': True, 'skin_tone': True, 'skin_method': 'colour'})
        row = next(row for row in result['entries'] if row['type'] == 'skin_colour_screen')
        self.assertIn('/image:', row['locator'])



