"""Offline archive readers, credential retries and verified picture previews."""
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from threading import Event

from PySide6.QtCore import Qt, QEventLoop, QTimer
from PySide6.QtWidgets import QApplication
from PIL import Image
from analyzers.content_worker import analyze
from analyzers.content import analyze as isolated
from analyzers.embedded import render_preview
from artifacts.file_collector import FileCollector
from controllers.scan_controller import ScanEngine
from interface.pages.analysis import AnalysisPage
from interface.widgets.embedded_preview import EmbeddedPreview
from interface.widgets.structured_findings import StructuredFindings
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


class ArchiveFeaturesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.app = QApplication.instance() or QApplication([])
    def zip(self, members):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, payload in members.items(): archive.writestr(name, payload)
        return output.getvalue()
    def picture(self):
        output = io.BytesIO()
        with Image.new('RGB', (40, 30), (180, 120, 90)) as image: image.save(output, 'PNG')
        return output.getvalue()
    def encrypted_zip(self, payload):
        import pyzipper
        output = io.BytesIO()
        with pyzipper.AESZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as archive:
            archive.setpassword(b'evidence-password')
            archive.writestr('evidence.txt', payload)
        return output.getvalue()

    def test_native_rar_regular_members_and_symlink_skip(self):
        original = Path(__file__).with_name('fixtures').joinpath('libarchive-reference.rar').read_bytes()
        result = analyze(original, '.rar', {})
        self.assertEqual([row['member_name'] for row in result['entries']], ['test.txt', 'testdir/test.txt'])
        self.assertTrue(any('nonregular' in item for item in result['limitations']))

    def test_unencrypted_and_encrypted_7z(self):
        import py7zr
        for password in (None, 'evidence-password'):
            output = io.BytesIO()
            with py7zr.SevenZipFile(output, 'w', password=password, header_encryption=bool(password)) as archive:
                archive.writestr(b'needle', 'sample.txt')
            result = analyze(output.getvalue(), '.7z', {
                'container_keywords': ['needle'], '_archive_passwords': [dict(secret='evidence-password', source_path='known.env', locator='line:1')]})
            self.assertEqual(result['entries'][0]['matched_content'], ['needle'])
            self.assertNotIn('secret', result['entries'][0].get('decryption', {}))
            if password:
                locked = analyze(output.getvalue(), '.7z', {})
                self.assertTrue(locked['archive_coverage']['needs_credentials'])
                self.assertFalse(locked['entries'])

    def test_aes_zip_passwords_and_provenance_no_secret_in_results(self):
        payload = b'needle'
        result = analyze(self.encrypted_zip(payload), '.zip', {
            'container_hashes': [hashlib.md5(payload).hexdigest()],
            '_archive_passwords': [dict(secret='incorrect'), dict(secret='evidence-password', source_path='archive.ini', source_sha256='a'*64, locator='line:4')]})
        row = result['entries'][0]
        self.assertEqual(row['matched_hashes']['md5'], hashlib.md5(payload).hexdigest())
        self.assertEqual(row['decryption']['locator'], 'line:4')
        self.assertNotIn('evidence-password', str(result))

    def test_discovered_password_retries_earlier_locked_archive_without_duplicate(self):
        payload = b'needle'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'first.zip'; archive.write_bytes(self.encrypted_zip(payload))
            secret = root / '.env'; secret.write_text('ZIP_PASSWORD="evidence-password"\n')
            config = configuration(hashes=[hashlib.md5(payload).hexdigest()], hash_matches=True)
            engine = ScanEngine({'paths': [directory]}, config, MemoryStore())
            engine.scan_file(str(archive), None)
            self.assertTrue(engine.locked_archives)
            engine.scan_file(str(secret), None)
            engine.retry_locked_archives()
            records = [row for row in engine.store.records if row['path'] == str(archive)]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['matches']['archive_hashes'][0]['hashes']['md5'], hashlib.md5(payload).hexdigest())
            self.assertFalse(engine.locked_archives)
            self.assertFalse(any('evidence-password' in entry['message'] for entry in engine.store.diagnostics))

    def test_full_hash_and_keyword_search_of_member_above_old_32_mib_limit(self):
        payload = b'x' * (33 * 1024 * 1024) + b'needle'
        result = analyze(self.zip({'big.bin': payload}), '.zip', {
            'container_hashes': [hashlib.md5(payload).hexdigest()], 'container_keywords': ['needle']})
        row = result['entries'][0]
        self.assertEqual(row['size'], len(payload))
        self.assertEqual(row['matched_content'], ['needle'])
        self.assertEqual(row['matched_hashes']['md5'], hashlib.md5(payload).hexdigest())

    def test_large_outer_archive_uses_verified_stream_and_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'large.zip'
            with zipfile.ZipFile(path, 'w', zipfile.ZIP_STORED) as archive:
                with archive.open('big.bin', 'w') as member:
                    for _ in range(65): member.write(b'x' * 1024 * 1024)
            data, metadata = FileCollector().collect(str(path), lambda: False)
            self.assertFalse(metadata['content_retained'])
            result = isolated(str(path), metadata, data, None, {}, lambda: False)
            self.assertEqual(result['entries'][0]['size'], 65 * 1024 * 1024)
            self.assertFalse(result['limitations'])
            from artifacts.file_collector import CollectionCancelled
            with self.assertRaises(CollectionCancelled): isolated(str(path), metadata, data, None, {}, lambda: True)

    def test_nested_preview_and_tampered_locator(self):
        original = self.zip({'inner.zip': self.zip({'../../picture.png': self.picture()})})
        result = analyze(original, '.zip', {'skin_tone': True, 'skin_method': 'colour'})
        row = next(row for row in result['entries'] if row['type'] == 'embedded_image')
        preview = render_preview(io.BytesIO(original), '.zip', {'_preview_spec': row['preview']})
        self.assertEqual(preview['original_dimensions'], [40, 30])
        spec = row['preview']
        spec['steps'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'changed'): render_preview(io.BytesIO(original), '.zip', {'_preview_spec': spec})

    def test_pdf_preview_fits_and_gui_exposes_contained_picture(self):
        output = io.BytesIO()
        with Image.new('RGB', (80, 60), (180, 120, 90)) as image: image.save(output, 'PDF')
        original = output.getvalue()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'picture.pdf'; path.write_bytes(original)
            data, metadata = FileCollector().collect(str(path), lambda: False)
            result = isolated(str(path), metadata, data, None, {'document_images': True, 'skin_tone': True, 'skin_method': 'colour'}, lambda: False)
            row = next(row for row in result['entries'] if row['type'] == 'embedded_image')
            record = dict(metadata, path=str(path), data=data, id=0, category='Documents', kind='file', matches={}, collection='Verified cached evidence', parsed_artifact=result)
            page = AnalysisPage(); page.add_finding(record)
            node = page.categories['Documents'].child(0)
            self.assertEqual(node.childCount(), 1)
            emitted = []; page.preview_embedded_requested.connect(lambda number, spec: emitted.append((number,spec)))
            page.preview(node.child(0), 0)
            self.assertEqual(emitted[0][0], 0)
            dialog = EmbeddedPreview(record, row['preview']); dialog.show()
            loop = QEventLoop(); dialog.worker.finished.connect(loop.quit); QTimer.singleShot(5000,loop.quit); loop.exec()
            self.app.processEvents()
            self.assertTrue(hasattr(dialog,'picture'), dialog.message.text())
            self.assertEqual(dialog.picture.original_pixmap.width(), 80)
            dialog.close(); page.deleteLater()

    def test_encrypted_rar5_native_callbacks_verify_discovered_password_and_all_members(self):
        original = Path(__file__).with_name('fixtures').joinpath('rar5-encrypted-reference.rar').read_bytes()
        result = analyze(original, '.rar', {'_archive_passwords': [dict(secret='wrong'), dict(secret='password', source_path='archive.ini', locator='line:1')]})
        self.assertEqual(result['status'], 'parsed', result['limitations'])
        self.assertEqual([row['member_name'] for row in result['entries']], ['stest1.txt', 'stest2.txt'])
        self.assertEqual(result['entries'][0]['size'], 2048)
        self.assertEqual(result['entries'][0]['decryption']['source_path'], 'archive.ini')
        self.assertNotIn('secret', result['entries'][0]['decryption'])
        locked = analyze(original, '.rar', {})
        self.assertFalse(locked['entries'])
        self.assertTrue(locked['archive_coverage']['needs_credentials'])

    def test_native_rar_reader_integrity_failure_is_reported(self):
        from analyzers.rar_native import library
        with patch('analyzers.rar_native.hashlib.sha256') as digest:
            digest.return_value.hexdigest.return_value = '0' * 64
            with self.assertRaisesRegex(ValueError, 'integrity'): library()

    def test_pdf_picture_inventory_requires_document_image_opt_in(self):
        output = io.BytesIO()
        with Image.new('RGB', (40, 30), (180, 120, 90)) as image: image.save(output, 'PDF')
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'picture.pdf').write_bytes(output.getvalue())
            store = MemoryStore()
            ScanEngine({'paths':[directory]}, configuration(), store).run()
            self.assertEqual(len(store.records), 1)
            self.assertNotIn('parsed_artifact', store.records[0])
            self.assertNotIn('Pictures', store.records[0].get('additional_categories', []))
            store = MemoryStore()
            config = configuration()
            config['analysis_options'] = {'document_images': True}
            ScanEngine({'paths':[directory]}, config, store).run()
            self.assertIn('Pictures', store.records[0]['additional_categories'])
            rows = store.records[0]['parsed_artifact']['entries']
            self.assertTrue(any(row['type'] == 'embedded_image' for row in rows))
            self.assertFalse(any(row['type'] in ('skin_colour_screen','weapon_screen','ocr_text') for row in rows))

    def test_closing_main_window_cancels_contained_preview_without_destroying_running_thread(self):
        from interface.main_window import MainWindow
        from shiboken6 import delete
        from analyzers.content import analyze as isolated
        original = self.zip({'image.png': self.picture()})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'images.zip'; path.write_bytes(original)
            data, metadata = FileCollector().collect(str(path),lambda:False)
            parsed = isolated(str(path),metadata,data,None,{},lambda:False)
            row = next(row for row in parsed['entries'] if row['type']=='embedded_image')
            record = dict(metadata,path=str(path),data=data,category='Other Files',kind='file',matches={},collection='Cached evidence',parsed_artifact=parsed)
            previous_quit = self.app.quitOnLastWindowClosed()
            self.app.setQuitOnLastWindowClosed(False)
            self.addCleanup(self.app.setQuitOnLastWindowClosed, previous_quit)
            window = MainWindow(); self.addCleanup(delete,window)
            window.show()
            dialog = EmbeddedPreview(record,row['preview'],parent=window); dialog.show()
            finished=[]; loop=QEventLoop()
            dialog.worker.finished.connect(lambda:(finished.append(True),loop.quit()))
            self.assertTrue(dialog.worker.isRunning())
            window.close()
            QTimer.singleShot(5000,loop.quit); loop.exec()
            self.app.processEvents()
            self.assertTrue(finished)
            self.assertFalse(window.isVisible())
