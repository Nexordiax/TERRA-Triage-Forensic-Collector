"""Independent fixtures for automatic key discovery, encrypted groups and OCR lists."""
import hashlib
import io
import json
import os
import sqlite3
import struct
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PIL import Image, ImageDraw, ImageFont

from artifacts.catalog import definition_for
from artifacts.encrypted import EntropySample, candidate, detect
from artifacts.encrypted_volumes import collect as collect_volumes
from artifacts.file_collector import FileCollector, CollectionCancelled
from artifacts.parsing import parse_artifact
from artifacts.protected_keys import resolve_safestorage, _item_secret
from controllers.configuration_controller import ConfigurationError
from controllers.scan_controller import ScanEngine
from interface.pages.analysis import AnalysisPage
from interface.pages.configuration import ConfigurationPage
from storage.memory_store import MemoryStore
from tests.test_scan import configuration
from tests.test_protected_formats import protected_value


class TriageEnrichmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def file(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def scan(self, config=None, collector=None):
        store = MemoryStore()
        summary = ScanEngine({'paths': [str(self.root)]}, config or configuration(), store,
                             collector=collector).run()
        return summary, store

    def keyring(self, application='chromium', secret='same-user-secret', user='test'):
        label = 'Chromium' if application == 'chromium' else 'Chrome'
        return self.file(f'home/{user}/.local/share/keyrings/login.keyring',
                         f'[keyring]\n[item]\ndisplay-name={label} Safe Storage\nsecret={secret}\n'
                         f'[item:attribute0]\nname=application\nvalue={application}\n'.encode())

    def chromium(self):
        path = self.root / 'home/test/.config/chromium/Default/Login Data'
        path.parent.mkdir(parents=True)
        with closing(sqlite3.connect(path)) as database:
            database.execute('CREATE TABLE logins(origin_url TEXT,username_value TEXT,password_value BLOB)')
            database.execute('INSERT INTO logins VALUES(?,?,?)', ('https://example.test', 'fixture-user',
                             protected_value(b'decoded-fixture', b'same-user-secret', b'v11')))
            database.commit()
        return path

    def parse(self, path, targets=None):
        data, metadata = FileCollector().collect(str(path), lambda: False)
        return parse_artifact(definition_for(path), str(path), metadata, data, None, lambda: False,
                              {'_selected_paths': targets or [str(self.root)]})

    def test_automatic_chromium_v11_and_hashed_key_provenance(self):
        path = self.chromium()
        keyring = self.keyring()
        result = self.parse(path)
        self.assertEqual(result['entries'][0]['password'], 'decoded-fixture')
        self.assertEqual(result['status'], 'parsed')
        input = next(item for item in result['inputs'] if item['path'] == str(keyring))
        self.assertEqual(input['sha256'], hashlib.sha256(keyring.read_bytes()).hexdigest())
        self.assertNotIn('same-user-secret', json.dumps({key: value for key, value in result.items() if key != '_supporting_snapshots'}))
        _, store = self.scan()
        companion = next(item for item in store.records if item['path'] == str(keyring))
        self.assertEqual(companion['data'], keyring.read_bytes())

    def test_key_discovery_never_crosses_user_application_scope_or_symlinks(self):
        path = self.chromium()
        self.keyring(user='other')
        self.keyring(application='chrome')
        self.assertEqual(self.parse(path)['entries'][0]['decryption_status'], 'locked')
        keyring = self.keyring()
        self.assertEqual(self.parse(path, [str(path.parent)])['entries'][0]['decryption_status'], 'locked')
        keyring.unlink()
        keyring.symlink_to(self.root / 'home/other/.local/share/keyrings/login.keyring')
        self.assertEqual(self.parse(path)['entries'][0]['decryption_status'], 'locked')

    def test_encrypted_and_conflicting_keyrings_remain_locked(self):
        path = self.chromium()
        keyring = self.keyring()
        keyring.write_bytes(b'GnomeKeyring\n\r\0\n' + b'opaque-encrypted-keyring')
        result = self.parse(path)
        self.assertEqual(result['entries'][0]['decryption_status'], 'locked')
        self.assertTrue(any('Unsupported GNOME keyring version' in note for note in result['limitations']))
        self.keyring()
        self.file('home/test/.local/share/keyrings/other.keyring', keyring.read_bytes().replace(b'same-user-secret', b'conflicting-secret'))
        result = self.parse(path)
        self.assertEqual(result['entries'][0]['decryption_status'], 'locked')
        self.assertTrue(any('Conflicting' in note for note in result['limitations']))

    def test_text_secret_spaces_binary_and_cancel(self):
        data = b'[keyring]\n[item]\ndisplay-name=Chromium Safe Storage\nsecret= a password \n'
        self.assertEqual(_item_secret(data, 'Chromium', 'chromium')[0][0], ' a password ')
        data = data.replace(b'secret= a password ', b'binary-secret=616263')
        self.assertEqual(_item_secret(data, 'Chromium', 'chromium')[0][0], 'abc')
        with self.assertRaises(CollectionCancelled):
            resolve_safestorage(str(self.root / 'home/test/.config/chromium/Default/Login Data'), [str(self.root)], lambda: True)

    def test_luks2_json_cipher_across_chunks_without_cache(self):
        area = 2 * 1024 * 1024
        header = bytearray(area)
        header[:8] = b'LUKS\xba\xbe\0\2'
        struct.pack_into('>Q', header, 8, area)
        text = json.dumps({'segments': {'0': {'type': 'crypt', 'encryption': 'aes-xts-plain64'}}}).encode()
        header[4096:4096 + len(text)] = text
        path = self.file('volume.raw', bytes(header) + b'payload')
        _, store = self.scan(collector=FileCollector(max_file_bytes=0))
        record = store.records[0]
        self.assertEqual(record['category_subgroups']['Encrypted Containers'], 'LUKS2 · aes-xts-plain64')
        self.assertFalse(record['content_retained'])
        self.assertEqual(record['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        bad = bytes(header[:4096]) + b'{malformed' + bytes(area - 4106)
        self.assertIn('malformed', detect(bad)['metadata_note'])

    def test_public_bitlocker_and_kdbx_cipher_and_truncation(self):
        header = bytearray(512)
        header[3:11] = b'-FVE-FS-'
        struct.pack_into('<H', header, 11, 512)
        header[510:512] = b'\x55\xaa'
        self.assertEqual(detect(header)['format'], 'BitLocker')
        header[510] = 0
        self.assertIsNone(detect(header))
        kdbx = bytes.fromhex('03d9a29a67fb4bb5') + struct.pack('<I', 0x00040001)
        kdbx += b'\2' + struct.pack('<I', 16) + bytes.fromhex('31c1f2e6bf714350be5805216afc5aff')
        self.assertEqual(detect(kdbx)['cipher'], 'AES-256-CBC')
        self.assertNotIn('cipher', detect(kdbx[:-1]))
        short = b'LUKS\xba\xbe\0\2' + b'\0' * 24
        self.assertIsNone(detect(short))
        self.assertEqual(detect(b'GnomeKeyring\n\r\0\n' + b'opaque')['format'], 'GNOME Keyring')
        self.assertIsNone(detect(b'GnomeKeyring\n\r\0'))
        zip_header = bytearray(30)
        zip_header[:4] = b'PK\3\4'
        struct.pack_into('<H', zip_header, 6, 1)
        self.assertEqual(detect(zip_header)['format'], 'Encrypted ZIP')
        struct.pack_into('<H', zip_header, 6, 0)
        self.assertIsNone(detect(zip_header))

    def test_entropy_samples_do_not_overlap_and_candidates_are_explicit(self):
        sample = EntropySample()
        data = bytes(range(256)) * 160
        for offset in range(0, len(data), 7000):
            sample.update(data[offset:offset + 7000])
        result = sample.result()
        self.assertEqual(result['entropy_bits_per_byte'], 8)
        self.assertEqual(result['entropy_sample_bytes'], len(data))
        self.assertTrue(candidate('volume.vc', result))
        self.assertFalse(candidate('picture.jpg', result))
        self.file('volume.vc', data)
        self.file('picture.jpg', data)
        _, store = self.scan()
        records = {Path(record['path']).name: record for record in store.records}
        self.assertEqual(records['volume.vc']['category'], 'Encrypted Containers')
        self.assertIn('unconfirmed', records['volume.vc']['category_subgroups']['Encrypted Containers'])
        self.assertEqual(records['picture.jpg']['category'], 'Pictures')
        _, store = self.scan(configuration('matches_only'))
        self.assertFalse(store.records)

    def test_mounted_stacked_luks_metadata_and_folder_scope(self):
        mount = self.root / 'media/volume'
        mount.mkdir(parents=True)
        self.file('proc/self/mountinfo', f'41 22 253:1 / {mount} rw - ext4 /dev/dm-1 rw\n'.encode())
        self.file('sys/dev/block/253:1/slaves/dm-0/dm/uuid', b'CRYPT-LUKS2-fixture-volume')
        diagnostics = []
        args = (lambda: False, lambda *entry: diagnostics.append(entry))
        rows = collect_volumes({'paths': [str(mount)]}, *args, str(self.root / 'proc'), str(self.root / 'sys'))
        self.assertEqual(rows[0]['format'], 'LUKS2')
        self.assertEqual(rows[0]['mountpoint'], str(mount))
        self.assertFalse(collect_volumes({'paths': [str(mount / 'folder')]}, *args, str(self.root / 'proc'), str(self.root / 'sys')))
        with patch('controllers.scan_controller.encrypted_volumes', return_value=rows):
            _, store = self.scan()
        record = next(record for record in store.records if record.get('generated_snapshot'))
        self.assertEqual(record['category_subgroups']['Encrypted Containers'], 'LUKS2')
        self.assertIn('not a disk image', record['collection'])

    def test_encrypted_subcategories_stay_collapsed_and_sort_by_entropy(self):
        page = AnalysisPage()
        self.addCleanup(page.deleteLater)
        record = dict(id=1, category='Encrypted Containers', category_subgroups={'Encrypted Containers': 'LUKS2'},
                      path='/fixture.img', matches={}, size=123, collection='verified',
                      encryption_detection={'entropy_bits_per_byte': 7.5})
        page.add_finding(record)
        page.add_finding(dict(record, id=2, path='/higher.img', encryption_detection={'entropy_bits_per_byte': 7.9}))
        parent = page.categories['Encrypted Containers']
        child = parent.child(0)
        self.assertEqual(parent.text(0), 'Encrypted Containers (2)')
        self.assertFalse(parent.isExpanded())
        self.assertFalse(child.isExpanded())
        self.assertEqual(child.child(0).data(0, Qt.ItemDataRole.UserRole), 2)
        page.toggle_category(child, 0)
        self.assertTrue(child.isExpanded())
        page.toggle_category(child.child(0), 0)
        self.assertFalse(child.child(0).isExpanded())

    def test_ocr_list_import_start_snapshot_and_validation(self):
        page = ConfigurationPage()
        self.addCleanup(page.deleteLater)
        for checkbox in page.options.values():
            checkbox.setChecked(False)
        page.matches_only.setChecked(True)
        path = self.file('ocr.txt', b'forensic phrase\n# comment\nforensic phrase\n')
        page.ocr_lists.add_files([str(path)])
        self.assertTrue(page.content_analysis.ocr.isChecked())
        page.content_analysis.ocr.setChecked(False)
        emitted = []
        page.start_requested.connect(emitted.append)
        page.submit()
        self.assertEqual(emitted[0]['ocr_keywords'], ['forensic phrase'])
        self.assertTrue(emitted[0]['analysis_options']['ocr'])
        path.unlink()
        page.submit()
        self.assertEqual(len(emitted), 1)
        self.assertIn('Cannot read list', page.error.text())

    def test_ocr_only_matches_category_and_reference_exclusion(self):
        path = self.file('scan.png', b'independent mocked acquired image')
        reference = self.file('ocr.txt', b'entry-only')
        config = configuration('matches_only')
        config.update(ocr_files=[str(reference)], ocr_keywords=['entry-only'], analysis_options={'ocr': True})
        result = dict(status='parsed', entries=[dict(type='ocr_text', locator='frame:0', text='Entry-only found')],
                      limitations=[], record_count=1, sources=[], inputs=[])
        with patch('controllers.scan_controller.analyze_content', return_value=result):
            _, store = self.scan(config)
        self.assertEqual(len(store.records), 1)
        record = store.records[0]
        self.assertEqual(record['path'], str(path))
        self.assertEqual(record['matches'], {'ocr': ['entry-only']})
        self.assertEqual(record['parsed_artifact']['entries'][0]['matched_ocr_entries'], ['entry-only'])
        page = AnalysisPage()
        self.addCleanup(page.deleteLater)
        page.add_finding(record)
        self.assertIn('OCR Matches', page.categories)
        self.assertNotIn('File Content Matches', page.categories)
        result['entries'][0]['type'] = 'document_text'
        with patch('controllers.scan_controller.analyze_content', return_value=result):
            _, store = self.scan(config)
        self.assertFalse(store.records)

    def test_native_ocr_separate_list_with_all_standard_matching_disabled(self):
        from analyzers.ocr.analyzer import installation
        binary, _, _ = installation()
        if not Path(binary).exists():
            self.skipTest('Native OCR backend unavailable')
        font_path = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
        if not font_path.exists():
            self.skipTest('Neutral fixture font unavailable')
        with Image.new('RGB', (1100, 200), 'white') as image:
            ImageDraw.Draw(image).text((30, 60), 'TERRA forensic sample', fill='black', font=ImageFont.truetype(str(font_path), 60))
            output = io.BytesIO()
            image.save(output, format='PNG')
        data = output.getvalue()
        self.file('neutral.png', data)
        config = configuration('matches_only')
        config.update(ocr_keywords=['forensic sample'], analysis_options={'ocr': True, 'ocr_languages': 'eng'})
        summary, store = self.scan(config)
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(len(store.records), 1)
        self.assertEqual(store.records[0]['matches']['ocr'], ['forensic sample'])
        self.assertEqual(store.records[0]['sha256'], hashlib.sha256(data).hexdigest())


if __name__ == '__main__':
    unittest.main()
