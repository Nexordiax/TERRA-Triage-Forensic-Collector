"""Native-format interoperability, locked inputs, scope and attachment export."""
import base64
import ctypes.util
import hashlib
import hmac
import io
import json
import sqlite3
import struct
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from artifacts.catalog import definition_for
from artifacts.communication.attachments import decrypt, extract
from artifacts.email.pff import attachments
from artifacts.file_collector import FileCollector
from artifacts.keyrings import gnome, kwallet
from artifacts.parsing import parse_artifact
from artifacts.parser_support import ParseError
from artifacts.protected_keys import resolve_safestorage
from artifacts.leveldb_state import annotate, manifest
from reporting.structured_export import write_structured
from tests.test_extended_formats import fragment, batch, sst, prefixed, varint


def aes(data, key, iv, padded=True):
    if padded:
        pad = PKCS7(128).padder()
        data = pad.update(data) + pad.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return cipher.update(data) + cipher.finalize()


def gnome_fixture(password):
    def blob(value):
        return struct.pack('>I', len(value)) + value
    attributes = struct.pack('>I', 1) + blob(b'application') + struct.pack('>I', 0) + blob(b'chromium')
    payload = blob(b'Chromium Safe Storage') + blob(b'fixture-safe-storage')
    payload += struct.pack('>QQI', 100, 200, 0xffffffff) + bytes(16) + attributes + struct.pack('>I', 0)
    payload += bytes((-len(payload)) % 16)
    salt, iterations = b'12345678', 100
    key = hashlib.sha256(password.encode() + salt).digest()
    for _ in range(iterations - 1):
        key = hashlib.sha256(key).digest()
    ciphertext = aes(hashlib.md5(payload).digest() + payload, key[:16], key[16:], False)
    header = b'GnomeKeyring\n\r\0\n' + bytes(4) + blob(b'fixture') + struct.pack('>QQIII', 100, 200, 0, 0, iterations)
    header += salt + bytes(16) + struct.pack('>III', 1, 42, 0) + struct.pack('>I', 0)
    return header + blob(ciphertext)


class ExpansionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def file(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def parse(self, path, secrets=None, targets=None):
        data, metadata = FileCollector().collect(str(path), lambda: False)
        return parse_artifact(definition_for(path), str(path), metadata, data, None, lambda: False,
                              {'_selected_paths': targets or [str(self.root)], '_decryption_secrets': secrets or {}})

    @unittest.skipUnless(ctypes.util.find_library('nss3') and ctypes.util.find_library('nssdbm3'), 'Native NSS DBM unavailable')
    def test_native_firefox_key3_empty_and_primary_password(self):
        from tests.nss_fixture import profile
        for index, password in enumerate(('', 'fixture-primary-password')):
            directory = self.root / f'home/user{index}/.mozilla/firefox/fixture.default'
            directory.mkdir(parents=True)
            profile(directory, password, backend='dbm')
            path = directory / 'logins.json'
            before = (directory / 'key3.db').read_bytes()
            parsed = self.parse(path, {'firefox_password': password})
            self.assertEqual(parsed['status'], 'parsed')
            self.assertEqual(parsed['entries'][0]['username'], 'test-user')
            self.assertEqual(parsed['entries'][0]['password'], 'fixture-password')
            self.assertTrue(any(item['path'].endswith('key3.db') for item in parsed['inputs']))
            self.assertEqual((directory / 'key3.db').read_bytes(), before)
            locked = self.parse(path, {'firefox_password': 'wrong-password'})
            self.assertEqual(locked['status'], 'partial')
            self.assertNotIn('password', locked['entries'][0])
            # A present but malformed key4 must not be bypassed with an older key.
            (directory / 'key4.db').write_bytes(b'corrupt-current-key-store')
            current = self.parse(path, {'firefox_password': password})
            self.assertNotIn('password', current['entries'][0])

    def test_native_kwallet_variants_wrong_password_and_tamper(self):
        fixtures = Path(__file__).parent / 'fixtures'
        for name in ('kwallet-legacy-ecb', 'kwallet-legacy-cbc', 'kwallet-modern-cbc'):
            with self.subTest(name=name):
                data = (fixtures / (name + '.kwl')).read_bytes()
                salt = (fixtures / (name + '.salt')).read_bytes() if 'modern' in name else None
                rows = kwallet(data, 'fixture-wallet-password', salt)
                self.assertEqual(rows[-1]['secret'], b'fixture-safestorage')
                self.assertEqual(rows[-1]['folder'], 'Chromium Keys')
                with self.assertRaises(ParseError):
                    kwallet(data, 'wrong-password', salt)
                with self.assertRaises(ParseError):
                    kwallet(data[:-1] + bytes([data[-1] ^ 1]), 'fixture-wallet-password', salt)
        with self.assertRaises(ParseError):
            kwallet(data, 'fixture-wallet-password')

    def test_gnome_binary_checksum_key_discovery_and_json_export(self):
        data = gnome_fixture('fixture-password')
        self.assertEqual(gnome(data, 'fixture-password')[-1]['secret'], b'fixture-safe-storage')
        with self.assertRaises(ParseError):
            gnome(data, 'wrong-password')
        with self.assertRaises(ParseError):
            gnome(data[:-1] + bytes([data[-1] ^ 1]), 'fixture-password')
        path = self.file('home/user/.local/share/keyrings/login.keyring', data)
        browser = self.file('home/user/.config/chromium/Default/Login Data', b'placeholder')
        secrets = {'gnome_password': 'fixture-password'}
        found, supporting, _ = resolve_safestorage(str(browser), [str(self.root)], lambda: False, secrets)
        self.assertEqual(found['safe_storage_password'], 'fixture-safe-storage')
        self.assertEqual(supporting[0][0]['sha256'], hashlib.sha256(data).hexdigest())
        parsed = self.parse(path, secrets)
        self.assertEqual(parsed['status'], 'parsed')
        self.assertEqual(parsed['entries'][-1]['secret']['value'], b'fixture-safe-storage'.hex())
        json.dumps(parsed, default=None)  # No opaque bytes reach structured output.
        found, _, _ = resolve_safestorage(str(browser), [str(browser.parent)], lambda: False, secrets)
        self.assertEqual(found, {})

    def test_kwallet_discovery_is_same_application_and_rejects_symlink_directory(self):
        fixtures = Path(__file__).parent / 'fixtures'
        data = (fixtures / 'kwallet-modern-cbc.kwl').read_bytes()
        wallet = self.file('home/user/.local/share/kwalletd/kdewallet.kwl', data)
        self.file('home/user/.local/share/kwalletd/kdewallet.salt', (fixtures / 'kwallet-modern-cbc.salt').read_bytes())
        browser = self.file('home/user/.config/chromium/Default/Login Data', b'placeholder')
        secrets = {'kwallet_password': 'fixture-wallet-password'}
        found, supporting, _ = resolve_safestorage(str(browser), [str(self.root)], lambda: False, secrets)
        self.assertEqual(found['safe_storage_password'], 'fixture-safestorage')
        self.assertEqual(len(supporting), 2)
        self.assertEqual(self.parse(wallet, secrets)['status'], 'parsed')
        chrome = self.file('home/user/.config/google-chrome/Default/Login Data', b'placeholder')
        self.assertEqual(resolve_safestorage(str(chrome), [str(self.root)], lambda: False, secrets)[0], {})
        wallet.parent.rename(wallet.parent.with_name('outside-wallet'))
        wallet.parent.symlink_to(wallet.parent.with_name('outside-wallet'), target_is_directory=True)
        found, _, warnings = resolve_safestorage(str(browser), [str(self.root)], lambda: False, secrets)
        self.assertEqual(found, {})
        self.assertTrue(warnings)

    def test_gnome_text_secret_spaces(self):
        data = b'[keyring]\ndisplay-name=fixture\n[1]\ndisplay-name=Chromium Safe Storage\nsecret= leading and trailing \n'
        self.assertEqual(gnome(data)[-1]['secret'], ' leading and trailing ')

    def signal_fixture(self, path='ab/fixture', version=2):
        plain = b'attachment bytes'
        key, iv = bytes(range(64)), bytes(range(16))
        ciphertext = iv + aes(plain + b'additional authenticated padding', key[:32], iv)
        raw = ciphertext + hmac.digest(key[32:], ciphertext, 'sha256')
        metadata = dict(path=path, size=len(plain), version=version, localKey=base64.b64encode(key).decode(), fileName='../fixture.bin')
        connection = sqlite3.connect(':memory:')
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        connection.execute('CREATE TABLE messages(id TEXT, json TEXT)')
        connection.execute('INSERT INTO messages VALUES (?,?)', ('m1', json.dumps({'attachments': [metadata]})))
        database = str(self.root / '.config/Signal/sql/db.sqlite')
        return plain, raw, metadata, connection, database

    def test_signal_attachment_authentication_padding_and_tamper(self):
        plain, raw, metadata, _, _ = self.signal_fixture()
        self.assertEqual(decrypt(raw, metadata['localKey'], len(plain)), plain)
        with self.assertRaises(ParseError):
            decrypt(raw[:-1] + bytes([raw[-1] ^ 1]), metadata['localKey'], len(plain))
        with self.assertRaises(ParseError):
            decrypt(raw, base64.b64encode(bytes(64)).decode(), len(plain))
        with self.assertRaises(ParseError):
            decrypt(raw, metadata['localKey'], 999)

    def test_signal_extraction_provenance_disabled_and_path_traversal(self):
        plain, raw, _, connection, database = self.signal_fixture()
        observed = []
        def reader(path):
            observed.append(path)
            return raw
        rows, warnings = extract(connection, database, reader, lambda: False)
        self.assertFalse(warnings)
        self.assertEqual(bytes.fromhex(rows[0]['payload_hex']), plain)
        self.assertEqual(rows[0]['encrypted_source_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertTrue(observed[0].endswith('attachments.noindex/ab/fixture'))
        rows, _ = extract(connection, database, reader, lambda: False, enabled=False)
        self.assertEqual(rows[0]['extraction_status'], 'unavailable')
        _, _, _, unsafe, database = self.signal_fixture('../escape')
        observed.clear()
        rows, warnings = extract(unsafe, database, reader, lambda: False)
        self.assertEqual(observed, [])
        self.assertTrue(warnings)
        self.assertEqual(rows[0]['extraction_status'], 'unavailable')

    def test_signal_parser_acquires_selected_attachment_companion(self):
        plain, raw, metadata, _, _ = self.signal_fixture()
        path = self.root / 'home/user/.config/Signal/sql/db.sqlite'
        path.parent.mkdir(parents=True)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('CREATE TABLE messages(id TEXT, json TEXT)')
            connection.execute('INSERT INTO messages VALUES(?,?)', ('m1', json.dumps({'body': 'fixture', 'attachments': [metadata]})))
            connection.commit()
        attachment = self.file('home/user/.config/Signal/attachments.noindex/ab/fixture', raw)
        parsed = self.parse(path)
        row = next(row for row in parsed['entries'] if row['type'] == 'signal_attachment')
        self.assertEqual(bytes.fromhex(row['payload_hex']), plain)
        self.assertTrue(any(item['path'] == str(attachment) for item in parsed['inputs']))
        selected_database_only = self.parse(path, targets=[str(path.parent)])
        self.assertEqual(selected_database_only['status'], 'partial')
        row = next(row for row in selected_database_only['entries'] if row['type'] == 'signal_attachment')
        self.assertEqual(row['extraction_status'], 'unavailable')

    def test_pff_attachment_payload_budget_and_truncation(self):
        payload = b'fixture attachment'
        def attachment(data, size):
            source = io.BytesIO(data)
            return SimpleNamespace(long_filename='../fixture.bin', size=size,
                                   seek_offset=source.seek, read_buffer=source.read)
        items = [attachment(payload, len(payload)), attachment(b'short', 100), attachment(payload, len(payload))]
        message = SimpleNamespace(number_of_attachments=3, get_attachment=lambda index: items[index])
        rows, warnings, remaining = attachments(message, 'root/message:0', lambda: False, len(payload))
        self.assertEqual(rows[0]['payload_sha256'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(remaining, 0)
        self.assertEqual([row['extraction_status'] for row in rows], ['extracted', 'unavailable', 'unavailable'])
        self.assertTrue(warnings)
        truncated = SimpleNamespace(number_of_attachments=1, get_attachment=lambda index: attachment(b'short', 100))
        rows, warnings, remaining = attachments(truncated, 'root/message:1', lambda: False, 200)
        self.assertEqual(remaining, 200)
        self.assertEqual(rows[0]['extraction_status'], 'unavailable')
        self.assertNotIn('payload_hex', rows[0])

    def test_attachment_export_is_portable_checksums_and_raw_rows_unchanged(self):
        payload = b'fixture attachment'
        row = dict(type='email_attachment', locator='message:1/attachment:0', filename='../../fixture.bin',
                   extraction_status='extracted', payload_hex=payload.hex(), payload_sha256=hashlib.sha256(payload).hexdigest())
        record = dict(path='fixture.pst', sha256='a' * 64, parsed_artifact=dict(entries=[row], artifact_id='pff', parser='pff', parser_version=1,
                      inputs=[], status='parsed', record_count=1))
        output, checksums = io.BytesIO(), {}
        with zipfile.ZipFile(output, 'w') as archive:
            result = write_structured(archive, record, 1, checksums, lambda: None)
        with zipfile.ZipFile(output) as archive:
            exported = json.loads(archive.read(result['jsonl_path']))
            name = exported['payload_archive_path']
            self.assertTrue(name.startswith('terra/analysis/artifact-000001/attachments/'))
            self.assertNotIn('..', name)
            self.assertEqual(archive.read(name), payload)
            self.assertEqual(checksums[name], hashlib.sha256(payload).hexdigest())
            self.assertNotIn('payload_hex', exported)
        self.assertEqual(record['parsed_artifact']['entries'][0]['payload_hex'], payload.hex())

    def state_fixture(self):
        table = sst([(b'key', b'old', 10, 1)])
        internal = b'key' + struct.pack('<Q', (10 << 8) | 1)
        edit = b'\x01' + prefixed(b'leveldb.BytewiseComparator') + b'\x02' + varint(2)
        edit += b'\x03' + varint(4) + b'\x04' + varint(10)
        edit += b'\x07' + varint(0) + varint(1) + varint(len(table)) + prefixed(internal) + prefixed(internal)
        sources = {'CURRENT': b'MANIFEST-000003\n', 'MANIFEST-000003': fragment(edit),
                   '000001.ldb': table, '000002.log': fragment(batch([(0, b'key', b'')], 11))}
        return sources, edit

    def test_manifest_current_table_history_and_log_tombstone(self):
        from artifacts.leveldb import parse
        sources, _ = self.state_fixture()
        reader = lambda path: sources[Path(path).name]
        for name, expected in (('000001.ldb', 'superseded_acquired_record'), ('000002.log', 'latest_acquired_delete')):
            path = '/fixture/' + name
            rows = list(parse(sources[name], path, lambda: False))
            annotate(rows, path, reader, list(sources), lambda: False)
            self.assertEqual(rows[0]['state_status'], expected)
        rows = list(parse(sources['000001.ldb'], '/fixture/000009.ldb', lambda: False))
        annotate(rows, '/fixture/000009.ldb', reader, list(sources), lambda: False)
        self.assertEqual(rows[0]['state_status'], 'outside_active_manifest')

    def test_manifest_deleted_file_replay_and_unknown_tags(self):
        _, edit = self.state_fixture()
        fields, tables = manifest(fragment(edit) + fragment(b'\x06\x00\x01'))
        self.assertEqual(tables, {})
        self.assertEqual(fields['last_sequence'], 10)
        with self.assertRaises(ParseError):
            manifest(fragment(edit + b'\x63'))
        with self.assertRaises(ParseError):
            manifest(fragment(edit)[:-1])

    def test_manifest_missing_companion_and_unsafe_current_fail_closed(self):
        sources, _ = self.state_fixture()
        sources['CURRENT'] = b'../MANIFEST-000003\n'
        with self.assertRaises(ParseError):
            annotate([], '/fixture/000001.ldb', lambda path: sources[Path(path).name], list(sources), lambda: False)
        sources['CURRENT'] = b'MANIFEST-000003\n'
        sources.pop('000001.ldb')
        with self.assertRaises(ParseError):
            annotate([], '/fixture/000002.log', lambda path: sources[Path(path).name], list(sources), lambda: False)

    def test_indexeddb_scan_preserves_decoded_companion_records_and_sources(self):
        from controllers.scan_controller import ScanEngine
        from storage.memory_store import MemoryStore
        from tests.test_scan import configuration
        # Standard IndexedDB prefix + string user key, independent of decoder.
        key = b'\x00\x01\x01\x01\x01\x01\x00k'
        table = sst([(key, b'\x01\xff\x0f"\x03old', 10, 1)])
        internal = key + struct.pack('<Q', (10 << 8) | 1)
        edit = b'\x01' + prefixed(b'idb_cmp1') + b'\x02\x02\x03\x04\x04\x0a'
        edit += b'\x07\x00\x01' + varint(len(table)) + prefixed(internal) + prefixed(internal)
        folder = 'home/user/.config/chromium/Default/IndexedDB/fixture.indexeddb.leveldb/'
        self.file(folder + 'CURRENT', b'MANIFEST-000003\n')
        self.file(folder + 'MANIFEST-000003', fragment(edit))
        self.file(folder + '000001.ldb', table)
        self.file(folder + '000002.log', fragment(batch([(1, key, b'\x01\xff\x0f"\x03new')], 11)))
        store = MemoryStore()
        summary = ScanEngine({'paths': [str(self.root)]}, configuration(), store).run()
        rows = [row for record in store.records for row in record.get('parsed_artifact', {}).get('entries', [])
                if row['type'] == 'leveldb_record']
        self.assertEqual(summary['parser_failures'], 0)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['indexeddb_decode_status'] == 'decoded' for row in rows))
        self.assertEqual({row['state_status'] for row in rows}, {'latest_acquired_put', 'superseded_acquired_record'})
        self.assertTrue(all(row['source_path'].endswith(('.ldb', '.log')) for row in rows))
        self.assertEqual(len(store.records), 4)
        self.assertEqual(len({record['path'] for record in store.records}), 4)
