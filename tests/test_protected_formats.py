"""Independent native fixtures, wrong-key checks and offline scope/export tests."""
import base64
import ctypes
import ctypes.util
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import struct
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path

from artifacts.browsers.credentials import firefox_value, AES_256, KEY_ID
from artifacts.browsers.indexeddb import parse as indexeddb, script_value, json_value, gecko_value
from artifacts.catalog import definition_for
from artifacts.communication.sqlcipher import RawKeyDecoder
from artifacts.communication.telegram_crypto import decrypt as telegram_decrypt
from artifacts.companions import read_companion
from artifacts.decryption import chromium_value
from artifacts.file_collector import FileCollector, CollectionCancelled
from artifacts.installed_apps.rpm import bdb
from artifacts.parsing import parse_artifact
from artifacts.parser_support import ParseError
from controllers.configuration_controller import ConfigurationController, ConfigurationError
from controllers.export_controller import ZipExporter, public_context
from controllers.scan_controller import ScanEngine
from interface.pages.configuration import ConfigurationPage
from storage.memory_store import MemoryStore
from tests.test_extended_formats import APP, batch, fragment, varint

FIXTURES = Path(__file__).with_name('fixtures')


def encrypt_cbc(data, key, iv):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def protected_value(value, password=b'peanuts', version=b'v10'):
    key = hashlib.pbkdf2_hmac('sha1', password, b'saltysalt', 1, 16)
    return version + encrypt_cbc(value, key, b' ' * 16)


def idb_key(index=1):
    return bytes([0, 1, 1, index, 1, 1]) + b'\0k'


def telegram_block(payload, local_key):
    """Use OpenSSL's native IGE implementation, independently of TERRA's loop."""
    class AESKey(ctypes.Structure):
        _fields_ = [('round_keys', ctypes.c_uint32 * 60), ('rounds', ctypes.c_int)]
    library = ctypes.CDLL(ctypes.util.find_library('crypto'))
    library.AES_set_encrypt_key.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(AESKey)]
    library.AES_ige_encrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.POINTER(AESKey), ctypes.c_void_p, ctypes.c_int]
    plain = struct.pack('<I', len(payload) + 4) + payload
    plain = plain.ljust((len(plain) + 15) // 16 * 16, b'\x5a')
    msg = hashlib.sha1(plain).digest()[:16]
    a = hashlib.sha1(msg + local_key[8:40]).digest()
    b = hashlib.sha1(local_key[40:56] + msg + local_key[56:72]).digest()
    c = hashlib.sha1(local_key[72:104] + msg).digest()
    d = hashlib.sha1(msg + local_key[104:136]).digest()
    key = a[:8] + b[8:20] + c[4:16]
    iv = ctypes.create_string_buffer(a[8:20] + b[:8] + c[16:20] + d[:8], 32)
    schedule, output = AESKey(), ctypes.create_string_buffer(len(plain))
    assert library.AES_set_encrypt_key(key, 256, ctypes.byref(schedule)) == 0
    library.AES_ige_encrypt(plain, output, len(plain), ctypes.byref(schedule), iv, 1)
    return msg + output.raw


def qblob(data):
    return struct.pack('>I', len(data)) + data


def tdf(payload):
    version = 5000000
    trailer = struct.pack('<II', len(payload), version) + b'TDF$'
    return b'TDF$' + struct.pack('<I', version) + payload + hashlib.md5(payload + trailer).digest()


class ProtectedFormatsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def file(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def parse(self, path, secrets=None, targets=None, retained=True):
        data, metadata = FileCollector().collect(str(path), lambda: False)
        metadata['content_retained'] = retained
        return parse_artifact(definition_for(path), str(path), metadata, data, None, lambda: False,
                              {'decrypt_protected': True, '_decryption_secrets': secrets or {},
                               '_selected_paths': targets or [str(self.root)]})

    def sqlcipher(self, version=4, wal=False):
        try:
            from sqlcipher3 import dbapi2 as sql
        except ImportError:
            self.skipTest('Independent SQLCipher fixture generator not installed.')
        path = self.root / 'home/test/.config/Signal/sql/db.sqlite'
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sql.connect(str(path))
        key = '01' * 32
        # Select the writer defaults before keying initializes SQLite reserve bytes.
        connection.execute(f'PRAGMA cipher_default_compatibility={version}')
        connection.execute('PRAGMA key = "x\'' + key + '\'"')
        connection.execute('PRAGMA cipher_default_compatibility=4')
        connection.execute('CREATE TABLE messages(id TEXT,json TEXT,body TEXT,conversationId TEXT)')
        connection.commit()
        if wal:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA wal_autocheckpoint=0')
        connection.execute('INSERT INTO messages VALUES(?,?,?,?)', ('m1', '{"body":"old"}', 'native fixture message', 'c1'))
        connection.commit()
        self.addCleanup(connection.close)
        if not wal:
            connection.close()
        self.file('home/test/.config/Signal/config.json', json.dumps({'key': key}).encode())
        return path, key

    def test_chromium_linux_versions_and_wrong_key(self):
        self.assertEqual(chromium_value(protected_value(b'secret')), b'secret')
        encrypted = protected_value(b'secret', b'examiner-secret', b'v11')
        self.assertEqual(chromium_value(encrypted, 'examiner-secret'), b'secret')
        for password in ('', 'wrong'):
            with self.assertRaises(ParseError):
                chromium_value(encrypted, password)
        with self.assertRaises(ParseError):
            chromium_value(b'v20unsupported')

    def test_chromium_login_and_cookie_host_binding(self):
        path = self.root / 'home/test/.config/chromium/Default/Login Data'
        path.parent.mkdir(parents=True)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('CREATE TABLE logins(origin_url TEXT,username_value TEXT,password_value BLOB)')
            connection.execute('INSERT INTO logins VALUES(?,?,?)', ('https://example.test', 'user', protected_value(b'pass')))
            connection.commit()
        self.assertEqual(self.parse(path)['entries'][0]['password'], 'pass')
        cookies = path.with_name('Cookies')
        prefix = hashlib.sha256(b'.example.test').digest()
        with closing(sqlite3.connect(cookies)) as connection:
            connection.execute('CREATE TABLE meta(key TEXT,value TEXT)')
            connection.execute('INSERT INTO meta VALUES("version","24")')
            connection.execute('CREATE TABLE cookies(host_key TEXT,name TEXT,encrypted_value BLOB)')
            connection.execute('INSERT INTO cookies VALUES(?,?,?)', ('.example.test', 'n', protected_value(prefix + b'cookie')))
            connection.commit()
        self.assertEqual(self.parse(cookies)['entries'][0]['value'], 'cookie')
        with closing(sqlite3.connect(cookies)) as connection:
            connection.execute('UPDATE cookies SET host_key="different.test"')
            connection.commit()
        parsed = self.parse(cookies)
        self.assertEqual(parsed['status'], 'partial')
        self.assertIn('host binding', parsed['entries'][0]['decryption_error'])

    @unittest.skipUnless(ctypes.util.find_library('nss3'), 'Native NSS fixture generator unavailable')
    def test_firefox_native_nss_profiles_password_and_no_password(self):
        from tests.nss_fixture import profile
        for password in ('', 'primary-password'):
            with self.subTest(password_protected=bool(password)):
                root = self.root / ('protected' if password else 'unprotected') / '.mozilla/firefox/test.default'
                root.mkdir(parents=True)
                profile(root, password)
                path = root / 'logins.json'
                before = {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ('key4.db','logins.json')}
                result = self.parse(path, {'firefox_password': password})
                self.assertEqual(result['status'], 'parsed')
                self.assertEqual(result['entries'][0]['password'], 'fixture-password')
                self.assertEqual(result['entries'][0]['username'], 'test-user')
                self.assertTrue(any(item['path'].endswith('key4.db') for item in result['inputs']))
                for name, digest in before.items():
                    self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(), digest)
                locked = self.parse(path, {'firefox_password': 'incorrect'})
                self.assertEqual(locked['status'], 'partial')
                self.assertNotIn('password', locked['entries'][0])

    def test_firefox_aes_login_and_key_identifier(self):
        from pyasn1.type import univ
        from pyasn1.codec.der.encoder import encode
        key, iv = b'k' * 32, b'i' * 16
        algorithm = univ.Sequence();algorithm.setComponentByPosition(0, univ.ObjectIdentifier(AES_256));algorithm.setComponentByPosition(1, univ.OctetString(iv))
        value = univ.Sequence();value.setComponentByPosition(0, univ.OctetString(KEY_ID));value.setComponentByPosition(1, algorithm);value.setComponentByPosition(2, univ.OctetString(encrypt_cbc(b'aes-secret', key, iv)))
        encoded = base64.b64encode(encode(value)).decode()
        self.assertEqual(firefox_value(encoded, {KEY_ID:key}), 'aes-secret')
        with self.assertRaises(ParseError):
            firefox_value(encoded, {b'other':key})

    def test_signal_native_sqlcipher_profiles_and_verified_sources(self):
        for version in (3, 4):
            with self.subTest(version=version):
                path, key = self.sqlcipher(version)
                original = path.read_bytes()
                result = self.parse(path, retained=False)
                self.assertEqual(result['status'], 'parsed')
                self.assertEqual(result['entries'][0]['body'], 'native fixture message')
                self.assertEqual(result['entries'][0]['conversation_id'], 'c1')
                self.assertEqual(path.read_bytes(), original)
                self.assertNotIn(key, json.dumps({k:v for k,v in result.items() if k != '_supporting_snapshots'}))
                path.unlink()

    def test_signal_encrypted_wal_commit_and_wrong_key(self):
        path, key = self.sqlcipher(wal=True)
        original, wal = path.read_bytes(), path.with_name('db.sqlite-wal').read_bytes()
        result = self.parse(path)
        self.assertEqual(result['entries'][0]['body'], 'native fixture message')
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(path.with_name('db.sqlite-wal').read_bytes(), wal)
        self.assertTrue(any(item['path'].endswith('-wal') for item in result['inputs']))
        with self.assertRaises(ParseError):
            self.parse(path, {'signal_key': '02' * 32})

    def test_signal_wrapped_config_and_scope(self):
        path, key = self.sqlcipher()
        config = path.parent.parent / 'config.json'
        config.write_text(json.dumps({'encryptedKey':protected_value(key.encode(), b'local-secret', b'v11').hex()}))
        result = self.parse(path, {'safe_storage_password':'local-secret'})
        self.assertEqual(result['entries'][0]['body'], 'native fixture message')
        locked = self.parse(path, targets=[str(path.parent)])
        self.assertEqual(locked['status'], 'partial')
        self.assertIn('outside', locked['entries'][0]['decryption_error'])

    def test_sqlcipher_authenticated_corruption_and_cancel(self):
        path, key = self.sqlcipher()
        raw = bytearray(path.read_bytes());raw[-100] ^= 1
        with self.assertRaises(ParseError):
            RawKeyDecoder(bytes.fromhex(key))(bytes(raw), b'', lambda:False)
        with self.assertRaises(CollectionCancelled):
            RawKeyDecoder(bytes.fromhex(key))(path.read_bytes(), b'', lambda:True)

    @unittest.skipUnless(importlib.util.find_spec('dissect'), 'Optional Dissect reader unavailable')
    def test_bdb_native_hash_and_btree(self):
        for kind in ('hash','btree'):
            rows = list(bdb((FIXTURES / ('rpm-'+kind+'.db')).read_bytes(), lambda:False))
            self.assertEqual(rows[0]['package'], 'example')
            self.assertEqual(rows[0]['version'], '1.2')
            path = self.file('var/lib/rpm/Packages', (FIXTURES / ('rpm-'+kind+'.db')).read_bytes())
            self.assertEqual(self.parse(path)['entries'][0]['backend'], 'bdb')
        with self.assertRaises(CollectionCancelled):
            list(bdb((FIXTURES/'rpm-hash.db').read_bytes(), lambda:True))
        with self.assertRaises(Exception):
            list(bdb((FIXTURES/'rpm-hash.db').read_bytes()[:100], lambda:False))

    @unittest.skipUnless(importlib.util.find_spec('dfindexeddb'), 'Optional IndexedDB reader unavailable')
    def test_indexeddb_native_v8_types_cycles_and_sparse_length(self):
        raw = b'\xff\x11' + (FIXTURES/'v8-object.bin').read_bytes()
        value = script_value(raw, lambda:False)
        self.assertIs(value['self'], value)
        self.assertIs(value['alias'], value['shared'])
        self.assertIs(value['map'].entries[0][0], value['shared'])
        self.assertIs(value['set'].values[0], value['shared'])
        self.assertEqual(value['sparse'].length, 1_000_000_000)
        self.assertEqual(value['bigint'].value, 123456789012345678901234567890)
        normalized = json_value(value)
        self.assertIn('$ref', json.dumps(normalized))
        import snappy
        for encoded in (raw, b'\xff\x11\x02'+snappy.compress(raw)):
            rows, warnings, status = indexeddb(fragment(batch([(1,idb_key(),b'\x01'+encoded)])), '000001.log', lambda:False)
            self.assertEqual(status,'parsed')
            self.assertEqual(rows[0]['indexeddb_decode_status'],'decoded')
            self.assertIn('fixture message',json.dumps(rows[0]['indexeddb_value']))

    @unittest.skipUnless(importlib.util.find_spec('dfindexeddb'), 'Optional IndexedDB reader unavailable')
    def test_indexeddb_unknown_tags_partial_and_cancel(self):
        rows, _, status = indexeddb(fragment(batch([(1,idb_key(),b'\x01\xff\x0f?')])), '000001.log',lambda:False)
        self.assertEqual(status,'partial')
        self.assertIn('value_hex',rows[0])
        with self.assertRaises(CollectionCancelled):
            script_value((FIXTURES/'v8-object.bin').read_bytes(),lambda:True)
        with self.assertRaises(ParseError):
            script_value(b'\xff\x11\x02'+varint(100_000_000),lambda:False)

    @unittest.skipUnless(importlib.util.find_spec('dfindexeddb'), 'Optional IndexedDB reader unavailable')
    def test_indexeddb_external_blob_provenance(self):
        raw = b'\xff\x0f"\x05hello'
        path = self.file('home/test/.config/chromium/Default/IndexedDB/https_example.indexeddb.leveldb/000001.log',
                        fragment(batch([(1,idb_key(),b'\x01\xff\x11\x01'+varint(len(raw))+b'\0'),
                                        (1,idb_key(3),b'\0\x01\0'+varint(len(raw)))])))
        blob = self.file('home/test/.config/chromium/Default/IndexedDB/https_example.indexeddb.blob/1/00/1',raw)
        result = self.parse(path)
        candidate = result['entries'][0]['external_blob_candidates'][0]
        self.assertEqual(candidate['value'],'hello')
        self.assertEqual(result['status'],'partial')
        self.assertTrue(any(item['path']==str(blob) for item in result['inputs']))
        self.assertIn('not established',candidate['association'])

    @unittest.skipUnless(importlib.util.find_spec('dfindexeddb'), 'Optional IndexedDB reader unavailable')
    def test_gecko_snappy_crc_and_inline_sqlite(self):
        import snappy
        from artifacts.leveldb import masked_crc
        raw = struct.pack('<II',0,0xfff10000)+struct.pack('<II',42,0xffff0003)
        self.assertEqual(gecko_value(snappy.compress(raw),lambda:False),42)
        chunk = struct.pack('<I',masked_crc(raw))+raw
        framed = b'\xff\x06\x00\x00sNaPpY\x01'+len(chunk).to_bytes(3,'little')+chunk
        self.assertEqual(gecko_value(framed,lambda:False),42)
        with self.assertRaises(ParseError):gecko_value(framed[:-1]+b'X',lambda:False)
        path = self.root/'home/test/.mozilla/firefox/a.default/storage/default/https_example/idb/1.sqlite'
        path.parent.mkdir(parents=True)
        with closing(sqlite3.connect(path)) as c:
            c.execute('CREATE TABLE object_data(key BLOB,data BLOB,object_store_id INTEGER)')
            c.execute('INSERT INTO object_data VALUES(?,?,?)',(b'\x30l\0',snappy.compress(raw),1))
            c.commit()
        result=self.parse(path)
        self.assertEqual(result['status'],'parsed')
        self.assertEqual(result['entries'][0]['value'],42)

    @unittest.skipUnless(importlib.util.find_spec('dfindexeddb'), 'Optional IndexedDB reader unavailable')
    def test_gecko_external_clone_reference_and_scope(self):
        import snappy
        raw=struct.pack('<II',0,0xfff10000)+struct.pack('<II',99,0xffff0003)
        path=self.root/'home/test/.mozilla/firefox/a.default/storage/default/https_example/idb/1.sqlite'
        path.parent.mkdir(parents=True)
        with closing(sqlite3.connect(path)) as c:
            c.execute('CREATE TABLE object_data(key BLOB,data INTEGER,object_store_id INTEGER,file_ids TEXT)')
            c.execute('INSERT INTO object_data VALUES(?,?,?,?)',(b'\x30l\0',1<<32,1,'.2'))
            c.commit()
        blob=self.file(str(path.relative_to(self.root)).replace('.sqlite','.files/2'),snappy.compress(raw))
        result=self.parse(path)
        self.assertEqual(result['entries'][0]['value'],99)
        self.assertTrue(any(item['path']==str(blob) for item in result['inputs']))
        restricted=self.parse(path,targets=[str(path)])
        self.assertEqual(restricted['status'],'partial')

    @unittest.skipUnless(ctypes.util.find_library('crypto'), 'Native OpenSSL fixture generator unavailable')
    def test_telegram_native_ige_draft_and_integrity(self):
        key = bytes(range(256))
        text = 'local draft'
        plain = struct.pack('>QQIq',0xffffffffffffff03,123,1,10)+qblob(text.encode('utf-16-be'))+qblob(b'')+struct.pack('>qi',7,0)
        encrypted = telegram_block(plain,key)
        self.assertEqual(telegram_decrypt(encrypted,key,lambda:False),plain)
        with self.assertRaises(ParseError):telegram_decrypt(encrypted,b'X'*256,lambda:False)
        path=self.file('home/test/.local/share/TelegramDesktop/tdata/D877F783D5D3EF8C/abcdef0123456789s',tdf(qblob(encrypted)))
        result=self.parse(path,{'telegram_key':key.hex()})
        self.assertEqual(result['status'],'parsed')
        self.assertEqual(result['entries'][1]['type'],'chat_draft')
        self.assertEqual(result['entries'][1]['body'],text)

    @unittest.skipUnless(ctypes.util.find_library('crypto'), 'Native OpenSSL fixture generator unavailable')
    def test_telegram_key_data_passcode_companion(self):
        key,salt,password=bytes(range(256)),b's'*32,b'passcode'
        derived=hashlib.pbkdf2_hmac('sha512',hashlib.sha512(salt+password+salt).digest(),salt,100000,256)
        self.file('home/test/.local/share/TelegramDesktop/tdata/key_datas',tdf(qblob(salt)+qblob(telegram_block(key,derived))+qblob(telegram_block(b'account',key))))
        path=self.file('home/test/.local/share/TelegramDesktop/tdata/abcdef0123456789s',tdf(qblob(telegram_block(b'unsupported inner data',key))))
        result=self.parse(path,{'telegram_passcode':'passcode'})
        self.assertTrue(result['entries'][0]['content_decrypted'])
        self.assertEqual(result['status'],'partial')
        self.assertTrue(any(item['path'].endswith('key_datas') for item in result['inputs']))
        locked=self.parse(path,{'telegram_passcode':'wrong'})
        self.assertFalse(locked['entries'][0]['content_decrypted'])

    def test_companion_scope_and_symlinks(self):
        outside = self.file('outside/key',b'secret')
        selected=self.root/'selected';selected.mkdir()
        with self.assertRaises(ParseError):read_companion(str(outside),[str(selected)],lambda:False)
        (selected/'link').symlink_to(outside.parent,target_is_directory=True)
        with self.assertRaises(OSError):read_companion(str(selected/'link/key'),[str(selected)],lambda:False)

    def test_gui_automatic_decoding_without_secret_fields(self):
        page=ConfigurationPage();self.addCleanup(page.deleteLater)
        for option in page.options.values():option.setChecked(False)
        emitted=[];page.start_requested.connect(emitted.append);page.submit()
        self.assertFalse(hasattr(page, 'decryption'))
        self.assertTrue(emitted[0]['decrypt_protected'])
        self.assertEqual(emitted[0]['_decryption_secrets'], {})
        self.assertNotIn('_decryption_secrets',public_context({'configuration':emitted[0]})['configuration'])

    def test_signal_wrapped_key_discovered_from_same_user_keyring(self):
        path, key = self.sqlcipher()
        config = path.parent.parent / 'config.json'
        config.write_text(json.dumps({'encryptedKey': protected_value(key.encode(), b'local-secret', b'v11').hex()}))
        keyring = self.file('home/test/.local/share/keyrings/login.keyring',
                            b'[keyring]\n[item]\ndisplay-name=Signal Safe Storage\nsecret=local-secret\n'
                            b'[item:attribute0]\nname=application\nvalue=signal\n')
        result = self.parse(path)
        self.assertEqual(result['status'], 'parsed')
        self.assertEqual(result['entries'][0]['body'], 'native fixture message')
        self.assertTrue(any(item['path'] == str(keyring) for item in result['inputs']))
        self.assertEqual(result['key_discovery_inputs'][0]['locator'], 'section:item/secret')
        self.assertNotIn('local-secret', json.dumps({k: v for k, v in result.items() if k != '_supporting_snapshots'}))

    def test_scan_zip_decrypted_findings_and_secret_exclusion(self):
        path,key=self.sqlcipher()
        context={'collection_mode':'all_supported','hashes':[],'keywords':[],
                 'options':dict(folder_names=False,file_names=False,file_contents=False,hash_matches=False),
                 'decrypt_protected':True,'_decryption_secrets':{'signal_key':key,'firefox_password':'examiner-only-password'}}
        store=MemoryStore();summary=ScanEngine({'paths':[str(self.root)]},context,store).run()
        self.assertEqual(summary['parser_failures'],0)
        records,diagnostics,count=store.snapshot()
        destination=self.root.parent/(self.root.name+'-export.zip');self.addCleanup(lambda:destination.unlink(missing_ok=True))
        ZipExporter(records,diagnostics,count,{'targets':{'paths':[str(self.root)]},'configuration':context,'scan_summary':summary}).save(str(destination))
        with zipfile.ZipFile(destination) as archive:
            manifest=archive.read('terra/manifest.json').decode()
            self.assertNotIn('_decryption_secrets',manifest)
            self.assertNotIn('examiner-only-password',manifest)
            rows=[json.loads(line) for name in archive.namelist() if name.endswith('records.jsonl') for line in archive.read(name).splitlines()]
            self.assertTrue(any(row.get('body')=='native fixture message' for row in rows))
            self.assertEqual(archive.read(next(name for name in archive.namelist() if name.endswith('/db.sqlite'))),path.read_bytes())
