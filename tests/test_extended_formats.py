"""Independent format fixtures, corruption cases and scan/export provenance."""
import hashlib
import io
import json
import os
import sqlite3
import struct
import tempfile
import unittest
import zipfile
import zlib
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from PySide6.QtWidgets import QApplication

from artifacts.catalog import definition_for
from artifacts.file_collector import FileCollector, CollectionCancelled
from artifacts.parsing import parse_artifact
from artifacts.parser_support import ParseError
from artifacts.leveldb import masked_crc, parse as leveldb, snappy
from artifacts.browsers.sessions import mozlz4
from artifacts.email.pff import parse as pff
from artifacts.installed_apps.rpm import header as rpm_header
from controllers.scan_controller import ScanEngine
from controllers.export_controller import ZipExporter
from storage.memory_store import MemoryStore

APP = QApplication.instance() or QApplication([])


def varint(value):
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def prefixed(value):
    return varint(len(value)) + value


def batch(operations, sequence=10):
    return struct.pack('<QI', sequence, len(operations)) + b''.join(
        bytes([kind]) + prefixed(key) + (prefixed(value) if kind else b'')
        for kind, key, value in operations)


def fragment(data, kind=1):
    return struct.pack('<IHB', masked_crc(bytes([kind]) + data), len(data), kind) + data


def restart_block(items):
    content = b''
    for key, value in items:
        content += varint(0) + varint(len(key)) + varint(len(value)) + key + value
    return content + struct.pack('<II', 0, 1)


def sst(items, compressed=False):
    payload = restart_block([(key + struct.pack('<Q', (sequence << 8) | kind), value)
                             for key, value, sequence, kind in items])
    if compressed:
        # Standard raw Snappy stream: a literal, independently constructed.
        size = len(payload)
        if size <= 60:
            raw = varint(size) + bytes([(size - 1) << 2]) + payload
        else:
            raw = varint(size) + bytes([60 << 2, size - 1]) + payload
    else:
        raw = payload
    data_block = raw + bytes([int(compressed)]) + struct.pack('<I', masked_crc(raw + bytes([int(compressed)])))
    index = restart_block([(b'z' + struct.pack('<Q', 1), varint(0) + varint(len(raw)))])
    index_block = index + b'\0' + struct.pack('<I', masked_crc(index + b'\0'))
    handles = varint(0) + varint(0) + varint(len(data_block)) + varint(len(index))
    return data_block + index_block + handles.ljust(40, b'\0') + struct.pack('<Q', 0xdb4775248b80fb57)


def rpm_blob():
    store = b'example\0' + b'1.2\0' + b'x86_64\0'
    fields = [(1000, 6, 0, 1), (1001, 6, 8, 1), (1022, 6, 12, 1)]
    return struct.pack('>II', len(fields), len(store)) + b''.join(struct.pack('>4I', *f) for f in fields) + store


class ExtendedFormatsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def file(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def db(self, name, schema, query, values):
        path = self.file(name, b'')
        with sqlite3.connect(path) as connection:
            connection.executescript(schema)
            connection.execute(query, values)
        connection.close()
        return path

    def parse(self, path, retain=32 * 1024 * 1024):
        data, metadata = FileCollector(retain).collect(str(path), lambda: False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            definition = definition_for(path)
            self.assertIsNotNone(definition)
            return parse_artifact(definition, str(path), metadata, data, directory, lambda: False)
        finally:
            os.close(directory)

    def test_lastlog_sparse_uid_terminal_not_username(self):
        record = struct.pack('<i', 1700000000) + b'pts/3'.ljust(32, b'\0') + b'example.test'.ljust(256, b'\0')
        result = self.parse(self.file('var/log/lastlog', b'\0' * 292 * 3 + record))
        self.assertEqual(result['record_count'], 1)
        self.assertEqual(result['entries'][0]['uid'], 3)
        self.assertEqual(result['entries'][0]['terminal'], 'pts/3')
        self.assertNotIn('username', result['entries'][0])

    def test_lastlog_bad_layout_and_negative_time(self):
        for data in (b'x', struct.pack('<i', -1) + b'\0' * 288):
            with self.assertRaises(ParseError):
                self.parse(self.file('var/log/lastlog', data))

    def test_lastlog2_and_rpm_sqlite(self):
        source = self.db('var/lib/lastlog/lastlog2.db',
                         'CREATE TABLE Lastlog2(Name TEXT,Time INTEGER,TTY TEXT,RemoteHost TEXT,Service TEXT);',
                         'INSERT INTO Lastlog2 VALUES(?,?,?,?,?)', ('tester', 1700000000, 'pts/1', 'host', 'sshd'))
        result = self.parse(source)
        self.assertEqual(result['entries'][0]['service'], 'sshd')
        source = self.db('usr/lib/sysimage/rpm/rpmdb.sqlite',
                         'CREATE TABLE Packages(hnum INTEGER,blob BLOB);',
                         'INSERT INTO Packages VALUES(?,?)', (7, rpm_blob()))
        result = self.parse(source, retain=1)
        self.assertEqual(result['entries'][0]['package'], 'example')
        self.assertEqual(result['entries'][0]['architecture'], 'x86_64')
        self.assertEqual(result['inputs'][0]['sha256'], hashlib.sha256(source.read_bytes()).hexdigest())

    def test_rpm_header_bounds_and_magic(self):
        self.assertEqual(rpm_header(b'\x8e\xad\xe8\x01' + b'\0'*4 + rpm_blob(), lambda: False)['name'], 'example')
        for data in (rpm_blob()[:-1], struct.pack('>II', 0xffffffff, 1) + b'x'):
            with self.assertRaises(ParseError):
                rpm_header(data, lambda: False)

    def test_rpm_ndb_inventory_and_blob_checksum(self):
        header=rpm_blob()
        pages=bytearray(4096)
        struct.pack_into('<4s4I',pages,0,b'RpmP',0,5,1,8)
        for offset in range(32,4096,16):struct.pack_into('<4sIII',pages,offset,b'Slot',0,0,0)
        count=(len(header)+28+15)//16
        struct.pack_into('<4sIII',pages,32,b'Slot',7,256,count)
        blob=struct.pack('<4sIII',b'BlbS',7,4,len(header))+header
        blob=blob.ljust(count*16-12,b'\0')
        blob+=struct.pack('<II4s',zlib.adler32(blob),len(header),b'BlbE')
        data=bytes(pages)+blob
        path=self.file('var/lib/rpm/Packages.db',data)
        result=self.parse(path)
        self.assertEqual(result['entries'][0]['package'],'example')
        self.assertEqual(result['entries'][0]['backend'],'ndb')
        corrupted=bytearray(data);corrupted[4112]^=1
        path.write_bytes(corrupted)
        with self.assertRaisesRegex(ParseError, 'checksum'):self.parse(path)

    def test_rpm_ndb_overlapping_slots(self):
        pages=bytearray(4096)
        struct.pack_into('<4s4I',pages,0,b'RpmP',0,5,1,8)
        for offset in range(32,4096,16):struct.pack_into('<4sIII',pages,offset,b'Slot',0,0,0)
        struct.pack_into('<4sIII',pages,32,b'Slot',7,256,4)
        struct.pack_into('<4sIII',pages,48,b'Slot',8,258,4)
        path=self.file('var/lib/rpm/Packages.db',bytes(pages)+b'\0'*96)
        with self.assertRaisesRegex(ParseError, 'Overlapping'):self.parse(path)

    def test_crc32c_standard_vector(self):
        expected = (((0xe3069283 >> 15) | (0xe3069283 << 17)) + 0xa282ead8) & 0xffffffff
        self.assertEqual(masked_crc(b'123456789'), expected)

    def test_leveldb_log_put_delete_and_chromium_dom_strings(self):
        key = b'_https://example.test\0\x01name'
        source = self.file('home/test/.config/chromium/Default/Local Storage/leveldb/000001.log',
                           fragment(batch([(1, key, b'\0h\0i\0'), (0, key, b'')], sequence=30)))
        result = self.parse(source)
        self.assertEqual([r['sequence'] for r in result['entries']], [30, 31])
        self.assertEqual(result['entries'][0]['storage_value'], 'hi')
        self.assertEqual(result['entries'][1]['operation'], 'delete')
        self.assertEqual(result['entries'][0]['storage_key'], 'name')

    def test_leveldb_fragment_across_blocks(self):
        value = b'x' * 40000
        payload = batch([(1, b'key', value)])
        data = fragment(payload[:32761], 2) + fragment(payload[32761:], 4)
        result = list(leveldb(data, '/Local Storage/000001.log', lambda: False))
        self.assertEqual(result[0]['value_utf8'], value.decode())

    def test_leveldb_session_strings_and_local_metadata_timestamp(self):
        payload=fragment(batch([(1,b'map-7-key', 'value'.encode('utf-16-le'))]))
        result=list(leveldb(payload,'/Session Storage/1.log',lambda:False))
        self.assertEqual(result[0]['storage_map_id'],'7')
        self.assertEqual(result[0]['storage_value'],'value')
        metadata=b'\x08'+varint(13344473600000000)+b'\x10'+varint(12)
        result=list(leveldb(fragment(batch([(1,b'META:https://example.test',metadata)])),
                            '/Local Storage/1.log',lambda:False))
        self.assertTrue(result[0]['storage_metadata_time_utc'].startswith('2023-'))
        self.assertEqual(result[0]['storage_size_bytes'],12)

    def test_leveldb_sst_raw_and_snappy(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                data = sst([(b'key', b'value', 42, 1), (b'old', b'', 43, 0)], compressed)
                records = list(leveldb(data, '000001.ldb', lambda: False))
                self.assertEqual(records[0]['value_utf8'], 'value')
                self.assertEqual(records[1]['operation'], 'delete')

    def test_leveldb_corrupt_checksums_and_batch_count(self):
        good = fragment(batch([(1, b'key', b'value')]))
        bad_count = bytearray(batch([(1, b'key', b'value')]))
        struct.pack_into('<I', bad_count, 8, 0)
        for data, name in ((bytes([good[0] ^ 1]) + good[1:], 'x.log'), (good[:-1], 'x.log'),
                           (fragment(bytes(bad_count)), 'x.log'), (sst([(b'key', b'value', 1, 1)])[:-1], 'x.ldb')):
            with self.subTest(name=name), self.assertRaises(ParseError):
                list(leveldb(data, name, lambda: False))

    def test_snappy_invalid_distance_and_size(self):
        for data in (b'\x04\x01\x00', varint(65*1024*1024), b'\x01\x00'):
            with self.assertRaises(ParseError):
                snappy(data, lambda: False)
        self.assertEqual(snappy(b'\x08\x00a\x1a\x01\x00', lambda: False), b'a'*8)

    def test_firefox_session_lz4_closed_tabs_and_bookmarks(self):
        try:
            from lz4.block import compress
        except ImportError:
            self.skipTest('Independent LZ4 comparison library is unavailable.')
        document = {'windows': [{'tabs': [{'index': 1, 'lastAccessed': 1700000000000,
                     'entries': [{'url': 'https://example.test', 'title': 'Example'}]}],
                     '_closedTabs': [{'state': {'entries': [{'url': 'https://closed.test'}]}}]}]}
        data = json.dumps(document).encode()
        compressed = b'mozLz40\0' + compress(data, store_size=True)
        self.assertEqual(mozlz4(compressed, lambda: False), data)
        result = self.parse(self.file('home/test/.mozilla/firefox/p/sessionstore-backups/recovery.jsonlz4', compressed))
        self.assertEqual(result['entries'][0]['url'], 'https://example.test')
        self.assertTrue(result['entries'][1]['closed'])
        self.assertNotIn('timestamp_utc', result['entries'][0])
        bookmark = {'children': [{'uri': 'https://bookmark.test', 'dateAdded': 1700000000000000}]}
        result = self.parse(self.file('home/test/.mozilla/firefox/p/bookmarkbackups/bookmarks.json', json.dumps(bookmark).encode()))
        self.assertEqual(result['entries'][0]['url'], 'https://bookmark.test')

    def test_lz4_corruption_and_safety_limit(self):
        for data in (b'mozLz40\0'+struct.pack('<I', 65*1024*1024),
                     b'mozLz40\0'+struct.pack('<I', 4)+b'\x00\x00\x00'):
            with self.assertRaises(ParseError):
                mozlz4(data, lambda: False)

    def test_firefox_permissions(self):
        path=self.db('home/test/.mozilla/firefox/p/permissions.sqlite',
                     'CREATE TABLE moz_perms(id INTEGER,origin TEXT,type TEXT,permission INTEGER,modificationTime INTEGER);',
                     'INSERT INTO moz_perms VALUES(?,?,?,?,?)', (1, 'https://example.test', 'camera', 1, 1700000000000))
        self.assertEqual(self.parse(path)['entries'][0]['fields']['type'], 'camera')

    def test_snap_and_flatpak_metadata(self):
        state={'data': {'snaps': {'example': {'active': True, 'current': '12', 'sequence': [{'revision': '12'}]}}}}
        result=self.parse(self.file('var/lib/snapd/state.json', json.dumps(state).encode()))
        self.assertEqual(result['entries'][0]['current_revision'], '12')
        result=self.parse(self.file('var/lib/flatpak/app/org.example.App/x86_64/stable/hash/metadata',
                                    b'[Application]\nname=org.example.App\nruntime=org.example.Runtime/x86_64/stable\n'))
        self.assertEqual(result['entries'][0]['package'], 'org.example.App')

    def test_telegram_wrapper_and_checksum_failure(self):
        payload=b'\0\0\0\4test'
        version=5000000
        digest=hashlib.md5(payload+struct.pack('<II', len(payload),version)+b'TDF$').digest()
        data=b'TDF$'+struct.pack('<I',version)+payload+digest
        path=self.file('home/test/.local/share/TelegramDesktop/tdata/key_datas',data)
        result=self.parse(path)
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['entries'][0]['content_decrypted'])
        path.write_bytes(data[:-1]+bytes([data[-1]^1]))
        with self.assertRaises(ParseError):self.parse(path)

    def test_signal_key_metadata_never_contains_key(self):
        key='sensitive-key'
        result=self.parse(self.file('home/test/.config/Signal/config.json', json.dumps({'key':key,'encryptedKey':'secret'}).encode()))
        self.assertEqual(result['status'],'partial')
        self.assertTrue(result['entries'][0]['plaintext_key_present'])
        self.assertNotIn(key,json.dumps(result))

    def test_signal_plaintext_and_encrypted_diagnostic(self):
        path=self.db('home/test/.config/Signal/sql/db.sqlite', 'CREATE TABLE messages(id TEXT,json TEXT);',
                     'INSERT INTO messages VALUES(?,?)', ('m1',json.dumps({'body':'test','conversationId':'c1'})))
        self.assertEqual(self.parse(path)['entries'][0]['body'],'test')
        path.write_bytes(b'encrypted SQLCipher bytes')
        result = self.parse(path)
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['entries'][0]['content_decrypted'])
        self.assertIn('decryption_error', result['entries'][0])

    def test_pff_optional_backend_partial_status(self):
        data=bytearray(564);data[:4]=b'!BDN';struct.pack_into('<H',data,10,23)
        with patch('artifacts.email.pff.importlib.import_module', side_effect=ImportError):
            result=self.parse(self.file('home/test/mail.pst',data))
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['entries'][0]['type'],'mail_store_header')
        self.assertIn('unavailable',result['limitations'][-1])

    def test_pff_readonly_file_object_and_close(self):
        data=bytearray(564);data[:4]=b'!BDN';struct.pack_into('<H',data,10,23)
        message=SimpleNamespace(identifier=2,subject='Example',sender_name='Tester',transport_headers=b'From: example@test',
                    plain_text_body=b'body',html_body=None,delivery_time=datetime(2024,1,1),client_submit_time=None,
                    creation_time=None,modification_time=None,number_of_attachments=0)
        folder=SimpleNamespace(identifier=1,name='Inbox',number_of_sub_messages=1,number_of_sub_folders=0,get_sub_message=lambda _:message)
        calls=[]
        archive=SimpleNamespace(open_file_object=lambda source,mode:calls.append((isinstance(source,io.BytesIO),mode)),
                                get_root_folder=lambda:folder,close=lambda:calls.append('close'))
        with patch('artifacts.email.pff.importlib.import_module',return_value=SimpleNamespace(file=lambda:archive)):
            rows,_,status=pff(bytes(data),lambda:False)
        self.assertEqual(calls,[(True,'r'),'close'])
        self.assertEqual(status,'parsed')
        self.assertEqual(rows[-1]['delivery_time_utc'],'2024-01-01T00:00:00+00:00')

    def test_cancellation(self):
        for parse,args in ((leveldb,(fragment(batch([(1,b'a',b'b')])), 'x.log')),
                           (snappy,(b'\x01\x00a',)),(mozlz4,(b'mozLz40\0'+struct.pack('<I',1)+b'\x10a',))):
            with self.assertRaises(CollectionCancelled):list(parse(*args,lambda:True)) if parse is leveldb else parse(*args,lambda:True)

    def test_catalog_priority_offline_roots_and_raw_fallbacks(self):
        cases={'var/lib/rpm/rpmdb.sqlite':'rpm_sqlite_inventory',
               'var/lib/rpm/Packages':'rpm_bdb_inventory','var/lib/lastlog/lastlog2.db':'lastlog2_records',
               'home/x/.config/discord/Local Storage/leveldb/1.ldb':'electron_leveldb_records',
               'home/x/.config/chromium/Default/IndexedDB/https_example.indexeddb.leveldb/1.ldb':'chromium_leveldb_records',
               'home/x/.config/chromium/Default/Local Storage/leveldb/MANIFEST-000001':'chromium_stores'}
        for path,id in cases.items():
            with self.subTest(path=path):self.assertEqual(definition_for(self.root/'mounted' / path)['id'],id)

    def test_scan_partial_and_failed_records_preserve_raw_export(self):
        self.file('home/test/.config/Signal/config.json',b'{"encryptedKey":"opaque"}')
        self.file('home/test/.config/chromium/Default/Local Storage/leveldb/000001.log',fragment(batch([(1,b'key',b'value')])))
        self.file('home/test/.config/Signal/sql/db.sqlite',b'encrypted database')
        store=MemoryStore()
        config={'collection_mode':'all_supported','hashes':[],'keywords':[],
                'options':dict(folder_names=False,file_names=False,file_contents=False,hash_matches=False)}
        engine=ScanEngine({'paths':[str(self.root)]},config,store)
        summary=engine.run()
        self.assertEqual(summary['partial_parsed_files'],2)
        self.assertEqual(summary['parser_failures'],0)
        records,diagnostics,count=store.snapshot()
        self.assertEqual(len(records),3)
        destination=self.root.parent/(self.root.name+'-export.zip')
        self.addCleanup(lambda: destination.unlink(missing_ok=True))
        exporter=ZipExporter(records,diagnostics,count,{'case':None,'targets':{'paths':[str(self.root)]},'configuration':config,'summary':summary})
        exporter.save(str(destination))
        with zipfile.ZipFile(destination) as archive:
            names=archive.namelist()
            self.assertTrue(any(n.endswith('records.jsonl') for n in names))
            self.assertTrue(any(n.endswith('db.sqlite') for n in names))
            self.assertIn('terra/logs/diagnostics.jsonl',names)
            partial = [json.loads(archive.read(name)) for name in names if name.endswith('metadata.json')]
            partial = next(item for item in partial if item.get('status') == 'partial')
            base = next(name.rsplit('/',1)[0] for name in names if name.endswith('metadata.json') and json.loads(archive.read(name)).get('status') == 'partial')
            row=json.loads(archive.read(base+'/records.jsonl').splitlines()[0])
            self.assertEqual(row['provenance']['parser_status'],'partial')
