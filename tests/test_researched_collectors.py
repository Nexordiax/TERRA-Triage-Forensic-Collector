import base64
import bz2
import ctypes
import errno
import hashlib
import json
import lzma
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ['QT_QPA_PLATFORMTHEME'] = 'generic'

from artifacts.catalog import definition_for
from artifacts.file_collector import CollectionCancelled
from artifacts.os_activity.journal import parse as journal
from artifacts.parser_support import ParseError, read_verified, text_lines
from artifacts.persistence import parse
from controllers.scan_controller import ScanEngine
from controllers.export_controller import ZipExporter
from storage.memory_store import MemoryStore
from PySide6.QtWidgets import QApplication


class RevisitedCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def rows(self, parser, data, path='fixture'):
        return list(parse(parser, data.encode() if isinstance(data, str) else data, path, lambda: False))

    def test_authorized_and_known_keys_with_fingerprints(self):
        key_type = b'ssh-ed25519'
        key = struct.pack('>I', len(key_type)) + key_type + struct.pack('>I', 32) + b'x' * 32
        encoded = base64.b64encode(key).decode()
        expected = 'SHA256:' + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
        authorized = self.rows('authorized_keys', 'command="echo a b",no-pty ssh-ed25519 ' + encoded + ' comment')[0]
        self.assertEqual(authorized['fingerprint'], expected)
        self.assertEqual(authorized['prefix_fields'], ['command=echo a b,no-pty'])
        known = self.rows('known_hosts', '|1|hashed|host ssh-ed25519 ' + encoded)[0]
        self.assertEqual(known['prefix_fields'], ['|1|hashed|host'])
        self.assertEqual(known['fingerprint'], expected)
        bad = self.rows('known_hosts', 'host ssh-rsa not-a-key')[0]
        self.assertEqual(bad['type'], 'ssh_unparsed_record')
        self.assertEqual(bad['definition'], 'host ssh-rsa not-a-key')

    def test_deb822_repositories_keep_multiline_and_disabled_state(self):
        rows = self.rows('apt_sources', '# comment\nTypes: deb\nURIs: https://example.test\nSuites: stable\nSigned-By: first\n second\nEnabled: no\n\nTypes: deb-src\nURIs: https://example.test\n', 'test.sources')
        self.assertEqual(len(rows), 2)
        self.assertFalse(rows[0]['enabled'])
        self.assertEqual(rows[0]['fields']['Signed-By'], 'first\nsecond')
        self.assertTrue(rows[1]['enabled'])
        with self.assertRaises(ParseError):
            self.rows('apt_sources', 'bad stanza', 'test.sources')

    def test_extension_metadata_preserved_without_execution(self):
        manifest = dict(manifest_version=3, name='__MSG_name__', version='1.0', permissions=['history'], background={'service_worker':'script.js'})
        rows = self.rows('extension_manifest', json.dumps(manifest))
        self.assertEqual(rows[0]['fields'], manifest)
        self.assertEqual(rows[0]['name'], '__MSG_name__')
        rows = self.rows('firefox_extensions', json.dumps({'addons':[{'id':'test@example','active':False,'version':'1'}]}))
        self.assertFalse(rows[0]['active'])
        with self.assertRaises(ParseError):
            self.rows('extension_manifest', '{}')

    def test_new_path_priority_and_offline_roots(self):
        cases = {'/media/disk/etc/sudoers':'sudoers', '/media/disk/etc/ld.so.preload':'loader_config',
                 '/media/disk/etc/apt/sources.list.d/test.sources':'apt_sources',
                 '/media/disk/home/test/.config/google-chrome/Default/Extensions/id/1/manifest.json':'extension_manifest',
                 '/media/disk/home/test/.mozilla/firefox/p/extensions.json':'firefox_extensions',
                 '/media/disk/etc/systemd/system/x.service.d/override.conf':'systemd',
                 '/media/disk/home/test/.config/systemd/user/x.timer':'systemd',
                 '/media/disk/etc/xdg/autostart/test.desktop':'desktop',
                 '/media/disk/var/spool/crontabs/test':'cron',
                 '/media/disk/var/log/custom.bin':None}
        for path, parser in cases.items():
            with self.subTest(path=path):
                self.assertEqual(definition_for(path)['parser'], parser)

    def test_parser_cancellation(self):
        with self.assertRaises(CollectionCancelled):
            list(parse('startup_script', b'echo test\n', 'fixture', lambda: True))

    def test_rotated_xz_bz2_logs_decode_and_reject_corruption(self):
        for extension, compress in (('.xz', lzma.compress), ('.bz2', bz2.compress)):
            with self.subTest(extension=extension):
                rows = list(text_lines(compress(b'first\nsecond\n'), 'syslog.1' + extension, lambda: False))
                self.assertEqual(rows, [(1,'first'),(2,'second')])
                with self.assertRaises((OSError, EOFError, lzma.LZMAError)):
                    list(text_lines(b'bad compressed data', 'syslog.1' + extension, lambda: False))

    def test_scan_export_preserves_new_sources_and_derived_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            fixtures = {'etc/sudoers':'test ALL=(ALL) NOPASSWD: /bin/test\n',
                        'etc/ld.so.preload':'/tmp/library.so\n',
                        'etc/apt/sources.list.d/test.sources':'Types: deb\nURIs: https://example.test\nSuites: stable\n',
                        'etc/systemd/system/test.timer.d/override.conf':'[Timer]\nOnCalendar=daily\n',
                        'var/spool/anacron/cron.daily':'20261010\n',
                        'home/test/.profile':'echo startup\n',
                        'var/log/anydesk.trace':'original session line\n',
                        'var/log/custom.log':'unrecognized format retained raw\n'}
            for name, data in fixtures.items():
                path = target / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(data)
            config = dict(collection_mode='all_supported', hashes=[], keywords=[], options=dict(
                file_names=False, folder_names=False, file_contents=False, hash_matches=False))
            targets = {'paths':[str(target)]}
            store = MemoryStore()
            summary = ScanEngine(targets, config, store).run()
            self.assertEqual(summary['parser_failures'], 0)
            self.assertEqual(summary['parsed_files'], 7)
            records, diagnostics, count = store.snapshot()
            output = root / 'export.zip'
            ZipExporter(records, diagnostics, count, dict(targets=targets, scan_summary=summary)).save(output)
            with zipfile.ZipFile(output) as archive:
                manifest = json.loads(archive.read('terra/manifest.json'))
                self.assertEqual(manifest['file_count'], len(fixtures))
                parsed_count = 0
                for item in manifest['entries']:
                    name = Path(item['source_path']).relative_to(target).as_posix()
                    self.assertEqual(archive.read(item['archive_path']), fixtures[name].encode())
                    parsed = item.get('parsed_artifact')
                    if parsed and parsed['status'] == 'parsed':
                        parsed_count += 1
                        self.assertIn(parsed['jsonl_path'], archive.namelist())
                        self.assertEqual(parsed['inputs'][0]['sha256'], item['sha256'])
                self.assertEqual(parsed_count, 7)

    def test_unavailable_journal_library_keeps_raw_and_file_hash_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'var/log/journal/id/system.journal'
            path.parent.mkdir(parents=True)
            data = b'LPKSHHRH' + bytes(504)
            path.write_bytes(data)
            digest = hashlib.md5(data).hexdigest()
            config = dict(collection_mode='matches_only', hashes=[digest], keywords=[], options=dict(
                file_names=False, folder_names=False, file_contents=False, hash_matches=True))
            store = MemoryStore()
            with patch('artifacts.os_activity.journal.library', side_effect=ParseError('Host library unavailable')):
                summary = ScanEngine({'paths':[directory]}, config, store).run()
            self.assertEqual(summary['hash_matches'], 1)
            self.assertEqual(summary['parser_failures'], 1)
            self.assertEqual(store.records[0]['data'], data)
            self.assertEqual(store.records[0]['parsed_artifact']['status'], 'failed')
            self.assertTrue(any('Host library unavailable' in entry['message'] for entry in store.diagnostics))


class FakeJournal:
    """Emulate public API lifetime, repeated fields and source-fallback behavior."""
    def __init__(self, fallback=False, fail_enumeration=False):
        self.opens = 0
        self.fd = None
        self.index = 0
        self.position = 0
        self.buffers = []
        self.closed = False
        self.fallback = fallback
        self.fail_enumeration = fail_enumeration

    def sd_journal_open_files_fd(self, result, fds, count, flags):
        self.opens += 1
        if self.fallback and self.opens == 1:
            return -errno.EIDRM
        self.fd = fds[0]
        result._obj.value = 1
        return 0

    def sd_journal_close(self, handle):
        self.closed = True
        os.close(self.fd)

    def sd_journal_set_data_threshold(self, handle, threshold):
        assert threshold == 0
        return 0

    def sd_journal_seek_head(self, handle):
        return 0

    def sd_journal_next(self, handle):
        self.index += 1
        return 1 if self.index == 1 else 0

    def sd_journal_restart_data(self, handle):
        self.position = 0

    def sd_journal_enumerate_data(self, handle, pointer, size):
        if self.fail_enumeration:
            return -errno.EBADMSG
        fields = [b'MESSAGE=usb 1-1: USB disconnect, device number 2', b'MESSAGE=second', b'BINARY=\xff\x00']
        if self.position == len(fields):
            return 0
        raw = fields[self.position]
        buffer = ctypes.create_string_buffer(raw)
        self.buffers.append(buffer)
        pointer._obj.value = ctypes.addressof(buffer)
        size._obj.value = len(raw)
        self.position += 1
        return 1

    def sd_journal_get_realtime_usec(self, handle, realtime):
        realtime._obj.value = 1700000000123456
        return 0


class JournalTests(unittest.TestCase):
    header = b'LPKSHHRH' + bytes(504)

    def test_complete_fields_binary_repeated_values_usb_event_and_close(self):
        lib = FakeJournal()
        with patch('artifacts.os_activity.journal.library', return_value=lib):
            rows = list(journal(self.header, lambda: False))
        self.assertTrue(lib.closed)
        self.assertEqual(rows[0]['type'], 'device_connection_event')
        self.assertEqual(len(rows[0]['fields']['MESSAGE']), 2)
        self.assertEqual(rows[0]['fields']['BINARY'][0]['value'], 'ff00')
        self.assertTrue(rows[0]['timestamp_utc'].endswith('.123456+00:00'))

    def test_readonly_fallback_rechecks_source_and_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.journal'
            path.write_bytes(self.header)
            data, metadata = read_verified(str(path))
            lib = FakeJournal(fallback=True)
            with patch('artifacts.os_activity.journal.library', return_value=lib):
                rows = list(journal(data, lambda: False, str(path), metadata))
            self.assertEqual(len(rows), 1)
            self.assertEqual(lib.opens, 2)
            self.assertTrue(lib.closed)
            lib = FakeJournal(fallback=True)
            original = lib.sd_journal_next
            def mutate(handle):
                result = original(handle)
                if result == 0:
                    path.write_bytes(self.header + b'changed')
                return result
            lib.sd_journal_next = mutate
            with patch('artifacts.os_activity.journal.library', return_value=lib):
                with self.assertRaises(ParseError):
                    list(journal(data, lambda: False, str(path), metadata))
            self.assertTrue(lib.closed)

    def test_library_errors_and_bad_header_remain_explicit(self):
        with self.assertRaises(ParseError):
            list(journal(b'bad', lambda: False))
        lib = FakeJournal(fail_enumeration=True)
        with patch('artifacts.os_activity.journal.library', return_value=lib):
            with self.assertRaises(ParseError):
                list(journal(self.header, lambda: False))
        self.assertTrue(lib.closed)

    def test_cancellation_closes_native_context(self):
        lib = FakeJournal()
        checks = 0
        def cancelled():
            nonlocal checks
            checks += 1
            return checks > 2
        with patch('artifacts.os_activity.journal.library', return_value=lib):
            with self.assertRaises(CollectionCancelled):
                list(journal(self.header, cancelled))
        self.assertTrue(lib.closed)
