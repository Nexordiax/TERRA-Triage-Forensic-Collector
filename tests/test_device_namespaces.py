import ctypes
import hashlib
import os
import struct
import tempfile
import unittest
import zipfile
import json
from pathlib import Path
from unittest.mock import patch
from PySide6.QtWidgets import QApplication

from analyzers.device_timeline import correlate, match_present_devices
from artifacts.device_history import annotate_history
from artifacts.devices import usb_event
from artifacts.file_collector import CollectionCancelled
from artifacts.live import LiveCollector
from artifacts.login_devices import (Id128, LoginDeviceCollector, SESSION_START, SESSION_STOP,
                                    journal_rows, kmsg_rows, regular_snapshot, session_state)
from controllers.scan_controller import ScanEngine
from controllers.export_controller import ZipExporter
from storage.memory_store import MemoryStore
from tests.test_scan import configuration

BOOT = '0123456789abcdef0123456789abcdef'


class NamespaceTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.proc = self.root / 'proc'
        self.proc.mkdir()
        self.logs = []
        self.collector = LiveCollector(self.proc, self.root / 'sys', diagnostic=lambda *row: self.logs.append(row))
        self.namespace('self', 'net', 'net:[1]')
        self.namespace('self', 'mnt', 'mnt:[1]')
        self.write('self/net/tcp', 'header\n0: 0100007F:0050 00000000:0000 0A 0:0 0:0 0 1000 0 42\n')
        self.write('self/mountinfo', '1 0 0:1 / / rw - tmpfs tmpfs rw\n')
        self.write('sys/kernel/random/boot_id', BOOT)

    def write(self, relative, text):
        path = self.proc / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def namespace(self, relative, kind, namespace):
        path = self.proc / relative / 'ns' / kind
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(namespace)

    def process(self, pid, net=2, mount=2, start=123):
        fields = ['S', '1', '0', str(pid)] + ['0'] * 15 + [str(start), '4096', '2']
        self.write(f'{pid}/stat', f'{pid} (test) ' + ' '.join(fields))
        self.namespace(str(pid), 'net', f'net:[{net}]')
        self.namespace(str(pid), 'mnt', f'mnt:[{mount}]')
        self.write(f'{pid}/net/tcp', 'header\n0: 0200007F:01BB 00000000:0000 0A 0:0 0:0 0 1001 0 42\n')
        self.write(f'{pid}/mountinfo', '2 0 0:2 / /container rw - tmpfs tmpfs rw\n')
        (self.proc / str(pid) / 'fd').mkdir()
        (self.proc / str(pid) / 'fd/3').symlink_to('socket:[42]')

    def test_distinct_namespaces_same_socket_inode_and_mount_id(self):
        self.process(99)
        self.process(100, net=3, mount=3)
        groups, provenance = self.collector.collect()
        sockets = {row['network_namespace']: row for row in groups['Network Connections'] if row['type'] == 'socket'}
        self.assertEqual(set(sockets), {'net:[1]', 'net:[2]', 'net:[3]'})
        self.assertEqual(sockets['net:[1]']['observed_owners'], [])
        self.assertEqual(sockets['net:[2]']['observed_owners'][0]['pid'], 99)
        self.assertEqual(sockets['net:[3]']['observed_owners'][0]['pid'], 100)
        mounts = [row for row in groups['Device Information'] if row['type'] == 'active_mount']
        self.assertEqual({row['mount_namespace'] for row in mounts}, {'mnt:[1]', 'mnt:[2]', 'mnt:[3]'})
        self.assertEqual(len(provenance['namespace_coverage']), 6)

    def test_shared_namespace_dedup_and_denied_representative_retry(self):
        self.process(99)
        self.process(100)
        original = self.collector.read
        def denied(name, directory_fd=None):
            if name == 'net/tcp' and os.readlink(f'/proc/self/fd/{directory_fd}').endswith('/99'):
                raise PermissionError('fixture denied')
            return original(name, directory_fd)
        with patch.object(self.collector, 'read', side_effect=denied):
            groups, provenance = self.collector.collect()
        rows = [row for row in groups['Network Connections'] if row.get('network_namespace') == 'net:[2]']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['representative_pid'], 100)
        self.assertEqual({owner['pid'] for owner in rows[0]['observed_owners']}, {99, 100})
        table = next(item for item in provenance['namespace_coverage'] if item['namespace'] == 'net:[2]')['tables']['tcp']
        self.assertEqual(table['status'], 'observed')
        self.assertEqual(len(table['failed_representatives']), 1)

    def test_namespace_change_during_table_read_discards_and_retries(self):
        self.process(99)
        self.process(100)
        original = self.collector.read
        def moved(name, directory_fd=None):
            value = original(name, directory_fd)
            if name == 'net/tcp' and os.readlink(f'/proc/self/fd/{directory_fd}').endswith('/99'):
                path = self.proc / '99/ns/net'
                path.unlink()
                path.symlink_to('net:[9]')
            return value
        with patch.object(self.collector, 'read', side_effect=moved):
            groups, provenance = self.collector.collect()
        rows = [row for row in groups['Network Connections'] if row.get('network_namespace') == 'net:[2]']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['representative_pid'], 100)
        self.assertTrue(any('membership changed' in row[1] for row in self.logs))

    def test_thread_only_namespace_discovered(self):
        self.process(99)
        fields = ['S', '1', '0', '99'] + ['0'] * 15 + ['456', '4096', '2']
        relative = '99/task/101'
        self.write(relative + '/stat', '101 (thread) ' + ' '.join(fields))
        self.namespace(relative, 'net', 'net:[8]')
        self.namespace(relative, 'mnt', 'mnt:[8]')
        self.write(relative + '/net/tcp', 'header\n0: 0100007F:0016 00000000:0000 0A 0:0 0:0 0 1001 0 55\n')
        self.write(relative + '/mountinfo', '8 0 0:8 / /thread rw - tmpfs tmpfs rw\n')
        groups, _ = self.collector.collect()
        row = next(row for row in groups['Network Connections'] if row.get('network_namespace') == 'net:[8]')
        self.assertEqual(row['representative_pid'], 99)
        self.assertEqual(row['representative_tid'], 101)
        self.assertEqual(row['observed_owners'], [])

    def test_unavailable_and_empty_tables_distinguished(self):
        self.process(99)
        self.write('99/net/tcp', 'header\n')
        _, provenance = self.collector.collect()
        tables = next(row for row in provenance['namespace_coverage'] if row['namespace'] == 'net:[2]')['tables']
        self.assertEqual(tables['tcp']['status'], 'observed')
        self.assertEqual(tables['tcp']['records'], 0)
        self.assertEqual(tables['udp']['status'], 'unavailable')

    def test_additional_interface_metadata(self):
        self.process(99)
        self.write('99/net/dev', 'header\nheader\neth0: ' + ' '.join(str(n) for n in range(16)) + '\n')
        self.write('99/net/if_inet6', '00000000000000000000000000000001 01 80 10 80 lo\n')
        groups, _ = self.collector.collect()
        row = next(row for row in groups['Network Connections'] if row['type'] == 'network_interface_counters')
        self.assertEqual(row['receive']['bytes'], 0)
        self.assertEqual(row['transmit']['bytes'], 8)
        row = next(row for row in groups['Network Connections'] if row['type'] == 'interface_ipv6_address')
        self.assertEqual(row['address'], '::1')


class DeviceTimelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def session(self, name='one', start=100, end=None, boot=BOOT, **values):
        return dict(session_id=name, username='examined', boot_id=boot, start_monotonic_usec=start,
                    start_realtime_usec=start * 1000000, end_monotonic_usec=end,
                    present_at_snapshot=end is None, locator='session:' + name, **values)

    def event(self, action='connect', monotonic=150, **values):
        return dict(type='device_connection_event', action=action, bus_path='1-1', boot_id=BOOT,
                    monotonic_usec=monotonic, locator=f'event:{monotonic}', **values)

    def test_monotonic_clock_overrides_backward_wallclock_and_normalizes_boot(self):
        event = self.event(timestamp_raw_usec=1)
        session = self.session(boot='01234567-89ab-cdef-0123-456789abcdef')
        row = correlate([event], [session])[0]
        self.assertTrue(row['since_recorded_login'])
        self.assertEqual(row['session_matches'][0]['ordering_basis'], 'same_boot_monotonic')

    def test_latest_login_uses_monotonic_when_wall_clock_moves_back(self):
        sessions = [self.session(name='before-clock-change', start=100),
                    dict(self.session(name='after-clock-change', start=140), start_realtime_usec=1)]
        row = correlate([self.event()], sessions)[0]
        self.assertEqual([match['latest_recorded_login_for_user'] for match in row['session_matches']], [False, True])

    def test_other_boot_prelogin_and_logout_excluded(self):
        events = [self.event(monotonic=90), self.event(monotonic=150), self.event(monotonic=200)]
        rows = correlate(events, [self.session(end=200), self.session(name='other', boot='f' * 32)])
        self.assertEqual([row['since_recorded_login'] for row in rows], [False, True, False])
        self.assertEqual(len(rows[1]['session_matches']), 1)

    def test_known_machine_id_mismatch_does_not_correlate(self):
        row = correlate([self.event(machine_id='a' * 32)], [self.session(machine_id='b' * 32)])[0]
        self.assertFalse(row['since_recorded_login'])

    def test_session_snapshot_changed_midread_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'session'
            path.write_bytes(b'UID=1\n')
            original = os.fstat
            count = 0
            def mutate(descriptor):
                nonlocal count
                count += 1
                if count == 2:
                    path.write_bytes(b'UID=22\n')
                return original(descriptor)
            with patch('artifacts.login_devices.os.fstat', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'changed during snapshot'):
                    regular_snapshot(path, lambda: False)

    def test_overlapping_users_latest_login_and_manager_exclusion(self):
        sessions = [self.session(name='old'), self.session(name='latest', start=140),
                    dict(self.session(name='second-user'), username='other'), self.session(name='manager', session_class='manager')]
        row = correlate([self.event()], sessions)[0]
        self.assertEqual(len(row['session_matches']), 3)
        self.assertEqual(set(row['since_latest_recorded_login_for_users']), {'examined', 'other'})
        self.assertFalse(row['session_matches'][0]['latest_recorded_login_for_user'])

    def test_naive_yearless_timestamp_not_inferred(self):
        events = [dict(type='device_connection_event', locator='log:1', timestamp_raw='Oct 10 12:00:00')]
        row = correlate(events, [self.session()])[0]
        self.assertFalse(row['since_recorded_login'])

    def test_port_reuse_requires_current_generation_and_matching_serial(self):
        device = dict(boot_id=BOOT, bus_path='1-1', idVendor='abcd', idProduct='1234', serial='new', devnum='3')
        events = [self.event(device_number=2), self.event('descriptor', 151, idVendor='abcd', idProduct='1234', serial='old'),
                  self.event('disconnect', 160), self.event(monotonic=170, device_number=3),
                  self.event('descriptor', 171, idVendor='abcd', idProduct='1234', serial='new')]
        correlated = correlate(events, [self.session()])
        result = match_present_devices([device], correlated)[0]
        self.assertEqual(result['observed_connection_event'], 'event:170')
        self.assertTrue(result['since_recorded_login'])
        self.assertNotIn('observed_connection_event', match_present_devices([dict(device, serial='old')], correlated)[0])
        self.assertNotIn('observed_connection_event', match_present_devices([dict(device, serial='')], correlated)[0])
        self.assertNotIn('observed_connection_event', match_present_devices([device], correlated + [self.event('disconnect', 180)])[0])

    def test_cancellation_preserved(self):
        with self.assertRaises(CollectionCancelled):
            correlate([self.event()], [self.session()], lambda: True)

    def test_session_state_private_format_and_source_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '1'
            data = b'UID=1000\nUSER=someone\nSTATE=online\nACTIVE=0\nREALTIME=1000000\nMONOTONIC=100\nCLASS=user\n'
            path.write_bytes(data)
            row = session_state(data, path, BOOT)
            self.assertTrue(row['present_at_snapshot'])
            self.assertFalse(row['active'])
            snapshot, source = regular_snapshot(path, lambda: False)
            self.assertEqual(source['sha256'], hashlib.sha256(data).hexdigest())
            (Path(folder) / 'link').symlink_to(path)
            with self.assertRaises(OSError):
                regular_snapshot(Path(folder) / 'link', lambda: False)
            (Path(folder) / 'parent').symlink_to(folder, target_is_directory=True)
            with self.assertRaises(OSError):
                regular_snapshot(Path(folder) / 'parent/1', lambda: False)
            with self.assertRaises(ValueError):
                session_state(b'UID=1\nUID=2\n', path, BOOT)
            self.assertEqual(path.read_bytes(), data)

    def test_live_sessions_journal_connection_export_provenance(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / 'run/systemd/sessions/1'
            path.parent.mkdir(parents=True)
            path.write_text('UID=1000\nUSER=examined\nSTATE=active\nREALTIME=100000000\nMONOTONIC=100\nCLASS=user\n')
            collector = LiveCollector(root / 'proc', root / 'sys')
            def rows(boot, cancelled, coverage):
                for n, message in enumerate(('new high-speed USB device number 3 using xhci_hcd',
                        'New USB device found, idVendor=abcd, idProduct=1234', 'SerialNumber: serial'), 150):
                    yield dict(fields={'_TRANSPORT': 'kernel', 'MESSAGE': 'usb 1-1: ' + message},
                               boot_id=boot, monotonic_usec=n, timestamp_raw_usec=n * 1000000,
                               timestamp_utc=None, locator=f'journal://{n}')
            device = dict(type='connected_usb_device', boot_id=BOOT, bus_path='1-1', serial='serial',
                          idVendor='abcd', idProduct='1234', devnum='3')
            sessions, devices, _ = LoginDeviceCollector(collector, journal_reader=rows).collect(BOOT, [device])
            self.assertEqual(len(sessions), 1)
            self.assertEqual(len(devices), 4)
            self.assertEqual(devices[0]['observed_connection_event'], 'journal://150')
            self.assertTrue(devices[0]['since_recorded_login'])

    def test_legacy_usb_action_and_identity_fields(self):
        self.assertEqual(usb_event('usb 1-1: USB disconnect, device number 2')['action'], 'disconnect')
        self.assertEqual(usb_event('usb 1-1: New USB device found, idVendor=abcd, idProduct=1234')['action'], 'descriptor')

    def test_kmsg_nonblocking_read_does_not_clear_and_ignores_injected_messages(self):
        observation = {}
        class DeviceInfo:
            st_mode = 0o020000
            st_rdev = os.makedev(1, 11)
        records = [b'6,1,100,-;usb 1-1: new high-speed USB device number 2 using xhci_hcd\n',
                   b'14,2,101,-;usb 1-1: USB disconnect, device number 2\n', BlockingIOError()]
        with patch('artifacts.login_devices.os.open', return_value=42) as opened, \
             patch('artifacts.login_devices.os.fstat', return_value=DeviceInfo()), \
             patch('artifacts.login_devices.os.read', side_effect=records), \
             patch('artifacts.login_devices.os.close') as closed:
            rows = list(kmsg_rows('/dev/kmsg', BOOT, lambda: False, observation))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['monotonic_usec'], 100)
        self.assertTrue(opened.call_args.args[1] & os.O_NONBLOCK)
        closed.assert_called_once_with(42)

    def test_offline_crossfile_wtmp_timezone_log_and_raw_preservation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'var/log').mkdir(parents=True)
            record = bytearray(384)
            struct.pack_into('<h', record, 0, 7)
            struct.pack_into('<i', record, 4, 123)
            record[8:13] = b'pts/1'
            record[44:52] = b'examined'
            struct.pack_into('<ii', record, 340, 100, 0)
            (root / 'var/log/wtmp').write_bytes(record)
            text = '1970-01-01T00:02:30+00:00 host kernel: usb 1-1: USB disconnect, device number 2\n'
            (root / 'var/log/kern.log').write_text(text)
            store = MemoryStore()
            summary = ScanEngine({'paths': [str(root)]}, configuration(), store).run()
            self.assertEqual(summary['status'], 'completed')
            log = next(row for row in store.records if row['path'].endswith('kern.log'))
            event = log['parsed_artifact']['entries'][0]
            self.assertTrue(event['since_recorded_login'])
            self.assertEqual(event['source_scope'], 'acquired_target_logs')
            self.assertEqual(event['session_matches'][0]['relation'], 'after_login_end_unknown')
            self.assertEqual(log['sha256'], hashlib.sha256(text.encode()).hexdigest())
            self.assertEqual(log['data'], text.encode())
            destination = tempfile.TemporaryDirectory()
            self.addCleanup(destination.cleanup)
            output = Path(destination.name) / 'output.zip'
            records, diagnostics, count = store.snapshot()
            ZipExporter(records, diagnostics, count, {'targets': {'paths': [str(root)]}}).save(output)
            with zipfile.ZipFile(output) as archive:
                analyses = [name for name in archive.namelist() if name.endswith('/records.jsonl')]
                exported = [json.loads(line) for name in analyses for line in archive.read(name).splitlines()]
                device_event = next(row for row in exported if row['type'] == 'device_connection_event')
                self.assertTrue(device_event['since_recorded_login'])
                self.assertEqual(device_event['session_matches'][0]['ordering_basis'], 'realtime_only_clock_changes_possible')
            # Other filesystem roots never borrow a session from this target.
            other = dict(log, id=99, path='/other/var/log/kern.log')
            updates = annotate_history([store.records[0], store.records[1], other])
            self.assertFalse(updates[99]['entries'][0]['since_recorded_login'])


class FakeLiveJournal:
    def __init__(self):
        self.filters = []
        self.group = -1
        self.index = -1
        self.buffers = []
        self.closed = 0
        self.kernel = [{'_TRANSPORT': 'kernel', 'MESSAGE': 'usb 1-1: USB disconnect, device number 2',
                        '_SOURCE_MONOTONIC_TIMESTAMP': '120'}]
        self.sessions = [{'MESSAGE_ID': SESSION_START, 'SESSION_ID': '1', 'USER_ID': 'examined'},
                         {'MESSAGE_ID': SESSION_STOP, 'SESSION_ID': '1', 'USER_ID': 'examined'}]

    def sd_journal_open(self, pointer, flags):
        self.group += 1
        self.index = -1
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(1)
        return 0

    def sd_journal_close(self, pointer):
        self.closed += 1

    def sd_journal_add_match(self, pointer, raw, size):
        self.filters.append(ctypes.string_at(raw, size).decode())
        return 0

    def sd_journal_set_data_threshold(self, *args):
        return 0

    def sd_journal_seek_head(self, *args):
        return 0

    def sd_journal_next(self, *args):
        self.index += 1
        return int(self.index < len(self.kernel if self.group == 0 else self.sessions))

    def sd_journal_get_data(self, pointer, field, value, size):
        row = (self.kernel if self.group == 0 else self.sessions)[self.index]
        name = field.decode()
        if name not in row:
            return -2
        raw = field + b'=' + row[name].encode()
        buffer = ctypes.create_string_buffer(raw)
        self.buffers.append(buffer)
        ctypes.cast(value, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(buffer)
        ctypes.cast(size, ctypes.POINTER(ctypes.c_size_t))[0] = len(raw)
        return 0

    def sd_journal_get_realtime_usec(self, pointer, value):
        ctypes.cast(value, ctypes.POINTER(ctypes.c_uint64))[0] = 1000000 + self.index
        return 0

    def sd_journal_get_monotonic_usec(self, pointer, value, boot):
        ctypes.cast(value, ctypes.POINTER(ctypes.c_uint64))[0] = 150 + self.index
        observed = ctypes.cast(boot, ctypes.POINTER(Id128)).contents
        observed.bytes[:] = bytes.fromhex(BOOT)
        return 0


class LiveJournalTests(unittest.TestCase):
    def test_boot_filters_session_ids_source_clock_and_closed_handles(self):
        lib = FakeLiveJournal()
        coverage = []
        with patch('artifacts.login_devices.journal_library', return_value=lib):
            rows = list(journal_rows(BOOT, lambda: False, coverage))
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]['monotonic_usec'], 120)
        self.assertEqual(rows[0]['journal_receipt_monotonic_usec'], 150)
        self.assertEqual(rows[0]['event_clock'], 'kernel_source_monotonic')
        self.assertEqual(lib.filters.count('_BOOT_ID=' + BOOT), 2)
        self.assertIn('MESSAGE_ID=' + SESSION_START, lib.filters)
        self.assertIn('MESSAGE_ID=' + SESSION_STOP, lib.filters)
        self.assertIn('_SYSTEMD_UNIT=systemd-logind.service', lib.filters)
        self.assertEqual(lib.closed, 2)

    def test_journal_budget_and_cancellation_are_explicit(self):
        lib = FakeLiveJournal()
        coverage = []
        with patch('artifacts.login_devices.journal_library', return_value=lib):
            rows = list(journal_rows(BOOT, lambda: False, coverage, max_records=1))
        self.assertEqual(len(rows), 1)
        self.assertEqual(coverage[-1]['status'], 'partial')
        lib = FakeLiveJournal()
        with patch('artifacts.login_devices.journal_library', return_value=lib):
            with self.assertRaises(CollectionCancelled):
                list(journal_rows(BOOT, lambda: True, []))
        self.assertEqual(lib.closed, 1)


if __name__ == '__main__':
    unittest.main()
