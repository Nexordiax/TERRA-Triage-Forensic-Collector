import json
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from PySide6.QtWidgets import QApplication

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from artifacts.live import LiveCollector, endpoint, process_stat
from artifacts.encrypted import detect
from artifacts.file_collector import CollectionCancelled, FileCollector
from controllers.scan_controller import ScanEngine
from controllers.export_controller import ZipExporter
from storage.memory_store import MemoryStore, MemoryLimitError
from tests.test_scan import configuration
from interface.pages.targets import TargetsPage


class LiveCollectorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.proc = self.root / 'proc'
        self.sysfs = self.root / 'sys'
        self.proc.mkdir()
        self.sysfs.mkdir()
        self.logs = []

    def file(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return path

    def fixture(self):
        fields = ['S', '1', '0', '99'] + ['0'] * 15 + ['12345', '4096', '2']
        self.file('proc/99/stat', '99 (name with ) brackets) ' + ' '.join(fields))
        self.file('proc/99/status', 'Uid:\t1000\t1000\t1000\t1000\n')
        self.file('proc/99/cmdline', b'/usr/bin/test\0--arg\0')
        os.symlink('/usr/bin/test', self.proc / '99/exe')
        os.symlink('/home/test', self.proc / '99/cwd')
        (self.proc / '99/fd').mkdir()
        os.symlink('socket:[42]', self.proc / '99/fd/3')
        os.symlink('/file (deleted)', self.proc / '99/fd/4')
        for folder in ('99/ns', 'self/ns'):
            (self.proc / folder).mkdir(parents=True, exist_ok=True)
            os.symlink('net:[1]', self.proc / folder / 'net')
        self.file('proc/self/net/tcp', 'header\n0: 0100007F:01BB 00000000:0000 0A 0:0 0:0 0 1000 0 42\n')
        self.file('proc/self/net/unix', 'header\n0: 2 0 00010000 0001 01 42 /a socket\n')
        for protocol in ('tcp6', 'udp', 'udp6'):
            self.file('proc/self/net/' + protocol, 'header\n')
        self.file('proc/sys/kernel/random/boot_id', 'fixture-boot')
        self.file('sys/bus/usb/devices/1-1/idVendor', 'abcd\n')
        self.file('sys/bus/usb/devices/1-1/idProduct', '1234\n')
        self.file('sys/bus/usb/devices/1-1/serial', 'serial\n')

    def collector(self, cancelled=lambda: False):
        return LiveCollector(self.proc, self.sysfs, cancelled,
                             lambda path, message, level: self.logs.append((path, message)))

    def test_process_handles_network_and_usb(self):
        self.fixture()
        groups, provenance = self.collector().collect()
        process = groups['Running Processes'][0]
        self.assertEqual(process['name'], 'name with ) brackets')
        self.assertEqual(process['start_ticks'], 12345)
        self.assertEqual(process['cmdline'], ['/usr/bin/test', '--arg'])
        self.assertEqual(len(groups['Open File Handles']), 2)
        tcp = groups['Network Connections'][0]
        self.assertEqual(tcp['local'], {'address': '127.0.0.1', 'port': 443})
        self.assertEqual(tcp['state'], 'LISTEN')
        self.assertEqual(tcp['observed_owners'][0]['pid'], 99)
        self.assertEqual(groups['Network Connections'][1]['address'], '/a socket')
        self.assertEqual(groups['Connected Devices'][0]['serial'], 'serial')
        self.assertEqual(provenance['scope'], 'live_host')
        self.assertEqual(provenance['boot_id'], 'fixture-boot')

    def test_namespace_owner_not_misattributed(self):
        self.fixture()
        namespace = self.proc / '99/ns/net'
        namespace.unlink()
        namespace.symlink_to('net:[2]')
        groups, _ = self.collector().collect()
        self.assertEqual(groups['Network Connections'][0]['observed_owners'], [])

    def test_malformed_process_logged_and_not_collected(self):
        self.file('proc/1/stat', 'broken')
        groups, _ = self.collector().collect()
        self.assertEqual(groups['Running Processes'], [])
        self.assertTrue(self.logs)

    def test_cancelled(self):
        self.fixture()
        with self.assertRaises(CollectionCancelled):
            self.collector(lambda: True).collect()

    def test_ipv6_native_words(self):
        self.assertEqual(endpoint('00000000000000000000000001000000:0050', True),
                         {'address': '::1', 'port': 80})

    def test_generated_snapshot_cannot_be_silently_discarded(self):
        with self.assertRaises(MemoryLimitError):
            MemoryStore(max_bytes=0).add({'generated_snapshot': True}, b'evidence')

    def test_live_export_and_matches_only(self):
        self.fixture()
        groups, provenance = self.collector().collect()
        target = self.root / 'target'
        target.mkdir()
        targets = {'paths': [str(target)], 'collect_live': True}
        config = configuration('matches_only', keywords=['serial'], file_contents=True)
        store = MemoryStore()
        with patch('controllers.scan_controller.LiveCollector') as collector:
            collector.return_value.collect.return_value = groups, provenance
            summary = ScanEngine(targets, config, store).run()
        self.assertEqual(summary['status'], 'completed')
        records, diagnostics, count = store.snapshot()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['category'], 'Connected Devices')
        self.assertEqual(records[0]['matches'], {'file_contents': ['serial']})
        self.assertEqual(summary['hash_checked'], 0)
        output = self.root / 'export.zip'
        ZipExporter(records, diagnostics, count, {'targets': targets}).save(output)
        with zipfile.ZipFile(output) as archive:
            self.assertIn('terra/live/connected-devices.json', archive.namelist())
            snapshot = json.loads(archive.read('terra/live/connected-devices.json'))
            self.assertEqual(snapshot['provenance']['scope'], 'live_host')
            metadata = json.loads(archive.read('terra/analysis/artifact-000000/metadata.json'))
            self.assertEqual(metadata['source_scope'], 'live_host')

    def test_offline_scan_does_not_collect_live_host(self):
        with patch('controllers.scan_controller.LiveCollector') as collector:
            ScanEngine({'paths': [str(self.root)]}, configuration(), MemoryStore()).run()
            collector.assert_not_called()

    def test_target_gui_clears_live_collection_for_custom_targets(self):
        page = TargetsPage()
        self.addCleanup(page.close)
        self.assertTrue(page.entire_system.isChecked())
        self.assertFalse(hasattr(page, 'collect_live'))
        page.entire_system.setChecked(False)
        page.folders.addItem(str(self.root))
        selections = []
        page.next_requested.connect(selections.append)
        page.submit()
        self.assertFalse(selections[0]['collect_live'])
        self.assertFalse(selections[0]['acquire_ram'])
        from PySide6.QtWidgets import QListWidgetItem
        from PySide6.QtCore import Qt
        page.volumes.clear()
        volume = QListWidgetItem(str(self.root))
        volume.setData(Qt.ItemDataRole.UserRole, str(self.root))
        page.volumes.addItem(volume)
        page.entire_system.setChecked(True)
        page.submit()
        self.assertTrue(selections[1]['collect_live'])

    def test_header_detection_ignores_extension_and_cache_limit(self):
        header = bytes.fromhex('03d9a29a67fb4bb5') + struct.pack('<I', 0x00040001)
        self.file('container.bin', header + b'payload')
        store = MemoryStore(max_bytes=0)
        summary = ScanEngine({'paths': [str(self.root)]}, configuration(), store,
                             collector=FileCollector()).run()
        self.assertEqual(summary['parsed_records'], 1)
        record = store.records[0]
        self.assertEqual(record['category'], 'Encrypted Containers')
        self.assertEqual(record['parsed_artifact']['entries'][0]['format'], 'KeePass KDBX')
        self.assertFalse(record['content_retained'])
        self.assertIsNone(detect(b'LUKS\xba\xbe\0\1'))
        self.assertIsNone(detect(b'random data'))

    def test_luks_versions(self):
        first = bytearray(592)
        first[:8] = b'LUKS\xba\xbe\0\1'
        self.assertEqual(detect(first)['format'], 'LUKS1')
        second = bytearray(4096)
        second[:8] = b'LUKS\xba\xbe\0\2'
        struct.pack_into('>Q', second, 8, 16384)
        self.assertEqual(detect(second)['format'], 'LUKS2')
        struct.pack_into('>Q', second, 8, 12345)
        self.assertIsNone(detect(second))

    def test_persisted_device_history_and_bluetooth(self):
        self.file('var/log/kern.log', 'Oct 10 12:00:00 host kernel: usb 1-1: USB disconnect, device number 2\n')
        self.file('var/lib/bluetooth/AA:BB:CC:DD:EE:FF/11:22:33:44:55:66/info', '[General]\nName=Phone\nTrusted=true\n')
        store = MemoryStore()
        summary = ScanEngine({'paths': [str(self.root)]}, configuration(), store).run()
        self.assertEqual(summary['parsed_records'], 2)
        log = next(record for record in store.records if record['path'].endswith('kern.log'))
        self.assertEqual(log['additional_categories'], ['Connected Devices'])
        self.assertEqual(log['parsed_artifact']['entries'][0]['type'], 'device_connection_event')
        bluez = next(record for record in store.records if record['path'].endswith('/info'))
        self.assertEqual(bluez['parsed_artifact']['entries'][0]['fields']['Name'], 'Phone')

    def test_kernel_network_tables_mappings_and_environments(self):
        self.fixture()
        self.file('proc/99/environ', b'LD_PRELOAD=/tmp/library.so\0X=one=two\0')
        self.file('proc/99/maps', '1000-2000 r-xp 0000 08:01 42 /tmp/mapped file (deleted)\n')
        os.symlink('/', self.proc / '99/root')
        self.file('proc/modules', 'test_module 4096 2 user_one,user_two, Live 0x00000000\ninvalid\n')
        self.file('proc/self/mountinfo', '36 35 8:1 / /mnt/a\\040b rw,noatime shared:1 - ext4 /dev/sda1 rw\n')
        self.file('proc/partitions', 'major minor #blocks name\n\n8 1 2048 sda1\n')
        self.file('proc/self/net/arp', 'IP address HW type Flags HW address Mask Device\n192.0.2.2 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n')
        self.file('proc/self/net/route', 'header\neth0 00000000 010200C0 0003 0 0 100 00000000 0 0 0\n')
        self.file('proc/self/net/ipv6_route', '00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000001 00000010 00000000 00000000 00000003 eth0\n')
        groups, provenance = self.collector().collect()
        self.assertEqual(groups['Running Processes'][0]['environ'], ['LD_PRELOAD=/tmp/library.so', 'X=one=two'])
        mapping = groups['Process Mappings'][0]
        self.assertEqual(mapping['mapped_path'], '/tmp/mapped file (deleted)')
        self.assertEqual(mapping['size_bytes'], 4096)
        self.assertEqual(mapping['process_start_ticks'], 12345)
        self.assertEqual(groups['Kernel Modules'][0]['used_by'], ['user_one', 'user_two'])
        mounts = groups['Device Information']
        self.assertEqual(mounts[0]['mountpoint'], '/mnt/a b')
        self.assertEqual(mounts[1]['blocks_1024'], 2048)
        routes = {row['type']: row for row in groups['Network Connections']}
        self.assertEqual(routes['ipv4_route']['gateway'], '192.0.2.1')
        self.assertEqual(routes['ipv6_route']['gateway'], '::1')
        self.assertEqual(routes['arp_neighbor']['network_namespace'], provenance['network_namespace'])
        self.assertTrue(any('modules:2' in path for path, _ in self.logs))

    def test_unstable_process_discards_mappings_and_handles(self):
        self.fixture()
        collector = self.collector()
        original = collector.read
        calls = 0
        def changed(name, directory_fd=None):
            nonlocal calls
            value = original(name, directory_fd)
            if name == 'stat':
                calls += 1
                if calls == 2:
                    value = value.replace('12345', '99999')
            return value
        with patch.object(collector, 'read', side_effect=changed):
            groups, _ = collector.collect()
        self.assertEqual(groups['Running Processes'], [])
        self.assertEqual(groups['Open File Handles'], [])
        self.assertEqual(groups['Process Mappings'], [])
