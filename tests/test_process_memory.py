import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

from artifacts.memory.collector import MemoryCancelled
from artifacts.memory.process_collector import ProcessMemoryCollector, ProcessMemoryUnavailable
from controllers.export_controller import ZipExporter
from interface.pages.ram import RamPage
from tests.test_ram import APP


class ProcessMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.proc = self.root / 'proc'
        self.proc.mkdir()
        self.destination = self.root / 'partial.zip'
        self.pid = 123456 if os.getpid() != 123456 else 123457

    def process(self, pid=None, readable=True):
        directory = self.proc / str(pid or self.pid)
        directory.mkdir()
        directory.joinpath('stat').write_text(f'{pid or self.pid} (test process) ' + ' '.join(['S'] + ['0'] * 18 + ['12345']))
        directory.joinpath('maps').write_text('00001000-00001008 r--p 00000000 00:00 0 [test]\n00002000-00002008 ---p 00000000 00:00 0 [unreadable]\n')
        if readable:
            with open(directory / 'mem', 'wb') as output:
                output.seek(0x1000)
                output.write(b'EVIDENCE')
        return directory

    def collector(self, cancel=None, progress=None):
        return ProcessMemoryCollector(cancel, progress, self.proc)

    def test_partial_capture_raw_bytes_metadata_and_hashes(self):
        self.process()
        self.process(self.pid + 1, readable=False)
        result = self.collector().acquire(self.destination)
        self.assertEqual(result['category'], 'Process Memory (Partial)')
        self.assertFalse(result['complete_physical_ram'])
        self.assertEqual(result['captured_bytes'], 8)
        self.assertEqual(result['process_count'], 1)
        self.assertEqual(result['skipped_processes'], 1)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result['sha256'], hashlib.sha256(self.destination.read_bytes()).hexdigest())
        with zipfile.ZipFile(self.destination) as archive:
            manifest = json.loads(archive.read('manifest.json'))
            region = manifest['processes'][0]['regions'][0]
            self.assertEqual(archive.read(region['archive_path']), b'EVIDENCE')
            self.assertEqual(region['segments'], [{'virtual_start': 4096, 'file_offset': 0, 'length': 8}])
            self.assertEqual(region['sha256'], hashlib.sha256(b'EVIDENCE').hexdigest())
            self.assertTrue(region['complete'])
            self.assertTrue(manifest['diagnostics'])
            self.assertFalse(manifest['complete_physical_ram'])
            self.assertEqual(manifest['byte_count_scope'], 'sum_of_copied_process_virtual_memory_bytes_not_unique_physical_ram')
            self.assertIn('exceed installed RAM', manifest['limitations'])

    def test_progress_labels_virtual_bytes_without_clipping_to_physical_capacity(self):
        page = RamPage()
        page.partial = True
        page.update_progress({'phase': 'Acquiring accessible process memory', 'bytes': 10120 * 1048576, 'total': 0})
        self.assertIn('10120.0', page.status.text())
        self.assertIn('virtual-memory', page.status.text())
        self.assertIn('not physical RAM size', page.status.text())
        page.partial = False
        page.update_progress({'phase': 'Acquiring physical RAM', 'bytes': 4096 * 1048576, 'total': 8192 * 1048576})
        self.assertNotIn('virtual-memory', page.status.text())
        self.assertEqual(page.progress.value(), 500)

    def test_accessible_context_and_region_times(self):
        directory = self.process()
        binary = self.root / 'test executable'
        binary.write_bytes(b'not executed')
        (directory / 'exe').symlink_to(binary)
        (directory / 'cmdline').write_bytes(b'/opt/test\0--message\0two words\0\xff\0')
        (self.proc / 'stat').write_text('btime 1700000000\n')
        with patch('artifacts.memory.process_context.os.sysconf', return_value=100):
            self.collector().acquire(self.destination)
        with zipfile.ZipFile(self.destination) as archive:
            manifest = json.loads(archive.read('manifest.json'))
        process = manifest['processes'][0]
        self.assertEqual(manifest['format_version'], 2)
        self.assertEqual(process['executable']['inode'], binary.stat().st_ino)
        self.assertEqual(process['executable']['path'], str(binary))
        self.assertEqual(process['command_line']['argv'][2], 'two words')
        self.assertEqual(bytes.fromhex(process['command_line']['raw_hex']), (directory / 'cmdline').read_bytes())
        self.assertEqual(process['start_time']['utc'], '2023-11-14T22:15:23.450000+00:00')
        self.assertEqual(process['mappings'][1]['capture_status'], 'not_readable')
        region = process['regions'][0]
        self.assertLessEqual(region['acquired_at'], region['completed_at'])
        self.assertGreaterEqual(region['duration_ns'], 0)
        self.assertFalse(process['command_line_changed_during_capture'])

    def test_denied_memory_keeps_accessible_context(self):
        self.process()
        denied = self.process(self.pid + 1)
        (denied / 'cmdline').write_bytes(b'denied-process\0')
        denied_inode = denied.stat().st_ino
        original_open = os.open
        def open_file(path, flags, *args, **kwargs):
            if path == 'mem' and os.fstat(kwargs['dir_fd']).st_ino == denied_inode:
                raise PermissionError(13, 'Permission denied')
            return original_open(path, flags, *args, **kwargs)
        with patch('artifacts.memory.process_collector.os.open', side_effect=open_file):
            result = self.collector().acquire(self.destination)
        self.assertEqual(result['process_count'], 1)
        with zipfile.ZipFile(self.destination) as archive:
            manifest = json.loads(archive.read('manifest.json'))
            record = manifest['unavailable_processes'][0]
            self.assertFalse(any(name.startswith(f'processes/{self.pid + 1}/') for name in archive.namelist()))
        self.assertEqual(record['access_status'], 'denied')
        self.assertEqual(record['access_errno'], 13)
        self.assertEqual(record['command_line']['argv'], ['denied-process'])
        self.assertEqual(record['failed_operation'], 'open_process_memory')

    def test_changes_during_capture_are_recorded(self):
        directory = self.process()
        (directory / 'cmdline').write_bytes(b'before\0')
        def progress(value):
            if value['bytes']:
                (directory / 'cmdline').write_bytes(b'after\0')
                with (directory / 'maps').open('a') as output:
                    output.write('00003000-00003008 ---p 00000000 00:00 0 [new]\n')
        self.collector(progress=progress).acquire(self.destination)
        with zipfile.ZipFile(self.destination) as archive:
            process = json.loads(archive.read('manifest.json'))['processes'][0]
        self.assertTrue(process['maps_changed_during_capture'])
        self.assertTrue(process['command_line_changed_during_capture'])
        self.assertEqual(len(process['mapping_changes']['added']), 1)
        self.assertIsNone(process['executable_changed_during_capture'])

    def test_optional_context_denied_preserves_memory(self):
        self.process()
        from artifacts.memory.process_context import read_bytes
        def read_context(directory, name, limit):
            if name == 'cmdline':
                raise PermissionError(13, 'Permission denied')
            return read_bytes(directory, name, limit)
        with patch('artifacts.memory.process_context.read_bytes', side_effect=read_context):
            result = self.collector().acquire(self.destination)
        self.assertEqual(result['captured_bytes'], 8)
        with zipfile.ZipFile(self.destination) as archive:
            process = json.loads(archive.read('manifest.json'))['processes'][0]
        self.assertEqual(process['command_line']['errno'], 13)
        self.assertEqual(process['command_line']['status'], 'unavailable')
        self.assertIsNone(process['command_line_changed_during_capture'])

    def test_unavailable_map_recheck_is_unknown(self):
        self.process()
        collector = self.collector()
        original = collector.read_text
        map_reads = 0
        def read_context(directory, name):
            nonlocal map_reads
            if name == 'maps':
                map_reads += 1
                if map_reads == 2:
                    raise PermissionError(13, 'Permission denied')
            return original(directory, name)
        with patch.object(collector, 'read_text', side_effect=read_context):
            collector.acquire(self.destination)
        with zipfile.ZipFile(self.destination) as archive:
            process = json.loads(archive.read('manifest.json'))['processes'][0]
        self.assertIsNone(process['maps_changed_during_capture'])
        self.assertEqual(process['maps_check_status'], 'unavailable')

    def test_no_access_reports_failure_and_removes_output(self):
        self.process(readable=False)
        with self.assertRaises(ProcessMemoryUnavailable) as result:
            self.collector().acquire(self.destination)
        self.assertTrue(result.exception.diagnostics)
        self.assertFalse(self.destination.exists())
        self.assertFalse(list(self.root.glob('.terra-process-*')))

    def test_page_failure_keeps_later_readable_segments(self):
        directory = self.process()
        directory.joinpath('maps').write_text('00001000-00004000 r--p 00000000 00:00 0 [test]\n')
        original = os.pread
        def read(fd, count, address):
            if address == 0x1000:
                raise OSError('page inaccessible')
            return b'X' * count
        with patch('artifacts.memory.process_collector.os.pread', side_effect=read):
            result = self.collector().acquire(self.destination)
        self.assertEqual(result['captured_bytes'], 8192)
        with zipfile.ZipFile(self.destination) as archive:
            region = json.loads(archive.read('manifest.json'))['processes'][0]['regions'][0]
            self.assertEqual(region['segments'][0]['virtual_start'], 0x2000)
            self.assertEqual(region['unreadable_bytes'], 4096)
            self.assertEqual(region['gaps'][0]['virtual_start'], 0x1000)
            self.assertEqual(region['gaps'][0]['length'], 4096)
            self.assertFalse(region['complete'])

    def test_live_process_exit_preserves_acquired_bytes_with_warning(self):
        self.process()
        collector = self.collector()
        with patch.object(collector, 'identity', side_effect=['12345', FileNotFoundError('process exited')]):
            result = collector.acquire(self.destination)
        self.assertEqual(result['captured_bytes'], 8)
        with zipfile.ZipFile(self.destination) as archive:
            process = json.loads(archive.read('manifest.json'))['processes'][0]
            self.assertFalse(process['identity_verified_after_capture'])

    def test_cancel_removes_output(self):
        self.process()
        cancel = Event()
        def progress(value):
            cancel.set()
        with self.assertRaises(MemoryCancelled):
            self.collector(cancel, progress).acquire(self.destination)
        self.assertFalse(self.destination.exists())

    def test_existing_output_is_preserved(self):
        self.destination.write_bytes(b'existing')
        with self.assertRaises(FileExistsError):
            self.collector().acquire(self.destination)
        self.assertEqual(self.destination.read_bytes(), b'existing')

    def test_stop_mid_region_finalizes_zip_and_address_metadata(self):
        directory = self.process()
        directory.joinpath('maps').write_text('00001000-00201000 r--p 00000000 00:00 0 [test]\n')
        cancel = Event()
        def progress(value):
            if value['phase'].startswith('Acquiring accessible process memory'):
                cancel.set()
        with patch('artifacts.memory.process_collector.os.pread', side_effect=lambda fd,length,address: b'X' * length):
            result = self.collector(cancel, progress).acquire(self.destination)
        self.assertTrue(result['acquisition_stopped'])
        self.assertEqual(result['captured_bytes'], 1024 * 1024)
        with zipfile.ZipFile(self.destination) as archive:
            self.assertIsNone(archive.testzip())
            manifest = json.loads(archive.read('manifest.json'))
            region = manifest['processes'][0]['regions'][0]
            self.assertTrue(manifest['acquisition_stopped'])
            self.assertFalse(region['complete'])
            self.assertEqual(region['not_attempted_bytes'], 1024 * 1024)
            self.assertEqual(region['not_attempted_ranges'][0]['virtual_start'], 0x101000)
            self.assertEqual(hashlib.sha256(archive.read(region['archive_path'])).hexdigest(), region['sha256'])

    def test_write_failure_is_not_treated_as_process_access_failure(self):
        self.process()
        with patch('zipfile._ZipWriteFile.write', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.collector().acquire(self.destination)
        self.assertFalse(self.destination.exists())

    def test_do_not_label_partial_capture_as_lime(self):
        with self.assertRaises(ValueError):
            self.collector().acquire(self.root / 'partial.lime')

    def test_partial_export_preserves_scope_and_bytes(self):
        self.process()
        record = self.collector().acquire(self.destination)
        record['data'] = b''
        target = self.root / 'target'
        target.mkdir()
        output = self.root / 'export.zip'
        ZipExporter([record], [], 0, {'targets': {'paths': [str(target)]}}).save(output)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read('terra/memory/partial.zip'), self.destination.read_bytes())
            entry = json.loads(archive.read('terra/manifest.json'))['entries'][0]
            self.assertFalse(entry['complete_physical_ram'])
            self.assertEqual(entry['memory_scope'], 'accessible_process_memory')

    def test_same_page_automatically_selects_destination_format(self):
        page = RamPage()
        with patch('interface.pages.ram.os.geteuid', return_value=1000):
            page.prepare({'paths': []}, None)
        self.assertTrue(page.partial)
        self.assertTrue(page.default_name.endswith('.zip'))
        self.assertIn('Partial', page.status.text())
        with patch('interface.pages.ram.os.geteuid', return_value=0):
            page.prepare({'paths': []}, None)
        self.assertFalse(page.partial)
        self.assertTrue(page.default_name.endswith('-RAM.zip'))
