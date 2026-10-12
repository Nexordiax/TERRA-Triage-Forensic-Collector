import hashlib
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

from PySide6.QtWidgets import QApplication
from artifacts.memory.collector import MemoryCollector, MemoryCancelled, validate_lime, BACKEND, BACKEND_SHA256
from controllers.export_controller import ZipExporter
from interface.main_window import MainWindow


APP = QApplication.instance() or QApplication([])


def lime(start=4096, data=b'test memory contents'):
    return struct.pack('<IIQQQ', 0x4C694D45, 1, start, start + len(data) - 1, 0) + data


class RamTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.payload = lime()
        self.expected = [(4096, 4096 + len(b'test memory contents') - 1)]

    def tearDown(self):
        self.temporary.cleanup()

    def backend(self, payload=None, failure=False, slow=False):
        script = self.root / 'fake-avml'
        body = '#!/usr/bin/env python3\nimport sys, time\nfrom pathlib import Path\n'
        if slow:
            body += 'time.sleep(30)\n'
        if failure:
            body += 'sys.stderr.write("memory access denied")\nsys.exit(1)\n'
        else:
            body += f'Path(sys.argv[-1]).write_bytes({self.payload if payload is None else payload!r})\n'
        script.write_text(body)
        script.chmod(0o700)
        return script

    def acquire(self, backend, cancel=None, progress=None, filename='memory.lime'):
        with patch('artifacts.memory.collector.BACKEND', backend), \
             patch('artifacts.memory.collector.BACKEND_SHA256', hashlib.sha256(backend.read_bytes()).hexdigest()), \
             patch('artifacts.memory.collector.os.geteuid', return_value=0), \
             patch('artifacts.memory.collector.physical_ranges', return_value=self.expected):
            return MemoryCollector(cancel, progress).acquire(self.root / filename)

    def test_full_and_stopped_physical_ram_zip(self):
        import json
        for stopped in (False, True):
            cancel = Event()
            def progress(value):
                if stopped and value['phase'] == 'Verifying RAM image':
                    cancel.set()
            name = 'stopped-RAM.zip' if stopped else 'full-RAM.zip'
            result = self.acquire(self.backend(), cancel, progress, name)
            with zipfile.ZipFile(result['path']) as archive:
                self.assertEqual(archive.read(Path(name).stem + '.lime'), self.payload)
                metadata = json.loads(archive.read('acquisition.json'))
                self.assertEqual(metadata['complete_physical_ram'], not stopped)
                self.assertEqual(metadata['sha256'], hashlib.sha256(self.payload).hexdigest())
                self.assertIn('backend.log', archive.namelist())
                if stopped:
                    self.assertIn('stopped-RAM.lime.json', archive.namelist())
                self.assertIsNone(archive.testzip())
            self.assertEqual(result['sha256'], hashlib.sha256(Path(result['path']).read_bytes()).hexdigest())
            self.assertEqual(result['image_sha256'], hashlib.sha256(self.payload).hexdigest())
            self.assertFalse(list(self.root.glob('.terra-ram-*')))

    def test_ram_zip_does_not_overwrite(self):
        destination = self.root / 'memory.zip'
        destination.write_bytes(b'previous evidence')
        with self.assertRaises(FileExistsError):
            self.acquire(self.backend(), filename='memory.zip')
        self.assertEqual(destination.read_bytes(), b'previous evidence')

    def test_ram_zip_failure_retains_captured_image(self):
        with patch('artifacts.memory.archive.zipfile.ZipFile', side_effect=OSError('disk failure')):
            with self.assertRaisesRegex(OSError, 'Captured evidence retained'):
                self.acquire(self.backend(), filename='memory.zip')
        self.assertFalse((self.root / 'memory.zip').exists())
        recovered = list(self.root.glob('.terra-ram-*/memory.lime'))
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].read_bytes(), self.payload)

    def test_bundled_backend_integrity(self):
        self.assertEqual(hashlib.sha256(BACKEND.read_bytes()).hexdigest(), BACKEND_SHA256)

    def test_validate_image_and_sha256(self):
        image = self.root / 'image.lime'
        image.write_bytes(self.payload)
        result = validate_lime(image, self.expected)
        self.assertEqual(result['sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(result['physical_bytes'], len(b'test memory contents'))

    def test_reject_incomplete_missing_and_invalid_ranges(self):
        image = self.root / 'image.lime'
        for payload, expected in [(self.payload[:-1], self.expected),
                                  (b'bad header', self.expected),
                                  (self.payload + self.payload, self.expected),
                                  (b'', self.expected)]:
            image.write_bytes(payload)
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                validate_lime(image, expected)

    def test_nonroot_dispatches_to_partial_collector(self):
        with patch('artifacts.memory.collector.os.geteuid', return_value=1000), \
             patch('artifacts.memory.process_collector.ProcessMemoryCollector') as collector:
            collector.return_value.acquire.return_value = {'memory_scope': 'accessible_process_memory'}
            result = MemoryCollector().acquire(self.root / 'memory.zip')
            self.assertEqual(result['memory_scope'], 'accessible_process_memory')
            collector.return_value.acquire.assert_called_once_with(self.root / 'memory.zip')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_success_is_private_and_source_backed(self):
        result = self.acquire(self.backend())
        self.assertEqual(Path(result['path']).read_bytes(), self.payload)
        self.assertTrue(result['memory_image'])
        self.assertFalse(result['content_retained'])
        self.assertEqual(Path(result['path']).stat().st_mode & 0o777, 0o600)
        self.assertEqual(result['sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertFalse(list(self.root.glob('.terra-ram-*')))

    def test_never_overwrite_existing_image(self):
        destination = self.root / 'memory.lime'
        destination.write_bytes(b'existing evidence')
        with self.assertRaises(FileExistsError):
            self.acquire(self.backend())
        self.assertEqual(destination.read_bytes(), b'existing evidence')

    def test_backend_failure_without_capture_is_removed(self):
        with self.assertRaises(RuntimeError):
            self.acquire(self.backend(failure=True))
        self.assertFalse((self.root / 'memory.lime').exists())
        self.assertFalse(list(self.root.glob('.terra-ram-*')))

    def test_validation_failure_preserves_original_bytes_in_zip(self):
        import json
        result = self.acquire(self.backend(payload=b'partial'), filename='failed.zip')
        self.assertTrue(result['acquisition_failed'])
        self.assertFalse(result['acquisition_stopped'])
        self.assertFalse(result['complete_physical_ram'])
        with zipfile.ZipFile(result['path']) as archive:
            self.assertEqual(archive.read('failed.lime'), b'partial')
            metadata = json.loads(archive.read('acquisition.json'))
            self.assertEqual(metadata['validation_status'], 'failed')
            self.assertIn('Truncated', metadata['validation_error'])
            self.assertIn(b'Truncated', archive.read('logs/acquisition.log'))
        self.assertFalse(list(self.root.glob('.terra-ram-*')))

    def test_split_blocks_validate_with_full_coverage(self):
        image = self.root / 'split.lime'
        image.write_bytes(lime(4096, b'abcd') + lime(4100, b'efgh'))
        result = validate_lime(image, [(4096, 4103)])
        self.assertTrue(result['complete_physical_ram'])
        self.assertEqual(result['physical_bytes'], 8)
        self.assertEqual(result['missing_memory_ranges'], [])
        self.expected = [(4096, 4103)]
        result = self.acquire(self.backend(payload=image.read_bytes()), filename='split.zip')
        self.assertTrue(result['complete_physical_ram'])
        with zipfile.ZipFile(result['path']) as archive:
            self.assertEqual(archive.read('split.lime'), image.read_bytes())

    def test_stopped_split_image_preserves_all_readable_prefix_blocks(self):
        self.expected = [(4096, 4103)]
        payload = lime(4096, b'abcd') + lime(4100, b'efgh')[:-2]
        cancel = Event()
        def progress(value):
            if value['phase'] == 'Verifying RAM image':
                cancel.set()
        result = self.acquire(self.backend(payload=payload), cancel, progress)
        self.assertTrue(result['acquisition_stopped'])
        self.assertEqual(result['physical_bytes'], 6)
        self.assertEqual(len(result['memory_ranges']), 2)
        self.assertEqual(result['missing_physical_bytes'], 2)
        self.assertEqual(Path(result['path']).read_bytes(), payload)

    def test_backend_error_after_capture_packages_bytes_and_diagnostics(self):
        import json
        backend = self.backend()
        backend.write_text(backend.read_text() + 'sys.stderr.write("backend read failed")\nsys.exit(1)\n')
        result = self.acquire(backend, filename='backend-failure.zip')
        self.assertTrue(result['acquisition_failed'])
        self.assertFalse(result['complete_physical_ram'])
        with zipfile.ZipFile(result['path']) as archive:
            self.assertEqual(archive.read('backend-failure.lime'), self.payload)
            self.assertIn(b'backend read failed', archive.read('backend.log'))
            self.assertIn('backend read failed', json.loads(archive.read('acquisition.json'))['validation_error'])

    def test_valid_gaps_and_missing_endpoint_save_as_incomplete(self):
        import json
        self.expected = [(4096, 4105), (8192, 8194)]
        payload = lime(4096, b'abcd') + lime(4102, b'efg')
        result = self.acquire(self.backend(payload=payload), filename='gaps.zip')
        self.assertFalse(result['complete_physical_ram'])
        self.assertEqual(result['missing_physical_bytes'], 6)
        self.assertEqual(result['validation_status'], 'valid')
        with zipfile.ZipFile(result['path']) as archive:
            self.assertEqual(archive.read('gaps.lime'), payload)
            metadata = json.loads(archive.read('acquisition.json'))
            self.assertEqual(metadata['missing_memory_ranges'], [dict(start=4100, end=4101), dict(start=4105, end=4105), dict(start=8192, end=8194)])
            self.assertIn('not assumed to be zero', metadata['limitations'][0])

    def test_outside_expected_block_and_overlap_are_rejected(self):
        image = self.root / 'invalid.lime'
        for payload in (lime(0, b'abcd'), lime(4096, b'abcd') + lime(4098, b'abcd')):
            image.write_bytes(payload)
            with self.assertRaises(ValueError):
                validate_lime(image, self.expected)

    def test_failure_to_publish_never_discards_captured_image(self):
        with patch('artifacts.memory.partial.os.replace', side_effect=OSError('destination failure')):
            with self.assertRaisesRegex(OSError, 'Captured evidence retained'):
                self.acquire(self.backend(payload=b'invalid captured bytes'), filename='failed.zip')
        retained = list(self.root.glob('.terra-ram-*/.terra-ram-*/image.lime'))
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b'invalid captured bytes')
        self.assertFalse((self.root / 'failed.zip').exists())

    def test_iomem_ignores_nested_system_ram_and_merges_adjacent_ranges(self):
        from artifacts.memory.collector import physical_ranges
        with patch('artifacts.memory.collector.Path.read_text', return_value='00001000-00001003 : System RAM\n  00001001-00001002 : System RAM\n00001004-00001007 : System RAM'):
            self.assertEqual(physical_ranges(), [(4096, 4103)])

    def test_cancel_verification_preserves_unpublished_image(self):
        cancel = Event()
        def progress(value):
            if value['phase'] == 'Verifying RAM image':
                cancel.set()
        result = self.acquire(self.backend(), cancel, progress)
        self.assertTrue(result['acquisition_stopped'])
        self.assertFalse(result['complete_physical_ram'])
        self.assertEqual((self.root / 'memory.lime').read_bytes(), self.payload)
        self.assertEqual(result['sha256'], hashlib.sha256(self.payload).hexdigest())
        import json
        self.assertTrue(json.loads(Path(result['metadata_path']).read_text())['acquisition_stopped'])

    def test_stop_mid_range_preserves_original_truncated_stream(self):
        script = self.root / 'fake-avml'
        truncated = self.payload[:-5]
        script.write_text('#!/usr/bin/env python3\nimport sys,time\nfrom pathlib import Path\n'
                          f'Path(sys.argv[-1]).write_bytes({truncated!r})\ntime.sleep(30)\n')
        script.chmod(0o700)
        cancel = Event()
        def progress(value):
            if value['phase'] == 'Acquiring physical RAM' and value['bytes']:
                cancel.set()
        result = self.acquire(script, cancel, progress)
        self.assertEqual(Path(result['path']).read_bytes(), truncated)
        self.assertFalse(result['memory_ranges'][0]['complete'])
        self.assertEqual(result['physical_bytes'], len(b'test memory contents') - 5)
        self.assertFalse(list(self.root.glob('.terra-ram-*')))

    def test_cancel_running_backend_terminates_and_cleans_up(self):
        cancel = Event()
        def progress(value):
            cancel.set()
        with self.assertRaises(MemoryCancelled):
            self.acquire(self.backend(slow=True), cancel, progress)
        self.assertFalse((self.root / 'memory.lime').exists())
        self.assertFalse(list(self.root.glob('.terra-ram-*')))

    def test_insufficient_space_no_destination_write(self):
        with patch('artifacts.memory.collector.shutil.disk_usage') as usage:
            usage.return_value.free = 0
            with self.assertRaises(OSError):
                self.acquire(self.backend())
        self.assertFalse((self.root / 'memory.lime').exists())

    def test_masked_memory_map_rejected(self):
        from artifacts.memory.collector import physical_ranges
        with patch('artifacts.memory.collector.Path.read_text', return_value='00000000-00000000 : System RAM'):
            with self.assertRaises(PermissionError):
                physical_ranges()

    def test_generated_ram_image_excluded_from_file_scan(self):
        from controllers.scan_controller import ScanEngine
        from storage.memory_store import MemoryStore
        image = self.root / 'memory.lime'
        image.write_bytes(self.payload)
        (self.root / 'document.txt').write_text('target evidence')
        store = MemoryStore()
        configuration = {'options': dict(folder_names=False, file_names=False, file_contents=False, hash_matches=False),
                         'collection_mode': 'all_supported', 'hashes': [], 'keywords': []}
        ScanEngine({'paths': [str(self.root)], 'excluded_files': [str(image)]}, configuration, store).run()
        self.assertEqual([record['path'] for record in store.records], [str(self.root / 'document.txt')])

    def test_pre_cancel_no_write(self):
        cancel = Event()
        cancel.set()
        with self.assertRaises(MemoryCancelled):
            self.acquire(self.backend(), cancel)
        self.assertFalse((self.root / 'memory.lime').exists())

    def test_memory_export_outside_target_hierarchy(self):
        record = self.acquire(self.backend())
        record['data'] = b''
        target = self.root / 'target'
        target.mkdir()
        output = self.root / 'export.zip'
        ZipExporter([record], [], 0, {'targets': {'paths': [str(target)]}}).save(output)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read('terra/memory/memory.lime'), self.payload)
            self.assertIn('terra/memory/memory.lime', archive.read('terra/checksums.sha256').decode())

    def test_navigation_routes_requested_ram_before_files(self):
        window = MainWindow()
        window.target_selection = {'paths': [str(self.root)], 'acquire_ram': True}
        window.start_triage({'options': {}, 'hashes': [], 'keywords': []})
        self.assertIs(window.stack.currentWidget(), window.ram)
        self.assertFalse(window.scan_controller.running)
        self.assertFalse(window.ram_controller.running)
        window.close()

    def test_destination_acknowledgement_required(self):
        window = MainWindow()
        window.ram.prepare({'paths': [str(self.root)]}, None)
        window.ram.destination.setText(str(self.root / 'memory.zip'))
        emitted = []
        window.ram.capture_requested.connect(emitted.append)
        window.ram.submit()
        self.assertEqual(emitted, [])
        window.ram.ack.setChecked(True)
        window.ram.submit()
        self.assertEqual(emitted, [str(self.root / 'memory.zip')])
        window.close()

    def test_ram_only_targets_skip_configuration_and_preserve_back(self):
        window = MainWindow()
        self.addCleanup(window.close)
        window.navigation.open(window.targets)
        window.targets.entire_system.setChecked(False)
        window.targets.volumes.clear()
        window.targets.folders.clear()
        window.targets.submit()
        self.assertIs(window.stack.currentWidget(), window.targets)
        self.assertTrue(window.targets.error.text())
        window.targets.acquire_ram.setChecked(True)
        with patch.object(window.scan_controller, 'start') as scan, patch.object(window.ram_controller, 'start') as ram:
            window.targets.submit()
            self.assertIs(window.stack.currentWidget(), window.ram)
            self.assertEqual(window.target_selection['paths'], [])
            self.assertFalse(window.target_selection['collect_live'])
            self.assertIsNone(window.triage_configuration)
            scan.assert_not_called()
            ram.assert_not_called()
            window.ram.finish({'status': 'saved', 'record': dict(path='memory.zip', size=100,
                               sha256='abc', memory_scope='physical_ram')})
            self.assertFalse(window.ram.next.isVisible())
            self.assertFalse(window.ram.finish_button.isHidden())
            window.start_file_triage()
            scan.assert_not_called()
            window.ram.back_requested.emit()
            self.assertIs(window.stack.currentWidget(), window.targets)

    def test_ram_with_folder_still_opens_configuration(self):
        window = MainWindow()
        self.addCleanup(window.close)
        window.accept_targets({'paths': [str(self.root)], 'all_volumes': False,
                               'collect_live': False, 'acquire_ram': True})
        self.assertIs(window.stack.currentWidget(), window.configuration)

    def test_stopped_file_scan_saves_only_when_user_selects_export(self):
        import json
        from storage.memory_store import MemoryStore
        from tests.test_scan import configuration
        window = MainWindow()
        self.addCleanup(window.close)
        selected = self.root / 'selected'
        selected.mkdir()
        path = selected / 'document.txt'
        data = b'Already found evidence'
        path.write_bytes(data)
        window.target_selection = {'paths': [str(selected)], 'acquire_ram': True}
        window.triage_configuration = configuration()
        window.ram_destination = str(self.root / 'memory.lime')
        window.scan_controller.store = MemoryStore()
        from artifacts.file_collector import FileCollector
        payload, metadata = FileCollector().collect(str(path), lambda: False)
        window.scan_controller.store.add(dict(metadata, path=str(path), category='Documents', kind='file', matches={}), payload)
        summary = dict(status='stopped', examined=1, collected=1, errors=0, diagnostic_count=0)
        calls = []
        def start(filename, store, context, allow_target=False):
            calls.append(filename)
            records, diagnostics, count = store.snapshot()
            result = ZipExporter(records, diagnostics, count, context).save(filename, allow_target)
            window.export_completed(result)
        with patch.object(window.export_controller, 'start', side_effect=start):
            window.scan_completed(summary)
            self.assertEqual(calls, [])
            window.open_export()
            window.export.destination.setText(str(self.root / 'selected-export.zip'))
            window.export.submit()
        self.assertEqual(len(calls), 1)
        self.assertEqual(Path(calls[0]).parent, self.root)
        self.assertEqual(Path(calls[0]).name, 'selected-export.zip')
        with zipfile.ZipFile(calls[0]) as archive:
            manifest = json.loads(archive.read('terra/manifest.json'))
            self.assertTrue(manifest['partial_scan'])
            self.assertTrue(any(archive.read(name) == data for name in archive.namelist() if name.startswith('evidence/')))
        with patch.object(window.export_controller, 'start') as start_mock:
            window.ram_destination = None
            window.scan_completed(summary)
            start_mock.assert_not_called()

    def test_ram_finish_exits_without_file_triage_or_case_export(self):
        from shiboken6 import delete
        window = MainWindow()
        self.addCleanup(delete, window)
        window.from_case = True
        window.target_selection = {'paths': [str(self.root)], 'acquire_ram': True}
        window.ram.prepare(window.target_selection, window.case_information())
        window.navigation.open(window.ram)
        window.show()
        self.assertTrue(window.ram.finish_button.isHidden())
        record = self.acquire(self.backend())
        window.ram_completed({'status': 'saved', 'record': record})
        self.assertFalse(window.ram.finish_button.isHidden())
        self.assertFalse(window.ram.next.isHidden())
        with patch.object(window.scan_controller, 'start') as scan, patch.object(window.export_controller, 'start') as export:
            window.ram.finish_button.click()
            scan.assert_not_called()
            export.assert_not_called()
        self.assertFalse(window.isVisible())
        self.assertEqual(Path(record['path']).read_bytes(), self.payload)

    def test_ram_finish_available_for_saved_partial_and_hidden_on_retry(self):
        from interface.pages.ram import RamPage
        from shiboken6 import delete
        page = RamPage()
        self.addCleanup(delete, page)
        for scope in ('physical_ram', 'accessible_process_memory'):
            page.finish({'status': 'saved', 'record': dict(memory_scope=scope, acquisition_stopped=True,
                         path='saved-memory', size=100, sha256='fixture')})
            self.assertFalse(page.finish_button.isHidden())
            page.begin()
            self.assertTrue(page.finish_button.isHidden())
        page.finish({'status': 'failed', 'error': 'Acquisition unavailable'})
        self.assertFalse(page.finish_button.isHidden())
        page.prepare({'paths': []}, None)
        self.assertTrue(page.finish_button.isHidden())
        page.finish({'status': 'failed', 'error': 'Acquisition unavailable'})
        self.assertFalse(page.finish_button.isHidden())
        self.assertTrue(page.next.isHidden())
