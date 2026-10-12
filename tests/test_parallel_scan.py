"""Serial/parallel equivalence, pinned descriptors, cancellation and RAM bounds."""
import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event, Lock
from unittest.mock import patch

from artifacts.file_collector import FileCollector, CollectionCancelled
from controllers.scan_controller import ScanEngine
from controllers.scan_scheduler import select_workers
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


class ObservedCollector(FileCollector):
    def __init__(self, cancel=None):
        super().__init__(max_file_bytes=4096)
        self.lock = Lock()
        self.active = self.highest = 0
        self.cancel = cancel

    def collect(self, *args, **kwargs):
        with self.lock:
            self.active += 1
            self.highest = max(self.highest, self.active)
        try:
            time.sleep(0.015)  # Deterministic overlap observation, not a speed benchmark.
            if self.cancel:
                self.cancel.set()
            return super().collect(*args, **kwargs)
        finally:
            with self.lock:
                self.active -= 1


class ParallelScanTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for index in range(20):
            (self.root / f'file-{index}.bin').write_bytes(b'needle ' + bytes([index]) * 2048)

    def run_scan(self, workers, collector=None, store=None, cancel=None, mode='all_supported'):
        digest = hashlib.sha256((self.root / 'file-0.bin').read_bytes()).hexdigest()
        config = configuration(mode, hashes=[digest], keywords=['needle'], hash_matches=True, file_contents=True)
        config['scan_workers'] = workers
        store = store if store is not None else MemoryStore()
        callbacks = []
        with patch('controllers.scan_scheduler.cpu_capacity', return_value=8):
            engine = ScanEngine({'paths': [str(self.root)]}, config, store, collector=collector,
                                cancel=cancel, on_finding=callbacks.append)
            summary = engine.run()
        summary = {key: value for key, value in summary.items() if key != 'volume_metadata'}
        self.assertEqual(store.remaining_bytes, store.max_bytes - store.bytes_used)
        return summary, store, callbacks

    def test_parallel_results_and_callbacks_equal_serial_with_full_and_matches_modes(self):
        for mode in ('all_supported', 'matches_only'):
            serial, first, _ = self.run_scan(1, mode=mode)
            collector = ObservedCollector()
            parallel, second, callbacks = self.run_scan(4, collector, mode=mode)
            self.assertGreater(collector.highest, 1)
            self.assertLessEqual(collector.highest, 4)
            self.assertEqual(serial, parallel)
            normalized = lambda record: {key: value for key, value in record.items() if key not in ('acquired_at', 'atime_ns')}
            self.assertEqual([normalized(row) for row in first.records], [normalized(row) for row in second.records])
            self.assertEqual(len(callbacks), 20)
            self.assertEqual(sum(bool(row['matches'].get('hashes')) for row in callbacks), 1)

    def test_small_ram_budget_preserves_findings_and_releases_reservations(self):
        serial, first, _ = self.run_scan(1, store=MemoryStore(max_bytes=6000))
        parallel, second, _ = self.run_scan(4, store=MemoryStore(max_bytes=6000))
        self.assertEqual(serial, parallel)
        self.assertEqual([row['data'] for row in first.records], [row['data'] for row in second.records])
        self.assertLessEqual(second.bytes_used, 6000)

    def test_stop_cancels_readers_and_closes_descriptors(self):
        cancel = Event()
        before = len(os.listdir('/proc/self/fd'))
        summary, store, callbacks = self.run_scan(4, ObservedCollector(cancel), cancel=cancel)
        self.assertEqual(summary['status'], 'stopped')
        self.assertEqual(callbacks, [])
        self.assertEqual(store.records, [])
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_failed_reader_is_logged_and_others_continue(self):
        collector = ObservedCollector()
        original = collector.collect
        def read(path, *args, **kwargs):
            if path.endswith('file-0.bin'):
                raise OSError('fixture read failure')
            return original(path, *args, **kwargs)
        with patch.object(collector, 'collect', side_effect=read):
            summary, store, _ = self.run_scan(3, collector)
        self.assertEqual(summary['status'], 'completed_with_errors')
        self.assertEqual(summary['examined'], 20)
        self.assertEqual(summary['collected'], 19)
        self.assertTrue(any('fixture read failure' in row['message'] for row in store.diagnostics))

    def test_structured_artifact_parsing_stays_serial(self):
        etc = self.root / 'etc'
        etc.mkdir()
        (etc / 'os-release').write_text('NAME=Fixture\nID=fixture\n')
        _, store, _ = self.run_scan(4)
        artifact = next(row for row in store.records if row['path'].endswith('os-release'))
        self.assertEqual(artifact['parsed_artifact']['status'], 'parsed')

    def test_worker_timeout_exception_is_logged_without_retry_loop(self):
        collector = ObservedCollector()
        original = collector.collect
        def read(path, *args, **kwargs):
            if path.endswith('file-0.bin'):
                raise TimeoutError('fixture worker timeout')
            return original(path, *args, **kwargs)
        with patch.object(collector, 'collect', side_effect=read):
            summary, store, _ = self.run_scan(3, collector)
        self.assertEqual(summary['collected'], 19)
        self.assertTrue(any('fixture worker timeout' in row['message'] for row in store.diagnostics))

    def test_worker_override_validation_and_cpu_limit(self):
        with patch('controllers.scan_scheduler.cpu_capacity', return_value=2):
            self.assertEqual(select_workers([], 8), 2)
        for invalid in (True, 0, 9, '4'):
            with self.assertRaises(ValueError):
                select_workers([], invalid)

    def test_automatic_scheduling_keeps_small_files_serial(self):
        collector = ObservedCollector()
        with patch('controllers.scan_controller.FileCollector', return_value=collector), patch('controllers.scan_controller.select_workers', return_value=4):
            engine = ScanEngine({'paths': [str(self.root)]}, configuration(), MemoryStore())
            self.assertEqual(engine.parallel_min_bytes, 1024 * 1024)
            summary = engine.run()
        summary = {key: value for key, value in summary.items() if key != 'volume_metadata'}
        self.assertEqual(summary['collected'], 20)
        self.assertEqual(collector.highest, 1)
