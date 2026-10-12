"""Media overlap with serial evidence, budget, stop and recovery semantics."""
import hashlib
import io
import os
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event, Lock
from unittest.mock import patch

from PIL import Image

from analyzers.content import analyze
from artifacts.file_collector import CollectionCancelled
from controllers.scan_controller import ScanEngine
from controllers.scan_scheduler import select_analysis_workers, available_memory
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


class ParallelMediaTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for index in range(6):
            image = Image.new('RGB', (48, 48), (180 + index, 130, 100))
            output = io.BytesIO()
            image.save(output, format='PNG')
            (self.root / f'image-{index}.png').write_bytes(output.getvalue())

    def run_scan(self, workers, mode='all_supported', store=None, cancel=None, budget=None, recovery=None, on_finding=None):
        config = configuration(mode, hashes=[hashlib.md5((self.root / 'image-0.png').read_bytes()).hexdigest()],
                               hash_matches=True)
        config.update(analysis_workers=workers, scan_workers=1,
                      analysis_options={'skin_tone': True, 'skin_threshold': 10})
        if recovery:
            config['recovery'] = recovery
        store = store if store is not None else MemoryStore()
        with patch('controllers.scan_scheduler.cpu_capacity', return_value=8), patch('controllers.scan_scheduler.available_memory', return_value=16 * 1024 ** 3):
            engine = ScanEngine({'paths': [str(self.root)]}, config, store, cancel=cancel, on_finding=on_finding)
        if budget is not None:
            engine.analysis_max_bytes = budget
        summary = engine.run()
        summary = {key: value for key, value in summary.items() if key != 'volume_metadata'}
        self.assertEqual(store.remaining_bytes, store.max_bytes - store.bytes_used)
        return summary, store, engine

    @staticmethod
    def evidence(store):
        return sorted([{key: value for key, value in row.items() if key not in ('acquired_at', 'id', 'atime_ns')} for row in store.records],
                      key=lambda row: row['path'])

    def test_real_isolated_analysis_matches_serial_in_both_collection_modes(self):
        for mode in ('all_supported', 'matches_only'):
            first, serial, _ = self.run_scan(1, mode)
            second, parallel, engine = self.run_scan(3, mode)
            self.assertEqual(engine.read_workers, 1)
            self.assertEqual(engine.analysis_workers, 3)
            self.assertEqual(first, second)
            self.assertEqual(self.evidence(serial), self.evidence(parallel))

    def test_analysis_overlaps_while_primary_reads_stay_serial(self):
        active = highest = 0
        lock = Lock()
        def observed(*args, **kwargs):
            nonlocal active, highest
            with lock:
                active += 1
                highest = max(highest, active)
            try:
                time.sleep(0.05)
                return analyze(*args, **kwargs)
            finally:
                with lock:
                    active -= 1
        with patch('controllers.scan_controller.analyze_content', side_effect=observed):
            summary, _, _ = self.run_scan(3)
        self.assertEqual(summary['status'], 'completed')
        self.assertGreater(highest, 1)
        self.assertLessEqual(highest, 3)

    def test_slow_first_media_does_not_block_ready_findings(self):
        release = Event()
        first_path = next(self.root.iterdir())
        callbacks = []
        def delayed(path, *args, **kwargs):
            if path == str(first_path):
                if not release.wait(3):
                    raise ValueError('Ready media findings were blocked behind the first decoder')
            return analyze(path, *args, **kwargs)
        def published(row):
            callbacks.append(row['path'])
            if row['path'] != str(first_path):
                release.set()
        with patch('controllers.scan_controller.analyze_content', side_effect=delayed):
            summary, store, _ = self.run_scan(3, on_finding=published)
        self.assertEqual(summary['status'], 'completed')
        self.assertNotEqual(callbacks[0], str(first_path))
        self.assertEqual(len(store.records), 6)

    def test_derived_result_budget_and_small_retention_match_serial(self):
        first, serial, _ = self.run_scan(1, store=MemoryStore(max_bytes=300), budget=2000)
        second, parallel, _ = self.run_scan(3, store=MemoryStore(max_bytes=300), budget=2000)
        self.assertEqual(first, second)
        self.assertEqual(self.evidence(serial), self.evidence(parallel))

    def test_cancel_stops_all_analysis_and_releases_descriptors(self):
        cancel = Event()
        before = len(os.listdir('/proc/self/fd'))
        def stopped(*args, **kwargs):
            cancel.set()
            raise CollectionCancelled()
        with patch('controllers.scan_controller.analyze_content', side_effect=stopped):
            summary, store, _ = self.run_scan(3, cancel=cancel)
        self.assertEqual(summary['status'], 'stopped')
        self.assertEqual(store.records, [])
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_checkpoint_contains_only_published_completed_media(self):
        from storage.recovery import load_session
        with tempfile.TemporaryDirectory() as destination:
            path = str(Path(destination) / 'scan.terra-session')
            summary, original, _ = self.run_scan(3, recovery={'enabled': True, 'path': path})
            engine, _, recovered = load_session(path)
            self.assertEqual(recovered['status'], summary['status'])
            self.assertEqual(self.evidence(original), self.evidence(engine.store))
            self.assertEqual(len(engine.finished_paths), 6)

    def test_memory_and_cpu_limits_and_override_validation(self):
        with patch('controllers.scan_scheduler.cpu_capacity', return_value=8):
            with patch('controllers.scan_scheduler.available_memory', return_value=0):
                self.assertEqual(select_analysis_workers(), 1)
            with patch('controllers.scan_scheduler.available_memory', return_value=4 * 1024 ** 3):
                self.assertEqual(select_analysis_workers(), 2)
            with patch('controllers.scan_scheduler.available_memory', return_value=16 * 1024 ** 3):
                self.assertEqual(select_analysis_workers(), 4)
                self.assertEqual(select_analysis_workers(1), 1)
        for invalid in (True, 0, 5, '2'):
            with self.assertRaises(ValueError):
                select_analysis_workers(invalid)

    def test_stopped_media_checkpoint_resumes_without_duplicate_findings(self):
        from storage.recovery import load_session
        cancel = Event()
        findings = []
        def stop_after_two(row):
            findings.append(row)
            if len(findings) == 2:
                cancel.set()
        with tempfile.TemporaryDirectory() as destination:
            path = str(Path(destination) / 'scan.terra-session')
            summary, partial, _ = self.run_scan(3, cancel=cancel, on_finding=stop_after_two,
                                              recovery={'enabled': True, 'path': path})
            self.assertEqual(summary['status'], 'stopped')
            self.assertEqual(len(partial.records), 2)
            engine, _, _ = load_session(path)
            resumed = engine.run()
            self.assertEqual(resumed['status'], 'completed')
            self.assertEqual(resumed['examined'], 6)
            _, serial, _ = self.run_scan(1)
            self.assertEqual(self.evidence(serial), self.evidence(engine.store))

    def test_memory_detection_uses_parent_limits_when_child_controller_is_missing(self):
        values = {'/proc/meminfo': 'MemAvailable: 8388608 kB\n',
                  '/proc/self/cgroup': '0::/parent/child\n',
                  '/sys/fs/cgroup/parent/memory.max': str(4 * 1024 ** 3),
                  '/sys/fs/cgroup/parent/memory.current': str(1024 ** 3),
                  '/sys/fs/cgroup/memory.max': 'max'}
        def read(path):
            if str(path) not in values:
                raise FileNotFoundError(str(path))
            return values[str(path)]
        with patch.object(Path, 'read_text', autospec=True, side_effect=read):
            self.assertEqual(available_memory(), 3 * 1024 ** 3)
        values = {key: value for key, value in values.items() if not key.startswith('/sys')}
        with patch.object(Path, 'read_text', autospec=True, side_effect=read):
            self.assertEqual(available_memory(), 8 * 1024 ** 3)
