"""Optional warm-cache synthetic benchmark: python -m tests.benchmark_scan."""
import hashlib
import json
import statistics
import tempfile
import time
from pathlib import Path

from controllers.scan_controller import ScanEngine
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


def benchmark():
    with tempfile.TemporaryDirectory(prefix='terra-synthetic-benchmark-') as temporary:
        root = Path(temporary)
        small, large = root / 'small', root / 'large'
        small.mkdir()
        large.mkdir()
        chunk = (b'fixture needle keyword ' * 50000)[:1024 * 1024]
        for index in range(256):
            (small / f'fixture-{index}.bin').write_bytes(chunk[:32768])
        large_data = chunk * 16
        for index in range(12):
            (large / f'fixture-{index}.bin').write_bytes(large_data)
        reports = []
        for name, directory, contents, budget in (('small-hash', small, False, 0),
                                                 ('large-hash', large, False, 0),
                                                 ('large-hash-keyword', large, True, 0),
                                                 ('small-retained', small, True, 16 * 1024 * 1024)):
            sample = next(directory.iterdir()).read_bytes()
            config = configuration(hashes=[hashlib.sha256(sample).hexdigest()], keywords=['needle', 'missing'],
                                   hash_matches=True, file_contents=contents)
            expected = None
            for workers in (1, 2, 4):
                elapsed, cpu = [], []
                actual = None
                for _ in range(3):
                    store = MemoryStore(max_bytes=budget)
                    engine = ScanEngine({'paths': [str(directory)]}, dict(config, scan_workers=workers), store)
                    start, cpu_start = time.perf_counter(), time.process_time()
                    summary = engine.run()
                    elapsed.append(time.perf_counter() - start)
                    cpu.append(time.process_time() - cpu_start)
                    observations = [(record['path'], record['sha256'], record['matches'], record['data']) for record in store.records]
                    if expected is None:
                        expected = (summary, observations)
                    assert (summary, observations) == expected, 'Serial/parallel evidence differs'
                    actual = engine.read_workers
                reports.append(dict(workload=name, workers=actual, elapsed_seconds=round(statistics.median(elapsed), 4),
                                    cpu_seconds=round(statistics.median(cpu), 4), files=summary['examined'],
                                    matched=summary['hash_matches'], retained_bytes=store.bytes_used))
        print(json.dumps(reports, indent=2))


if __name__ == '__main__':
    benchmark()
