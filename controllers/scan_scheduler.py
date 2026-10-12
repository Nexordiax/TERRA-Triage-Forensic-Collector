"""Bounded scan pipeline; only the coordinator publishes findings or parses."""
import os
from collections import deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from threading import Event, Lock, Semaphore

from artifacts.file_collector import CollectionCancelled


def cpu_capacity():
    count = max(1, getattr(os, 'process_cpu_count', os.cpu_count)() or 1)
    try:
        count = min(count, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        pass
    # Respect the actual cgroup-v2 CPU quota and all parent quotas.
    try:
        group = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                     if line.startswith('0::'))
        directory = Path('/sys/fs/cgroup') / group.lstrip('/')
        base = Path('/sys/fs/cgroup')
        while directory == base or base in directory.parents:
            quota, period = (directory / 'cpu.max').read_text().split()
            if quota != 'max':
                count = min(count, max(1, int(quota) // int(period)))
            if directory == base:
                break
            directory = directory.parent
    except (OSError, ValueError, StopIteration, ZeroDivisionError):
        pass
    return max(1, count)


def select_workers(paths, requested=None):
    if requested is not None:
        if isinstance(requested, bool) or not isinstance(requested, int) or not 1 <= requested <= 8:
            raise ValueError('Scan worker count must be an integer between 1 and 8.')
        return min(requested, cpu_capacity())
    count = min(4, cpu_capacity())
    for path in paths:
        try:
            device = os.stat(path).st_dev
            node = (Path('/sys/dev/block') / f'{os.major(device)}:{os.minor(device)}').resolve()
            rotational = next((parent / 'queue/rotational' for parent in (node, *node.parents)
                               if (parent / 'queue/rotational').is_file()), None)
            if rotational is None:
                count = min(count, 2)  # Unknown/removable/network storage: conservative.
            elif rotational.read_text().strip() == '1':
                return 1
        except (OSError, ValueError):
            count = min(count, 2)
    return max(1, count)


def available_memory():
    """Available host RAM, reduced by remaining cgroup-v2 memory allowances."""
    try:
        fields = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        available = int(fields['MemAvailable'].split()[0]) * 1024
    except (OSError, ValueError, KeyError):
        return 0  # Unknown memory capacity keeps analysis serial.
    try:
        group = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                     if line.startswith('0::'))
        base = Path('/sys/fs/cgroup')
        directory = base / group.lstrip('/')
        while directory == base or base in directory.parents:
            try:
                maximum = (directory / 'memory.max').read_text().strip()
                if maximum != 'max':
                    available = min(available, max(0, int(maximum) - int((directory / 'memory.current').read_text())))
            except FileNotFoundError:
                pass  # A missing child controller must not hide a parent limit.
            if directory == base:
                break
            directory = directory.parent
    except (OSError, ValueError, StopIteration):
        pass  # No readable memory controller; use measured host availability.
    return available


def select_analysis_workers(requested=None):
    if requested is not None and (isinstance(requested, bool) or not isinstance(requested, int) or not 1 <= requested <= 4):
        raise ValueError('Analysis worker count must be an integer between 1 and 4.')
    # Each isolated decoder has a 1.5 GiB address-space limit. Leave 1 GiB
    # available for TERRA, evidence retention and the desktop.
    memory_slots = max(1, (available_memory() - 1024 ** 3) // (1536 * 1024 ** 2))
    return max(1, min(requested or 4, cpu_capacity(), memory_slots))


class ReadQueue:
    """Pin descriptors, reserve cache RAM and publish ready independent media."""
    max_prefetch_bytes = 64 * 1024 * 1024

    def __init__(self, engine):
        self.engine = engine
        self.jobs = deque()
        self.bytes_reserved = 0
        self.abort = Event()
        self.lock = Lock()
        self.latest = None
        self.media_futures = set()
        self.active_analysis = set()
        self.workers = max(engine.read_workers, engine.analysis_workers)
        self.read_slots = Semaphore(engine.read_workers)
        self.analysis_slots = Semaphore(engine.analysis_workers)
        self.pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix='terra-scan')

    def cancelled(self):
        return self.abort.is_set() or self.engine.cancel.is_set()

    def progress(self, path, read, size):
        with self.lock:
            self.latest = (path, read, size)

    def acquire(self, path, descriptor, reserved, analysis_options):
        with self.read_slots:
            if self.cancelled():
                raise CollectionCancelled()
            acquired = self.engine.read_file(path, descriptor, reserved, self.cancelled,
                                            lambda read, total: self.progress(path, read, total))
        analysis = None
        if acquired is not False and analysis_options is not None:
            with self.analysis_slots:
                if self.cancelled():
                    raise CollectionCancelled()
                with self.lock:
                    self.active_analysis.add(path)
                try:
                    analysis = self.engine.analyze_acquired(path, descriptor, acquired, analysis_options,
                                                           self.cancelled, 16 * 1024 * 1024)
                finally:
                    with self.lock:
                        self.active_analysis.discard(path)
        return acquired, analysis

    def submit(self, path, directory_fd, size, analysis_options=None):
        desired = size if size <= min(self.engine.collector.max_file_bytes,
                                      self.engine.store.max_bytes - self.engine.store.bytes_used) else 0
        while self.jobs and (len(self.jobs) >= self.workers * 2 or
                             self.bytes_reserved + desired > self.max_prefetch_bytes or
                             desired > self.engine.store.remaining_bytes):
            self.consume()
        if self.cancelled():
            raise CollectionCancelled()
        reserved = desired if self.engine.store.reserve_bytes(desired) else 0
        descriptor = None
        try:
            descriptor = os.dup(directory_fd)
            future = self.pool.submit(self.acquire, path, descriptor, reserved, analysis_options)
        except Exception:
            self.engine.store.release_bytes(reserved)
            if descriptor is not None:
                os.close(descriptor)
            raise
        self.bytes_reserved += reserved
        self.jobs.append((path, descriptor, reserved, future))
        if analysis_options is not None:
            self.media_futures.add(future)

    def consume(self):
        job = self.jobs[0]
        while True:
            if self.cancelled():
                raise CollectionCancelled()
            # A slow decoder must not hold every ready result behind it. Preserve
            # read-only order and tight derived-budget allocation; independent
            # media with sufficient result headroom can be published as ready.
            if (job[3] in self.media_futures and not job[3].done()
                    and self.engine.analysis_max_bytes - self.engine.analysis_bytes >= 16 * 1024 * 1024):
                job = next((candidate for candidate in self.jobs if candidate[3].done()), job)
            path, descriptor, reserved, future = job
            try:
                result = future.result(timeout=0.1)
                break
            except TimeoutError as error:
                if future.done() and isinstance(future.exception(), TimeoutError):
                    result = None
                    self.engine.counts['examined'] += 1
                    self.engine.log(path, error)
                    break
                with self.lock:
                    update = self.latest
                    active = sorted(self.active_analysis)
                if active:
                    self.engine.progress(f'Analyzing media ({len(active)} active; {len(self.jobs)} queued): {active[0]}')
                elif update:
                    current, self.engine.current_file_bytes, self.engine.current_file_size = update
                    self.engine.progress(current)
            except (OSError, ValueError) as error:
                result = None
                self.engine.counts['examined'] += 1
                self.engine.log(path, error)
                break
        self.jobs.remove(job)
        self.media_futures.discard(future)
        self.bytes_reserved -= reserved
        self.engine.store.release_bytes(reserved)
        try:
            # A serialized parser may have already acquired a companion snapshot.
            if result is not None and os.path.abspath(path) not in self.engine.supporting_collected:
                acquired, analysis = result
                self.engine.scan_file(path, descriptor, acquired=acquired, content_analysis=analysis)
        finally:
            os.close(descriptor)

    def drain(self):
        while self.jobs:
            self.consume()

    def close(self):
        self.abort.set()
        for _, _, _, future in self.jobs:
            future.cancel()
        self.pool.shutdown(wait=True, cancel_futures=True)
        while self.jobs:
            _, descriptor, reserved, _ = self.jobs.popleft()
            os.close(descriptor)
            self.engine.store.release_bytes(reserved)
        self.bytes_reserved = 0
        self.media_futures.clear()
