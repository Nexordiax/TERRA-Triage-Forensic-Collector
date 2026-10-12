"""Full physical Linux memory acquisition through the pinned, offline AVML build."""
import hashlib
import os
import platform
import re
import shutil
import struct
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from artifacts.memory.coverage import merge_ranges, coverage, estimated_image_size

BACKEND = Path(__file__).resolve().parents[2] / 'assets/tools/avml-minimal'
BACKEND_SHA256 = '79094391156f778db695cde0f84c36c3ad16987b51d80ea02f4a2ffe703b9f47'


class MemoryCancelled(Exception):
    pass


def physical_ranges():
    ranges = []
    for line in Path('/proc/iomem').read_text().splitlines():
        if line[:1].isspace():
            continue
        match = re.fullmatch(r'([0-9a-fA-F]+)-([0-9a-fA-F]+) : System RAM', line.strip())
        if match:
            start, end = (int(value, 16) for value in match.groups())
            ranges.append((start, end))
    if not ranges or all(end == 0 for _, end in ranges):
        raise PermissionError('Physical RAM ranges are unavailable or masked. Run TERRA with authorized root privileges; kernel restrictions may also prevent acquisition.')
    return merge_ranges(ranges)


def validate_lime(filename, expected, cancel=None, progress=None):
    """Check all LiME ranges and payload lengths, while hashing bounded chunks."""
    cancel = cancel or Event()
    progress = progress or (lambda value: None)
    digest = hashlib.sha256()
    ranges = []
    size = 0
    total = os.stat(filename).st_size
    last_progress = 0
    expected = merge_ranges(expected)
    expected_index = 0
    with open(filename, 'rb') as source:
        while header := source.read(32):
            if cancel.is_set():
                raise MemoryCancelled()
            if len(header) != 32:
                raise ValueError('Truncated LiME header.')
            magic, version, start, end, reserved = struct.unpack('<IIQQQ', header)
            if magic != 0x4C694D45 or version != 1 or reserved != 0 or end < start:
                raise ValueError('Invalid LiME range header.')
            if ranges and start <= ranges[-1][1]:
                raise ValueError('Overlapping or unordered LiME ranges.')
            while expected_index < len(expected) and expected[expected_index][1] < start:
                expected_index += 1
            if expected_index >= len(expected) or start < expected[expected_index][0] or end > expected[expected_index][1]:
                raise ValueError(f'RAM image block {start:#x}-{end:#x} lies outside expected physical RAM.')
            ranges.append((start, end))
            digest.update(header)
            size += len(header)
            remaining = end - start + 1
            while remaining:
                if cancel.is_set():
                    raise MemoryCancelled()
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError('Incomplete physical RAM image: truncated range payload.')
                digest.update(chunk)
                remaining -= len(chunk)
                size += len(chunk)
                now = time.monotonic()
                if now - last_progress >= 0.1 or size == total:
                    progress({'phase': 'Verifying RAM image', 'bytes': size, 'total': total})
                    last_progress = now
    if not ranges:
        raise ValueError('RAM image contains no physical memory blocks.')
    summary = coverage(expected, ranges)
    limitations = []
    if not summary['complete_physical_ram']:
        limitations.append(f"{summary['missing_physical_bytes']} expected physical RAM bytes are absent from the image. AVML can omit zero blocks or inaccessible ranges; absent bytes are not assumed to be zero.")
    return {**summary, 'validation_status': 'valid', 'limitations': limitations, 'sha256': digest.hexdigest(), 'size': size,
            'physical_bytes': sum(end - start + 1 for start, end in ranges),
            'memory_ranges': [{'start': start, 'end': end} for start, end in ranges]}


class MemoryCollector:
    def __init__(self, cancel=None, progress=None):
        self.cancel = cancel or Event()
        self.progress = progress or (lambda value: None)

    def acquire(self, destination):
        if os.geteuid() != 0:
            from artifacts.memory.process_collector import ProcessMemoryCollector
            return ProcessMemoryCollector(self.cancel, self.progress).acquire(destination)
        if Path(destination).suffix.lower() == '.zip':
            from artifacts.memory.archive import acquire_archive
            return acquire_archive(self, destination)
        return self.acquire_physical(destination)

    def acquire_physical(self, destination):
        if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
            raise RuntimeError('The bundled RAM backend supports Linux x86-64.')
        if os.geteuid() != 0:
            raise PermissionError('Full physical RAM acquisition requires root. Use Back to return to privilege selection and explicitly elevate TERRA.')
        if not BACKEND.is_file() or hashlib.sha256(BACKEND.read_bytes()).hexdigest() != BACKEND_SHA256:
            raise RuntimeError('The bundled AVML backend is missing or failed SHA-256 verification.')
        expected = physical_ranges()
        destination = Path(os.path.abspath(destination))
        if destination.suffix.lower() != '.lime':
            raise ValueError('Choose a RAM image filename ending in .lime.')
        required = estimated_image_size(expected)
        if shutil.disk_usage(destination.parent).free < required:
            raise OSError(f'Insufficient destination space: at least {required} bytes are needed for the full RAM image.')
        if self.cancel.is_set():
            raise MemoryCancelled()
        started = datetime.now(timezone.utc).isoformat()
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        reserved = os.fstat(descriptor)
        os.close(descriptor)
        published = False
        try:
            work = Path(tempfile.mkdtemp(prefix='.terra-ram-', dir=destination.parent))
            try:
                image = work / 'image.lime'
                try:
                    with open(Path(work) / 'backend.log', 'w+b') as log:
                        # Minimal AVML has no network features. No shell or upload arguments.
                        process = subprocess.Popen([str(BACKEND), 'acquire', str(image)],
                                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                        try:
                            while process.poll() is None:
                                if self.cancel.wait(0.2):
                                    raise MemoryCancelled()
                                self.progress({'phase': 'Acquiring physical RAM',
                                               'bytes': image.stat().st_size if image.exists() else 0, 'total': required})
                            if self.cancel.is_set():
                                raise MemoryCancelled()
                            if process.returncode:
                                log.seek(0)
                                detail = log.read(16384).decode('utf-8', errors='replace').strip()
                                raise RuntimeError(f'AVML could not acquire full RAM (exit {process.returncode}). {detail}')
                        finally:
                            if process.poll() is None:
                                process.terminate()
                                try:
                                    process.wait(timeout=5)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                    process.wait()
                    verified = validate_lime(image, expected, self.cancel, self.progress)
                    os.chmod(image, 0o600)
                    with open(image, 'rb') as source:
                        os.fsync(source.fileno())
                    current = os.stat(destination, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != (reserved.st_dev, reserved.st_ino):
                        raise OSError('Destination was replaced during acquisition; it was not overwritten.')
                    if self.cancel.is_set():
                        raise MemoryCancelled()
                    os.replace(image, destination)
                    published = True
                    info = destination.stat()
                    return dict(verified, path=str(destination), kind='file', category='Physical RAM', matches={},
                                content_retained=False, collection=('full physical RAM image (LiME)' if verified['complete_physical_ram'] else 'physical RAM image with coverage gaps (LiME)'),
                                memory_image=True, memory_scope='physical_ram', backend='AVML minimal 0.20.0', backend_sha256=BACKEND_SHA256,
                                acquired_at=started, completed_at=datetime.now(timezone.utc).isoformat(),
                                mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
                                device=info.st_dev, inode=info.st_ino, mode=info.st_mode,
                                backend_log=(Path(work) / 'backend.log').read_text(errors='replace'))
                except MemoryCancelled:
                    if not image.exists() or not image.stat().st_size:
                        raise
                    from artifacts.memory.partial import publish
                    record = publish(image, destination, reserved, expected, started, self.progress, BACKEND_SHA256)
                    record['backend_log'] = (Path(work) / 'backend.log').read_text(errors='replace')
                    published = True
                    return record
                except Exception as error:
                    if not image.exists() or not image.stat().st_size:
                        raise
                    from artifacts.memory.partial import publish
                    record = publish(image, destination, reserved, expected, started, self.progress,
                                     BACKEND_SHA256, error=str(error))
                    record['backend_log'] = (work / 'backend.log').read_text(errors='replace')
                    published = True
                    return record
            except Exception as error:
                if image.exists() and image.stat().st_size:
                    raise OSError(f'RAM acquisition failed: {error}. Captured evidence retained at {work}') from error
                raise
            finally:
                if published or not image.exists() or not image.stat().st_size:
                    shutil.rmtree(work)

        finally:
            if not published:
                try:
                    current = os.stat(destination, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (reserved.st_dev, reserved.st_ino):
                        destination.unlink()
                except FileNotFoundError:
                    pass
