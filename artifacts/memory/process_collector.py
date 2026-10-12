"""Collect only Linux process memory that the current session can read."""
import hashlib
import json
import os
import platform
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

from artifacts.memory.collector import MemoryCancelled
from artifacts.memory.process_context import (utc_now, read_bytes, process_details, boot_context,
                                             mapping, command_line, executable, changed)


class ProcessAccessUnavailable(OSError):
    def __init__(self, message, context=None, operation=None, error_number=None):
        super().__init__(message)
        self.context = context or {}
        self.operation = operation
        self.error_number = error_number


class ProcessMemoryUnavailable(RuntimeError):
    def __init__(self, message, diagnostics):
        super().__init__(message)
        self.diagnostics = diagnostics


class ProcessMemoryCollector:
    def __init__(self, cancel=None, progress=None, proc_root='/proc'):
        self.cancel = cancel or Event()
        self.progress = progress or (lambda value: None)
        self.proc_root = Path(proc_root)
        self.diagnostics = []
        self.captured_bytes = 0
        self.last_progress = 0
        self.boot_context = boot_context(self.proc_root)

    def check_cancelled(self):
        if self.cancel.is_set():
            raise MemoryCancelled()

    def log(self, pid, message, level='warning', **details):
        self.diagnostics.append({'time': datetime.now(timezone.utc).isoformat(),
                                 'pid': pid, 'path': f'/proc/{pid}', 'level': level, 'message': str(message), **details})

    def read_text(self, directory, name):
        data, truncated = read_bytes(directory, name, 4 * 1024 * 1024)
        if truncated:
            raise ValueError(f'Process {name} metadata exceeds 4 MiB read bound')
        return data.decode('utf-8', errors='replace')

    def identity(self, directory):
        text = self.read_text(directory, 'stat')
        # comm may contain spaces and parentheses; starttime is field 22.
        return text[text.rfind(')') + 2:].split()[19]

    def collect_process(self, archive, pid):
        process = dict(pid=pid, regions=[], captured_bytes=0, acquired_at=utc_now())
        process_started = time.monotonic_ns()
        try:
            directory = os.open(self.proc_root / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError as error:
            raise ProcessAccessUnavailable(str(error), process, 'open_process_directory', error.errno) from error
        try:
            operation = 'read_process_identity'
            try:
                identity = self.identity(directory)
                process['starttime_ticks'] = identity
                process.update(process_details(directory, identity, self.boot_context))
                for field in ('executable', 'command_line', 'start_time'):
                    if process[field]['status'] == 'unavailable':
                        self.log(pid, f"Process {field} unavailable: {process[field].get('error')}",
                                 operation=field, errno=process[field].get('errno'))
                operation = 'read_memory_maps'
                maps = self.read_text(directory, 'maps')
                process['maps_observed_at'] = utc_now()
                process['mappings'] = [mapping(line, index) for index, line in enumerate(maps.splitlines()) if line.strip()]
                operation = 'open_process_memory'
                memory = os.open('mem', os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
            except (OSError, ValueError, IndexError) as error:
                process['completed_at'] = utc_now()
                raise ProcessAccessUnavailable(str(error), process, operation, getattr(error, 'errno', None)) from error
            try:
                for mapped in process['mappings']:
                    if self.cancel.is_set():
                        break
                    if mapped['capture_status'] == 'not_readable':
                        continue
                    index, line = mapped['index'], mapped['raw']
                    start, end = mapped['start'], mapped['end_exclusive']
                    region_started = time.monotonic_ns()
                    name = f'processes/{pid}/regions/{index:06d}-{start:x}-{end:x}.bin'
                    region = {'start': start, 'end_exclusive': end, 'permissions': mapped['permissions'], 'mapping_index': index,
                              'file_offset': mapped['file_offset'], 'device': mapped['device'],
                              'inode': mapped['inode'], 'pathname': mapped['pathname'],
                              'acquired_at': utc_now(), 'gaps': [], 'read_attempt_errors': 0,
                              'mapping': line, 'archive_path': name, 'segments': [], 'captured_bytes': 0,
                              'unreadable_bytes': 0, 'read_errors': 0}
                    digest = hashlib.sha256()
                    address = start
                    with archive.open(name, 'w', force_zip64=True) as output:
                        while address < end:
                            if self.cancel.is_set():
                                break
                            length = min(1024 * 1024, end - address)
                            read_error = None
                            try:
                                data = os.pread(memory, length, address)
                            except OSError as error:
                                region['read_attempt_errors'] += 1
                                read_error = error
                                # A large read may cross an inaccessible page. Retry
                                # page by page so later readable data is still captured.
                                length = min(4096 - address % 4096, end - address)
                                try:
                                    data = os.pread(memory, length, address)
                                except OSError as error:
                                    region['read_attempt_errors'] += 1
                                    read_error = error
                                    data = b''
                            if not data:
                                gap = dict(virtual_start=address, length=length,
                                           errno=getattr(read_error, 'errno', None),
                                           reason=str(read_error) if read_error else 'Read returned no bytes')
                                gaps = region['gaps']
                                if gaps and gaps[-1]['virtual_start'] + gaps[-1]['length'] == address and all(gaps[-1][key] == gap[key] for key in ('errno', 'reason')):
                                    gaps[-1]['length'] += length
                                else:
                                    gaps.append(gap)
                                region['unreadable_bytes'] += length
                                region['read_errors'] += 1
                                address += length
                                continue
                            offset = region['captured_bytes']
                            segments = region['segments']
                            if segments and segments[-1]['virtual_start'] + segments[-1]['length'] == address:
                                segments[-1]['length'] += len(data)
                            else:
                                segments.append({'virtual_start': address, 'file_offset': offset, 'length': len(data)})
                            output.write(data)
                            digest.update(data)
                            region['captured_bytes'] += len(data)
                            process['captured_bytes'] += len(data)
                            self.captured_bytes += len(data)
                            address += len(data)
                            now = time.monotonic()
                            if now - self.last_progress >= 0.1:
                                self.progress({'phase': f'Acquiring accessible process memory · PID {pid}',
                                               'bytes': self.captured_bytes, 'total': 0})
                                self.last_progress = now
                    region['completed_at'] = utc_now()
                    region['duration_ns'] = time.monotonic_ns() - region_started
                    region['sha256'] = digest.hexdigest()
                    region['complete'] = region['captured_bytes'] == end - start
                    region['not_attempted_bytes'] = end - address
                    region['not_attempted_ranges'] = ([dict(virtual_start=address, length=end - address,
                                                            reason='Acquisition stopped')]
                                                      if address < end else [])
                    region['stopped'] = self.cancel.is_set()
                    if not region['complete']:
                        self.log(pid, f"Mapping {start:x}-{end:x}: {region['unreadable_bytes']} bytes unreadable; {region['read_errors']} read failures; {region['not_attempted_bytes']} bytes not attempted after stop.")
                    mapped['capture_status'] = 'captured' if region['complete'] else 'partial'
                    mapped['archive_path'] = name
                    process['regions'].append(region)
                process['identity_checked_at'] = utc_now()
                try:
                    process['identity_verified_after_capture'] = self.identity(directory) == identity
                    process['identity_check_status'] = 'available'
                except (OSError, ValueError, IndexError) as error:
                    process['identity_verified_after_capture'] = False
                    process['identity_check_status'] = 'unavailable'
                    self.log(pid, 'Post-acquisition identity unavailable: ' + str(error), operation='verify_identity', errno=getattr(error, 'errno', None))
                process['maps_checked_at'] = utc_now()
                try:
                    maps_after = self.read_text(directory, 'maps')
                    process['maps_changed_during_capture'] = maps_after != maps
                    process['maps_check_status'] = 'available'
                    if maps_after != maps:
                        process['maps_after'] = maps_after
                        process['mapping_changes'] = dict(added=sorted(set(maps_after.splitlines()) - set(maps.splitlines())),
                                                          removed=sorted(set(maps.splitlines()) - set(maps_after.splitlines())))
                except (OSError, ValueError) as error:
                    process['maps_changed_during_capture'] = None
                    process['maps_check_status'] = 'unavailable'
                    self.log(pid, 'Post-acquisition mappings unavailable: ' + str(error), operation='verify_maps', errno=getattr(error, 'errno', None))
                process['executable_after'] = executable(directory)
                process['command_line_after'] = command_line(directory)
                process['executable_changed_during_capture'] = changed(process['executable'], process['executable_after'], ('path', 'device', 'inode', 'size', 'mtime_ns', 'ctime_ns'))
                process['command_line_changed_during_capture'] = changed(process['command_line'], process['command_line_after'], ('raw_hex', 'truncated'))
                for field in ('executable_after', 'command_line_after'):
                    if process[field]['status'] == 'unavailable':
                        self.log(pid, f"Process {field} unavailable: {process[field]['error']}", operation=field, errno=process[field].get('errno'))
                if not process['identity_verified_after_capture'] or process['maps_changed_during_capture'] is not False or process['executable_changed_during_capture'] or process['command_line_changed_during_capture']:
                    self.log(pid, 'Process identity, mappings or context changed/unavailable during live acquisition; consult the process metadata.')
                process['completed_at'] = utc_now()
                process['duration_ns'] = time.monotonic_ns() - process_started
                for mapped in process['mappings']:
                    if mapped['capture_status'] == 'not_attempted' and self.cancel.is_set():
                        mapped['capture_status'] = 'not_attempted_after_stop'
            finally:
                os.close(memory)
            return process
        finally:
            os.close(directory)

    def acquire(self, destination):
        if platform.system() != 'Linux':
            raise RuntimeError('Accessible process memory acquisition supports Linux.')
        destination = Path(os.path.abspath(destination))
        if destination.suffix.lower() != '.zip':
            raise ValueError('Without root, choose a .zip destination for partial process-memory capture; it is not a LiME physical image.')
        self.check_cancelled()
        started = datetime.now(timezone.utc).isoformat()
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        reserved = os.fstat(descriptor)
        os.close(descriptor)
        published = False
        try:
            with tempfile.TemporaryDirectory(prefix='.terra-process-ram-', dir=destination.parent) as work:
                image = Path(work) / 'process-memory.zip'
                processes = []
                unavailable_processes = []
                excluded_processes = []
                skipped = 0
                with zipfile.ZipFile(image, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                    for entry in sorted(self.proc_root.iterdir(), key=lambda path: path.name):
                        if self.cancel.is_set():
                            break
                        if not entry.name.isdigit():
                            continue
                        pid = int(entry.name)
                        if pid == os.getpid():
                            self.log(pid, 'TERRA itself excluded from process-memory evidence.', 'info')
                            excluded_processes.append(dict(pid=pid, reason='TERRA collector excluded'))
                            skipped += 1
                            continue
                        self.progress({'phase': f'Checking process memory access · PID {pid}',
                                       'bytes': self.captured_bytes, 'total': 0})
                        try:
                            process = self.collect_process(archive, pid)
                        except (ProcessAccessUnavailable, ValueError, IndexError) as error:
                            operation = getattr(error, 'operation', None)
                            error_number = getattr(error, 'error_number', None)
                            self.log(pid, f'Process memory unavailable or process exited: {error}', operation=operation, errno=error_number)
                            unavailable_processes.append(dict(getattr(error, 'context', {}) or {'pid': pid},
                                access_status='denied' if error_number in (1, 13) else 'unavailable',
                                access_error=str(error), access_errno=error_number, failed_operation=operation))
                            skipped += 1
                            continue
                        if process['captured_bytes']:
                            processes.append(process)
                        else:
                            self.log(pid, 'No readable memory bytes acquired.')
                            unavailable_processes.append(dict(process, access_status='no_readable_bytes'))
                            skipped += 1
                    if not processes:
                        if self.cancel.is_set():
                            raise MemoryCancelled()
                        raise ProcessMemoryUnavailable('No other process memory was accessible with current privileges. No RAM capture was saved. Root permits more comprehensive acquisition; kernel restrictions may still apply.', self.diagnostics)
                    manifest = {'format': 'terra-process-memory', 'format_version': 2,
                                'memory_scope': 'accessible_process_memory', 'complete_physical_ram': False,
                                'byte_count_scope': 'sum_of_copied_process_virtual_memory_bytes_not_unique_physical_ram',
                                'acquisition_stopped': self.cancel.is_set(),
                                'acquired_at': started, 'uid': os.geteuid(), 'captured_bytes': self.captured_bytes,
                                'process_count': len(processes), 'skipped_processes': skipped,
                                'processes': processes, 'unavailable_processes': unavailable_processes,
                                'excluded_processes': excluded_processes, 'boot_context': self.boot_context,
                                'timing_note': 'UTC times bracket live reads; duration_ns uses a monotonic clock. Processes are not paused; no simultaneous snapshot is claimed.',
                                'diagnostics': self.diagnostics,
                                'limitations': 'Live virtual process memory only. Captured bytes sum every copied virtual mapping; shared/aliased pages may repeat, and readable mappings need not have been resident before capture. This total can exceed installed RAM and is not unique physical RAM coverage. Kernel, inaccessible processes and unmapped physical memory are omitted. Processes are not paused. Gaps are not zero-filled; segments map file offsets to virtual addresses.'}
                self.progress({'phase': 'Verifying partial process-memory archive', 'bytes': 0, 'total': image.stat().st_size})
                verified_bytes = 0
                last_progress = 0
                with zipfile.ZipFile(image) as archive:
                    # Stream every member for CRC verification, without buffering dumps.
                    for name in archive.namelist():
                        with archive.open(name) as source:
                            while chunk := source.read(1024 * 1024):
                                verified_bytes += len(chunk)
                                now = time.monotonic()
                                if now - last_progress >= 0.1:
                                    self.progress({'phase': 'Verifying partial process-memory archive',
                                                   'bytes': verified_bytes, 'total': image.stat().st_size})
                                    last_progress = now
                manifest['acquisition_stopped'] = self.cancel.is_set()
                manifest['completed_at'] = utc_now()
                with zipfile.ZipFile(image, 'a', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                    archive.writestr('logs/diagnostics.jsonl', ''.join(json.dumps(entry) + '\n' for entry in self.diagnostics))
                    archive.writestr('logs/acquisition.log', ''.join(f"{entry.get('time', '')} [{entry.get('level', '')}] PID {entry.get('pid', '')}: {entry.get('message', '')}\n" for entry in self.diagnostics))
                    archive.writestr('manifest.json', json.dumps(manifest, indent=2).encode())
                    archive.writestr('README.txt', 'Partial Linux process-memory capture, not a physical RAM image.\nCaptured byte totals sum copied process virtual mappings, including repeated shared pages; they can exceed installed RAM and do not measure unique physical RAM coverage.\nRaw region bytes are under processes/. manifest.json includes process executable/argv context, derived start times, structured mappings, per-region acquisition times, virtual-address segments, explicit gaps and errors. unavailable_processes are metadata-only records, not collected memory. Unknown change checks are null rather than proof of unchanged context.\nImport individual raw regions into tools supporting process memory and use the manifest for address mapping. Do not import this ZIP as a LiME image.\n')
                digest = hashlib.sha256()
                hashed_bytes = 0
                last_progress = 0
                with open(image, 'rb') as source:
                    while chunk := source.read(1024 * 1024):
                        digest.update(chunk)
                        hashed_bytes += len(chunk)
                        now = time.monotonic()
                        if now - last_progress >= 0.1:
                            self.progress({'phase': 'Hashing partial process-memory archive',
                                           'bytes': hashed_bytes, 'total': image.stat().st_size})
                            last_progress = now
                    os.fsync(source.fileno())
                current = os.stat(destination, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (reserved.st_dev, reserved.st_ino):
                    raise OSError('Destination changed during acquisition; it was not overwritten.')
                os.chmod(image, 0o600)
                os.replace(image, destination)
                published = True
                info = destination.stat()
                return {'path': str(destination), 'size': info.st_size, 'sha256': digest.hexdigest(),
                        'kind': 'file', 'category': 'Process Memory (Partial)', 'matches': {},
                        'memory_image': True, 'memory_scope': 'accessible_process_memory',
                        'complete_physical_ram': False, 'acquisition_stopped': self.cancel.is_set(),
                        'captured_bytes': self.captured_bytes,
                        'byte_count_scope': 'sum_of_copied_process_virtual_memory_bytes_not_unique_physical_ram',
                        'process_count': len(processes), 'skipped_processes': skipped,
                        'acquisition_diagnostics': self.diagnostics, 'content_retained': False,
                        'collection': 'partial accessible process memory (ZIP with raw regions and manifest)',
                        'acquired_at': started, 'completed_at': datetime.now(timezone.utc).isoformat(),
                        'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns,
                        'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode}
        finally:
            if not published:
                try:
                    current = os.stat(destination, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (reserved.st_dev, reserved.st_ino):
                        destination.unlink()
                except FileNotFoundError:
                    pass
