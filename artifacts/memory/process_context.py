"""Bounded, read-only process metadata; never execute the discovered executable."""
import os
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_bytes(directory, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(fd, 'rb') as source:
        data = source.read(limit + 1)
    return data[:limit], len(data) > limit


def optional(operation):
    observed = utc_now()
    try:
        return dict(operation(), status='available', observed_at=observed)
    except (OSError, ValueError, IndexError) as error:
        return dict(status='unavailable', observed_at=observed, error=str(error), errno=getattr(error, 'errno', None))


def command_line(directory):
    def collect():
        data, truncated = read_bytes(directory, 'cmdline', 65536)
        arguments = data.split(b'\0')
        if arguments and arguments[-1] == b'':
            arguments.pop()
        return dict(argv=[value.decode('utf-8', errors='replace') for value in arguments] if data else [],
                    raw_hex=data.hex(), truncated=truncated,
                    note='Observed argv bytes; processes can modify cmdline. Empty does not mean access denied.')
    return optional(collect)


def executable(directory):
    def collect():
        target = os.readlink('exe', dir_fd=directory)
        info = os.stat('exe', dir_fd=directory)
        return dict(path=target, device=info.st_dev, inode=info.st_ino,
                    size=info.st_size, mode=info.st_mode, mtime_ns=info.st_mtime_ns,
                    ctime_ns=info.st_ctime_ns, deleted=target.endswith(' (deleted)'),
                    note='Kernel exe link and backing-file metadata; executable bytes are not run or hashed.')
    return optional(collect)


def boot_context(proc_root):
    def collect():
        directory = os.open(proc_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            data, truncated = read_bytes(directory, 'stat', 1024 * 1024)
            if truncated:
                raise ValueError('Boot metadata exceeds read bound')
            seconds = next(int(line.split()[1]) for line in data.decode().splitlines() if line.startswith('btime '))
            ticks = os.sysconf('SC_CLK_TCK')
            if ticks <= 0:
                raise ValueError('Invalid clock tick frequency')
            return dict(boot_time_unix_seconds=seconds, clock_ticks_per_second=ticks,
                        note='Start UTC is derived from proc btime and starttime ticks; approximate wall-clock time.')
        except StopIteration:
            raise ValueError('Boot time is unavailable') from None
        finally:
            os.close(directory)
    return optional(collect)


def process_details(directory, start_ticks, boot):
    result = dict(executable=executable(directory), command_line=command_line(directory),
                  start_time=dict(starttime_ticks=start_ticks, utc=None, status='unavailable'))
    if boot.get('status') == 'available':
        try:
            timestamp = boot['boot_time_unix_seconds'] + int(start_ticks) / boot['clock_ticks_per_second']
            result['start_time'].update(utc=datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
                                        status='derived', clock_ticks_per_second=boot['clock_ticks_per_second'],
                                        boot_time_unix_seconds=boot['boot_time_unix_seconds'], note=boot['note'])
        except (ValueError, OverflowError, OSError) as error:
            result['start_time']['error'] = str(error)
    else:
        result['start_time']['error'] = boot.get('error', 'Boot metadata unavailable')
    return result


def mapping(line, index):
    fields = line.split(maxsplit=5)
    if len(fields) < 5:
        raise ValueError('Invalid process memory mapping')
    start, end = (int(value, 16) for value in fields[0].split('-'))
    if end <= start or start < 0:
        raise ValueError('Invalid process memory mapping range')
    return dict(index=index, raw=line, start=start, end_exclusive=end, permissions=fields[1],
                file_offset=int(fields[2], 16), device=fields[3], inode=int(fields[4]),
                pathname=fields[5] if len(fields) > 5 else None,
                capture_status='not_attempted' if fields[1].startswith('r') else 'not_readable')


def changed(before, after, fields):
    if before.get('status') != 'available' or after.get('status') != 'available':
        return None
    return any(before.get(key) != after.get(key) for key in fields)
