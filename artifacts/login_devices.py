"""Live login boundaries and read-only boot-scoped device-event observations."""
import ctypes
import errno
import hashlib
import os
import re
import stat
import time
from pathlib import Path

from analyzers.device_timeline import correlate, match_present_devices
from artifacts.devices import usb_event
from artifacts.os_activity.parser import parse as parse_os
from artifacts.os_activity.journal import checked
from artifacts.parser_support import check_cancelled, utc_time

SESSION_START = '8d45620c1a4348dbb17410da57c60c66'
SESSION_STOP = '3354939424b4456d9802ca8333ed424a'
SOURCES = [
    'https://man7.org/linux/man-pages/man5/utmp.5.html',
    'https://github.com/systemd/systemd/blob/main/src/login/logind-session.c',
    'https://www.freedesktop.org/software/systemd/man/latest/sd_journal_get_realtime_usec.html',
    'https://www.freedesktop.org/software/systemd/man/latest/sd_journal_open.html',
    'https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/dev-kmsg',
]


def regular_snapshot(path, cancelled, limit=1024 * 1024):
    """Bounded stable regular-file snapshot; no special files or symlink parents."""
    path = Path(path)
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.absolute().parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            descriptor = os.open(path.name, flags | getattr(os, 'O_NOATIME', 0), dir_fd=directory)
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EACCES, errno.EINVAL):
                raise
            descriptor = os.open(path.name, flags, dir_fd=directory)
        with os.fdopen(descriptor, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError('Session source is not a bounded regular file')
            output = bytearray()
            while chunk := source.read(min(65536, limit + 1 - len(output))):
                check_cancelled(cancelled)
                output.extend(chunk)
                if len(output) > limit:
                    raise ValueError('Session source exceeds snapshot limit')
            after = os.fstat(source.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(output) != before.st_size:
                raise ValueError('Session source changed during snapshot')
            data = bytes(output)
            return data, dict(path=str(path), size=len(data), sha256=hashlib.sha256(data).hexdigest())
    finally:
        os.close(directory)


def session_state(data, path, boot_id):
    fields = {}
    for line in data.decode('utf-8', errors='strict').splitlines():
        if not line or line.startswith('#'):
            continue
        name, separator, value = line.partition('=')
        if not separator or name in fields:
            raise ValueError('Unsupported logind session state layout')
        # Never evaluate/shell-source this private, version-dependent state format.
        fields[name] = value.strip().strip('"')
    if not fields.get('UID', '').isdigit():
        raise ValueError('Logind session has no valid UID')
    realtime = int(fields['REALTIME']) if fields.get('REALTIME') else None
    monotonic = int(fields['MONOTONIC']) if fields.get('MONOTONIC') else None
    if any(value is not None and value < 0 for value in (realtime, monotonic)):
        raise ValueError('Invalid login timestamp')
    return dict(type='login_session', locator=str(path), session_id='logind:' + Path(path).name,
                logind_session_id=Path(path).name, boot_id=boot_id,
                uid=int(fields['UID']), username=fields.get('USER'), leader_pid=fields.get('LEADER'),
                terminal=fields.get('TTY'), seat=fields.get('SEAT'), remote=fields.get('REMOTE'),
                session_class=fields.get('CLASS', 'user'), session_type=fields.get('TYPE'),
                state=fields.get('STATE'), active=fields.get('ACTIVE') in ('1', 'yes'),
                present_at_snapshot=fields.get('STATE') in ('active', 'online'),
                start_realtime_usec=realtime, start_monotonic_usec=monotonic,
                start_timestamp_utc=utc_time(realtime, 1000000), raw_state=fields,
                note='Read-only logind private state snapshot; ACTIVE refers to foreground seat state, not whether a user remains logged in')


class Id128(ctypes.Structure):
    _fields_ = [('bytes', ctypes.c_ubyte * 16)]


def journal_library():
    lib = ctypes.CDLL('libsystemd.so.0')
    pointer = ctypes.c_void_p
    signatures = {
        'sd_journal_open': ([ctypes.POINTER(pointer), ctypes.c_int], ctypes.c_int),
        'sd_journal_close': ([pointer], None),
        'sd_journal_add_match': ([pointer, pointer, ctypes.c_size_t], ctypes.c_int),
        'sd_journal_seek_head': ([pointer], ctypes.c_int),
        'sd_journal_next': ([pointer], ctypes.c_int),
        'sd_journal_get_data': ([pointer, ctypes.c_char_p, ctypes.POINTER(pointer), ctypes.POINTER(ctypes.c_size_t)], ctypes.c_int),
        'sd_journal_get_realtime_usec': ([pointer, ctypes.POINTER(ctypes.c_uint64)], ctypes.c_int),
        'sd_journal_get_monotonic_usec': ([pointer, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(Id128)], ctypes.c_int),
        'sd_journal_set_data_threshold': ([pointer, ctypes.c_size_t], ctypes.c_int),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(lib, name)
        function.argtypes, function.restype = arguments, result
    return lib


def journal_rows(boot_id, cancelled, coverage, deadline_seconds=30, max_records=250000):
    """Read only local journal kernel/session entries from the observed boot."""
    if not re.fullmatch(r'[0-9a-fA-F]{32}', (boot_id or '').replace('-', '')):
        raise ValueError('A valid boot ID is required for live journal correlation')
    lib = journal_library()
    deadline = time.monotonic() + deadline_seconds
    total = 0
    for filters in (('_TRANSPORT=kernel',), ('MESSAGE_ID=' + SESSION_START, 'MESSAGE_ID=' + SESSION_STOP)):
        journal = ctypes.c_void_p()
        observation = dict(source='local_systemd_journal', filters=list(filters), boot_id=boot_id,
                           status='observed', entries_examined=0,
                           completeness='Accessible retained entries only; no completeness or sealing guarantee')
        coverage.append(observation)
        try:
            checked(lib.sd_journal_open(ctypes.byref(journal), 1))  # LOCAL_ONLY; no daemon/remote connection.
            checked(lib.sd_journal_set_data_threshold(journal, 1024 * 1024 + 1))
            for match in ('_BOOT_ID=' + boot_id.replace('-', ''), *filters):
                raw = match.encode('ascii')
                checked(lib.sd_journal_add_match(journal, ctypes.c_char_p(raw), len(raw)))
            if filters[0].startswith('MESSAGE_ID='):
                raw = b'_SYSTEMD_UNIT=systemd-logind.service'
                checked(lib.sd_journal_add_match(journal, ctypes.c_char_p(raw), len(raw)))
            checked(lib.sd_journal_seek_head(journal))
            while checked(lib.sd_journal_next(journal)):
                check_cancelled(cancelled)
                if total >= max_records or time.monotonic() >= deadline:
                    observation.update(status='partial', limitation='Journal observation time/entry budget reached')
                    return
                total += 1
                observation['entries_examined'] += 1
                fields = {}
                for name in ('MESSAGE', 'MESSAGE_ID', 'SESSION_ID', 'USER_ID', 'LEADER', 'CLASS', 'TYPE',
                             '_TRANSPORT', '_BOOT_ID', '_HOSTNAME', 'SYSLOG_IDENTIFIER',
                             '_SOURCE_MONOTONIC_TIMESTAMP', '_SOURCE_BOOTTIME_TIMESTAMP', '_MACHINE_ID', '_SYSTEMD_UNIT'):
                    value, size = ctypes.c_void_p(), ctypes.c_size_t()
                    result = lib.sd_journal_get_data(journal, name.encode(), ctypes.byref(value), ctypes.byref(size))
                    if result == -errno.ENOENT:
                        continue
                    checked(result)
                    if size.value > 1024 * 1024:
                        raise ValueError('Journal field exceeds observation bound')
                    fields[name] = ctypes.string_at(value, size.value).partition(b'=')[2].decode('utf-8', errors='replace')
                realtime, monotonic, observed_boot = ctypes.c_uint64(), ctypes.c_uint64(), Id128()
                checked(lib.sd_journal_get_realtime_usec(journal, ctypes.byref(realtime)))
                checked(lib.sd_journal_get_monotonic_usec(journal, ctypes.byref(monotonic), ctypes.byref(observed_boot)))
                entry_boot = bytes(observed_boot.bytes).hex()
                if entry_boot != boot_id.replace('-', '').lower():
                    raise ValueError('Journal boot identity does not agree with requested boot')
                # Retain identifying source fields and both clocks, independent of locale/date inference.
                source_monotonic = fields.get('_SOURCE_MONOTONIC_TIMESTAMP', '')
                yield dict(fields=fields, boot_id=entry_boot, machine_id=fields.get('_MACHINE_ID'),
                           monotonic_usec=int(source_monotonic) if source_monotonic.isdigit() else monotonic.value,
                           journal_receipt_monotonic_usec=monotonic.value,
                           event_clock='kernel_source_monotonic' if source_monotonic.isdigit() else 'journal_receipt_monotonic',
                           timestamp_raw_usec=realtime.value, timestamp_utc=utc_time(realtime.value, 1000000),
                           monotonic_semantics='Journal receipt timestamp; delayed delivery can affect ordering near login boundaries',
                           locator=f'journal://{entry_boot}/{monotonic.value}/{realtime.value}/{total}')
            if not observation['entries_examined']:
                observation.update(status='empty_or_inaccessible',
                                   limitation='No readable matching entries; absence and access restrictions cannot be distinguished')
        except (OSError, ValueError, AttributeError) as error:
            observation.update(status='partial' if observation['entries_examined'] else 'unavailable',
                               error=str(error), limitation=str(error))
            raise
        finally:
            if journal.value:
                lib.sd_journal_close(journal)


def session_events(rows):
    sessions = {}
    for row in sorted(rows, key=lambda item: (item['boot_id'], item.get('monotonic_usec') or item['timestamp_raw_usec'])):
        fields = row['fields']
        session_id = fields.get('SESSION_ID')
        if not session_id:
            continue
        key = (row['boot_id'], session_id)
        if fields.get('MESSAGE_ID') == SESSION_START:
            if key in sessions:
                # Do not silently merge a reused ID with a prior login interval.
                sessions[(row['boot_id'], session_id, row['locator'])] = sessions.pop(key)
            sessions[key] = dict(type='login_session', locator=row['locator'], session_id='logind:' + session_id,
                logind_session_id=session_id, username=fields.get('USER_ID'), leader_pid=fields.get('LEADER'),
                boot_id=row['boot_id'], machine_id=row.get('machine_id'), session_class=fields.get('CLASS', 'user'), session_type=fields.get('TYPE'),
                start_monotonic_usec=row.get('monotonic_usec'), start_realtime_usec=row['timestamp_raw_usec'],
                start_timestamp_utc=row['timestamp_utc'], present_at_snapshot=False, evidence_events=[row],
                source_sha256=row.get('source_sha256'))
        elif fields.get('MESSAGE_ID') == SESSION_STOP and key in sessions:
            sessions[key].update(end_monotonic_usec=row.get('monotonic_usec'), end_realtime_usec=row['timestamp_raw_usec'],
                                 end_timestamp_utc=row['timestamp_utc'], end_semantics='logind session removal; user logout may have occurred earlier')
            sessions[key]['evidence_events'].append(row)
    return list(sessions.values())


def kmsg_rows(path, boot_id, cancelled, observation, max_records=250000, deadline_seconds=10):
    """Nonblocking read of retained printk records; never clear or consume /proc/kmsg."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    deadline = time.monotonic() + deadline_seconds
    previous = None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISCHR(info.st_mode) or (os.major(info.st_rdev), os.minor(info.st_rdev)) != (1, 11):
            raise ValueError('Kernel log source is not the expected /dev/kmsg device')
        observation.update(status='observed', entries_examined=0, gaps=[],
                           completeness='Retained ring-buffer records only; earlier messages may have been overwritten')
        while True:
            check_cancelled(cancelled)
            if observation['entries_examined'] >= max_records or time.monotonic() >= deadline:
                observation.update(status='partial', limitation='Kernel ring observation time/entry budget reached')
                return
            try:
                raw = os.read(descriptor, 1024 * 1024)
            except BlockingIOError:
                break
            except OSError as error:
                if error.errno == errno.EPIPE:
                    observation['gaps'].append('Ring overwritten while reading')
                    continue
                raise
            if not raw:
                break
            observation['entries_examined'] += 1
            header, separator, message = raw.partition(b';')
            fields = header.split(b',')
            if not separator or len(fields) < 4:
                raise ValueError('Malformed kernel ring record')
            priority, sequence, monotonic = (int(value) for value in fields[:3])
            if previous is not None and sequence != previous + 1:
                observation['gaps'].append(dict(previous_sequence=previous, next_sequence=sequence))
            previous = sequence
            # LOG_KERN only; user-injected messages cannot use facility zero.
            if priority >> 3 != 0:
                continue
            text = message.split(b'\n', 1)[0].decode('utf-8', errors='replace')
            event = usb_event(text)
            if event:
                yield dict(event, type='device_connection_event', locator=f'{path}:sequence:{sequence}',
                    boot_id=boot_id, monotonic_usec=monotonic, timestamp_utc=None, sequence=sequence,
                    fields={'MESSAGE': text}, raw_kernel_record=raw.decode('utf-8', errors='replace'),
                    timestamp_note='Kernel monotonic clock; UTC is not inferred from current wall clock')
    finally:
        os.close(descriptor)


class LoginDeviceCollector:
    def __init__(self, collector, journal_reader=None):
        self.collector = collector
        self.journal_reader = journal_reader
        # Alternate proc roots are fixture/offline metadata roots, never permission to read host sessions.
        self.root = Path('/') if str(collector.proc) == '/proc' else collector.proc.parent

    def collect(self, boot_id, devices):
        collector = self.collector
        coverage, sessions, events, journal_sessions = [], [], [], []
        directory = self.root / 'run/systemd/sessions'
        try:
            names = sorted(directory.iterdir())
        except OSError as error:
            collector.warn(directory, error)
            names = []
            coverage.append(dict(source=str(directory), status='unavailable', error=str(error)))
        for path in names:
            check_cancelled(collector.cancelled)
            collector.progress(str(path))
            try:
                data, source = regular_snapshot(path, collector.cancelled)
                session = session_state(data, path, boot_id)
                session['source_snapshot'] = source
                sessions.append(session)
                coverage.append(dict(source=str(path), status='observed'))
            except (OSError, ValueError) as error:
                collector.warn(path, error)
                coverage.append(dict(source=str(path), status='unavailable', error=str(error)))
        # utmp covers terminal sessions on non-systemd systems and supplements logind.
        for path in (self.root / 'run/utmp', self.root / 'var/run/utmp'):
            try:
                data, source = regular_snapshot(path, collector.cancelled, 16 * 1024 * 1024)
                rows = list(parse_os('utmp', data, str(path), collector.cancelled))
                additions = []
                for row in rows:
                    if row['record_type'] != 'user_process':
                        continue
                    if any(str(session.get('leader_pid')) == str(row['pid']) for session in sessions):
                        continue
                    seconds, micros = row['timestamp_raw']
                    if seconds <= 0 or not 0 <= micros < 1000000:
                        raise ValueError('Invalid utmp login timestamp')
                    additions.append(dict(type='login_session', locator=str(path) + ':' + row['locator'],
                        session_id=f"utmp:{row['pid']}:{row['terminal']}:{seconds}:{micros}",
                        username=row['username'], terminal=row['terminal'], leader_pid=row['pid'],
                        boot_id=boot_id, present_at_snapshot=True, start_realtime_usec=seconds * 1000000 + micros,
                        start_timestamp_utc=row['timestamp_utc'], source_snapshot=source, raw_record=row,
                        note='utmp USER_PROCESS observation; wall-clock ordering only, record may be stale'))
                sessions.extend(additions)
                coverage.append(dict(source=str(path), status='observed', records=len(rows)))
                break
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as error:
                collector.warn(path, error)
                coverage.append(dict(source=str(path), status='unavailable', error=str(error)))
        # Host journals are opt-in through the existing collect_live option, not recursive target reads.
        if self.root == Path('/') or self.journal_reader is not None:
            try:
                for row in (self.journal_reader or journal_rows)(boot_id, collector.cancelled, coverage):
                    check_cancelled(collector.cancelled)
                    fields = row['fields']
                    event = usb_event(fields.get('MESSAGE', '')) if fields.get('_TRANSPORT') == 'kernel' else None
                    if event:
                        events.append(dict(row, **event, type='device_connection_event'))
                    elif fields.get('MESSAGE_ID') in (SESSION_START, SESSION_STOP):
                        journal_sessions.append(row)
            except (OSError, ValueError, AttributeError) as error:
                collector.warn('Live device journal', error)
                if not coverage or coverage[-1]['status'] != 'unavailable':
                    coverage.append(dict(source='local_systemd_journal', status='unavailable', error=str(error)))
            # Independent retained ring snapshot supplements missing/inaccessible journal kernels.
            kernel_seen = any(item.get('filters') == ['_TRANSPORT=kernel'] and item.get('entries_examined', 0)
                              for item in coverage)
            if not kernel_seen and self.root == Path('/'):
                observation = dict(source='/dev/kmsg', status='unavailable')
                coverage.append(observation)
                try:
                    events.extend(kmsg_rows('/dev/kmsg', boot_id, collector.cancelled, observation))
                except (OSError, ValueError) as error:
                    observation.update(status='unavailable', error=str(error))
                    collector.warn('/dev/kmsg', error)
        machines = {row.get('machine_id') for row in events + journal_sessions if row.get('machine_id')}
        if len(machines) == 1:
            machine = next(iter(machines))
            for session in sessions:
                session['machine_id'] = machine
        for historical in session_events(journal_sessions):
            existing = next((session for session in sessions if session['session_id'] == historical['session_id']), None)
            if existing:
                existing['evidence_events'] = historical['evidence_events']
                for key in ('end_monotonic_usec', 'end_realtime_usec', 'end_timestamp_utc', 'end_semantics'):
                    if key in historical:
                        existing[key] = historical[key]
            else:
                sessions.append(historical)
        events.sort(key=lambda row: row.get('monotonic_usec', 0))
        events = correlate(events, sessions, collector.cancelled)
        devices = match_present_devices(devices, events, collector.cancelled)
        for observation in coverage:
            if observation['status'] in ('partial', 'empty_or_inaccessible'):
                collector.warn(observation['source'], observation['limitation'])
        return sessions, devices + events, coverage
