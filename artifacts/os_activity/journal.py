"""Read journals with host libsystemd, validating all derived source bytes."""
import ctypes
import errno
import fcntl
import os
import stat

from artifacts.parser_support import ParseError, check_cancelled, entry, utc_time, read_verified
from artifacts.devices import usb_event


class Id128(ctypes.Structure):
    _fields_ = [('bytes', ctypes.c_ubyte * 16)]


def library():
    try:
        lib = ctypes.CDLL('libsystemd.so.0')
        pointer = ctypes.c_void_p
        signatures = {
            'sd_journal_open_files_fd': ([ctypes.POINTER(pointer), ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_int], ctypes.c_int),
            'sd_journal_close': ([pointer], None),
            'sd_journal_seek_head': ([pointer], ctypes.c_int),
            'sd_journal_next': ([pointer], ctypes.c_int),
            'sd_journal_restart_data': ([pointer], None),
            'sd_journal_enumerate_data': ([pointer, ctypes.POINTER(pointer), ctypes.POINTER(ctypes.c_size_t)], ctypes.c_int),
            'sd_journal_get_realtime_usec': ([pointer, ctypes.POINTER(ctypes.c_uint64)], ctypes.c_int),
            'sd_journal_get_monotonic_usec': ([pointer, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(Id128)], ctypes.c_int),
            'sd_journal_set_data_threshold': ([pointer, ctypes.c_size_t], ctypes.c_int),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(lib, name)
            function.argtypes, function.restype = arguments, result
        return lib
    except (OSError, AttributeError) as error:
        raise ParseError('Host libsystemd journal API unavailable; raw journal remains available') from error


def checked(value):
    if value < 0:
        raise ParseError('libsystemd journal read failed: ' + os.strerror(-value))
    return value


def parse(data, cancelled, path=None, metadata=None, directory_fd=None):
    if len(data) < 256 or data[:8] != b'LPKSHHRH':
        raise ParseError('Invalid/truncated systemd journal header')
    check_cancelled(cancelled)
    lib = library()
    if not hasattr(os, 'memfd_create'):
        raise ParseError('RAM-only journal snapshots require Linux memfd support')
    fd = os.memfd_create('terra-journal', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    journal = ctypes.c_void_p()
    owned = True
    try:
        for offset in range(0, len(data), 1024 * 1024):
            check_cancelled(cancelled)
            view = memoryview(data)[offset:offset + 1024 * 1024]
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise ParseError('RAM journal snapshot write failed')
                view = view[written:]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
        descriptors = (ctypes.c_int * 1)(fd)
        result = lib.sd_journal_open_files_fd(ctypes.byref(journal), descriptors, 1, 1 << 8)
        if result in (-errno.EIDRM, -errno.EINVAL) and path is not None and metadata is not None:
            # Some host libsystemd versions reject unlinked RAM files. Their
            # read-only API may instead use the original anchored source; the
            # complete source is reverified afterwards before rows are accepted.
            os.close(fd)
            owned = False
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            name = os.path.basename(path) if directory_fd is not None else path
            try:
                fd = os.open(name, flags | getattr(os, 'O_NOATIME', 0), dir_fd=directory_fd)
            except OSError as error:
                if error.errno not in (errno.EPERM, errno.EACCES, errno.EINVAL):
                    raise
                fd = os.open(name, flags, dir_fd=directory_fd)
            owned = True
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != tuple(
                    metadata[key] for key in ('device', 'inode', 'size', 'mtime_ns', 'ctime_ns')):
                raise ParseError('Journal source changed before parsing')
            descriptors = (ctypes.c_int * 1)(fd)
            result = lib.sd_journal_open_files_fd(ctypes.byref(journal), descriptors, 1, 0)
        checked(result)
        owned = False  # libsystemd owns this descriptor after successful open.
        checked(lib.sd_journal_set_data_threshold(journal, 0))
        checked(lib.sd_journal_seek_head(journal))
        number = 0
        while checked(lib.sd_journal_next(journal)):
            check_cancelled(cancelled)
            number += 1
            fields = {}
            lib.sd_journal_restart_data(journal)
            pointer, size = ctypes.c_void_p(), ctypes.c_size_t()
            while checked(lib.sd_journal_enumerate_data(journal, ctypes.byref(pointer), ctypes.byref(size))):
                check_cancelled(cancelled)
                raw = ctypes.string_at(pointer, size.value)
                key, separator, value = raw.partition(b'=')
                if not separator:
                    raise ParseError('Journal field has no separator')
                name = key.decode('ascii')
                try:
                    value = value.decode('utf-8')
                except UnicodeDecodeError:
                    value = {'encoding': 'hex', 'value': value.hex(), 'byte_length': len(value)}
                fields.setdefault(name, []).append(value)
            realtime = ctypes.c_uint64()
            checked(lib.sd_journal_get_realtime_usec(journal, ctypes.byref(realtime)))
            clock_fields = {}
            if hasattr(lib, 'sd_journal_get_monotonic_usec'):
                monotonic, boot = ctypes.c_uint64(), Id128()
                checked(lib.sd_journal_get_monotonic_usec(journal, ctypes.byref(monotonic), ctypes.byref(boot)))
                clock_fields = dict(monotonic_usec=monotonic.value, boot_id=bytes(boot.bytes).hex(),
                                    monotonic_semantics='Journal receipt timestamp, not necessarily device-event origin time')
                source_monotonic = fields.get('_SOURCE_MONOTONIC_TIMESTAMP', [''])[0]
                if isinstance(source_monotonic, str) and source_monotonic.isdigit():
                    clock_fields.update(monotonic_usec=int(source_monotonic), journal_receipt_monotonic_usec=monotonic.value,
                                        event_clock='kernel_source_monotonic')
                else:
                    clock_fields['event_clock'] = 'journal_receipt_monotonic'
            device_event = next((event for message in fields.get('MESSAGE', [])
                                 if isinstance(message, str) and (event := usb_event(message))), None)
            yield entry('device_connection_event' if device_event else 'journal_event', f'entry:{number}', fields=fields,
                        timestamp_utc=utc_time(realtime.value, 1000000), timestamp_raw_usec=realtime.value,
                        note='Source bytes verified against acquired evidence; journal sealing/integrity not verified.',
                        **clock_fields, **(device_event or {}))
        if path is not None and metadata is not None:
            read_verified(path, metadata, directory_fd, cancelled)
    finally:
        if journal.value:
            lib.sd_journal_close(journal)
        if owned:
            os.close(fd)
