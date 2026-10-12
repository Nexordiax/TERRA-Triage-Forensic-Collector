"""Verified, read-only inputs and common provenance for structured artifacts."""
import errno
import gzip
import bz2
import hashlib
import io
import lzma
import os
import stat
from datetime import datetime, timedelta, timezone

from artifacts.file_collector import CollectionCancelled


class ParseError(ValueError):
    pass


def utc_time(value, unit=1, epoch=1970):
    if value in (None, '', 0, '0'):
        return None
    try:
        whole,remainder = divmod(int(value),unit)
        return (datetime(epoch, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=whole,microseconds=remainder * 1000000 // unit)).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


def check_cancelled(cancelled):
    if cancelled():
        raise CollectionCancelled()


def read_verified(path, expected=None, directory_fd=None, cancelled=lambda: False):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    name = os.path.basename(path) if directory_fd is not None else path
    try:
        descriptor = os.open(name, flags | getattr(os, 'O_NOATIME', 0), dir_fd=directory_fd)
    except OSError as error:
        if error.errno not in (errno.EPERM, errno.EACCES, errno.EINVAL):
            raise
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ParseError('Parser input is not a regular file.')
        actual = {'size': before.st_size, 'mtime_ns': before.st_mtime_ns, 'ctime_ns': before.st_ctime_ns,
                  'device': before.st_dev, 'inode': before.st_ino}
        if expected and any(actual[key] != expected[key] for key in actual):
            raise ParseError('Source changed before structured parsing.')
        actual['atime_ns'] = before.st_atime_ns
        digest = hashlib.sha256()
        output = bytearray()
        while chunk := source.read(1024 * 1024):
            check_cancelled(cancelled)
            digest.update(chunk)
            output.extend(chunk)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ParseError('Source changed while taking a parser snapshot.')
        if len(output) != before.st_size or (expected and digest.hexdigest() != expected['sha256']):
            raise ParseError('Parser snapshot differs from acquired evidence.')
        return bytes(output), dict(actual, path=str(path), sha256=digest.hexdigest(), mode=before.st_mode)


def verify_unchanged(path, expected, directory_fd=None):
    name = os.path.basename(path) if directory_fd is not None else path
    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    values = (current.st_size, current.st_mtime_ns, current.st_ctime_ns, current.st_dev, current.st_ino)
    if not stat.S_ISREG(current.st_mode) or values != tuple(expected[key] for key in ('size','mtime_ns','ctime_ns','device','inode')):
        raise ParseError('Artifact input changed during the database/WAL snapshot; parsing was discarded.')


def text_lines(data, path, cancelled):
    if str(path).endswith('.gz'):
        source = gzip.GzipFile(fileobj=io.BytesIO(data))
    elif str(path).endswith('.bz2'):
        source = bz2.BZ2File(io.BytesIO(data))
    elif str(path).endswith('.xz'):
        source = lzma.LZMAFile(io.BytesIO(data))
    else:
        source = io.BytesIO(data)
    with source:
        for number, raw in enumerate(source, 1):
            check_cancelled(cancelled)
            yield number, raw.decode('utf-8', errors='replace').rstrip('\r\n')


def entry(kind, locator, **values):
    return {'type': kind, 'locator': locator, **values}
