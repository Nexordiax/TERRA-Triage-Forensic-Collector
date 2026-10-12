import errno
import hashlib
import os
import stat


class CollectionCancelled(Exception):
    pass


class FileCollector:
    """Acquire regular files read-only, with cancellation and bounded RAM use."""
    def __init__(self, max_file_bytes=32 * 1024 * 1024):
        self.max_file_bytes = max_file_bytes

    def collect(self, path, cancelled, directory_fd=None, *, on_chunk=None,
                on_progress=None, retention_limit=None):
        if cancelled():
            raise CollectionCancelled()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        filename = os.path.basename(path) if directory_fd is not None else path
        # Avoid atime changes where Linux permits it, otherwise use read-only access.
        try:
            descriptor = os.open(filename, flags | getattr(os, 'O_NOATIME', 0), dir_fd=directory_fd)
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EACCES, errno.EINVAL):
                raise
            descriptor = os.open(filename, flags, dir_fd=directory_fd)
        with os.fdopen(descriptor, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError('Not a regular file; special devices and sockets are not read.')
            limit = self.max_file_bytes if retention_limit is None else min(self.max_file_bytes, retention_limit)
            retained = before.st_size <= limit
            reason = ''
            if not retained:
                reason = ('Per-file RAM retention limit exceeded.' if before.st_size > self.max_file_bytes
                          else 'Total RAM file-byte retention limit reached.')
            data = bytearray()
            digest = hashlib.sha256()
            bytes_read = 0
            while True:
                if cancelled():
                    raise CollectionCancelled()
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                bytes_read += len(chunk)
                if retained:
                    if bytes_read > limit:
                        retained = False
                        reason = 'File grew beyond its RAM retention limit.'
                        data.clear()
                    else:
                        data.extend(chunk)
                digest.update(chunk)
                if on_chunk:
                    on_chunk(chunk)
                if on_progress:
                    on_progress(bytes_read, before.st_size)
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or bytes_read != before.st_size:
                raise ValueError('File changed during acquisition; inconsistent evidence was discarded.')
        return bytes(data), {'size': bytes_read, 'sha256': digest.hexdigest(),
                             'mtime_ns': before.st_mtime_ns, 'atime_ns': before.st_atime_ns, 'mode': before.st_mode,
                             'ctime_ns': before.st_ctime_ns, 'device': before.st_dev,
                             'inode': before.st_ino,
                             'content_retained': retained, 'retention_reason': reason}
