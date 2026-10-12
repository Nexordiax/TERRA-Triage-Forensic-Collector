import errno
import os
import stat

from PySide6.QtCore import QBuffer, QFile, QFileDevice, QIODevice


def validate_source(record, descriptor):
    current = os.fstat(descriptor)
    expected = ('size', 'mtime_ns', 'ctime_ns', 'device', 'inode')
    if any(key not in record for key in expected):
        raise ValueError('Source verification details are unavailable. Rescan this file before viewing it.')
    actual = (current.st_size, current.st_mtime_ns, current.st_ctime_ns, current.st_dev, current.st_ino)
    if not stat.S_ISREG(current.st_mode) or actual != tuple(record[key] for key in expected):
        raise ValueError('The source file changed or was replaced after scanning. Rescan it before viewing it.')


def open_record_device(record, parent=None):
    """Use a cached snapshot when available, otherwise open the verified source."""
    if record.get('content_retained', True):
        device = QBuffer(parent)
        device.setData(record['data'])
        device.open(QIODevice.OpenModeFlag.ReadOnly)
        return device, 'Viewing the file copy cached during this scan.'
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(record['path'], flags | getattr(os, 'O_NOATIME', 0))
    except OSError as error:
        if error.errno not in (errno.EPERM, errno.EACCES, errno.EINVAL):
            raise
        descriptor = os.open(record['path'], flags)
    try:
        validate_source(record, descriptor)
        device = QFile(parent)
        if not device.open(descriptor, QIODevice.OpenModeFlag.ReadOnly, QFileDevice.FileHandleFlag.AutoCloseHandle):
            raise OSError(device.errorString())
    except Exception:
        os.close(descriptor)
        raise
    return device, 'Viewing the source file on the selected drive. It was verified unchanged since scanning when opened.'
