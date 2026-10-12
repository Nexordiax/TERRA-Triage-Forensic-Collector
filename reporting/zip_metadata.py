"""Portable ZIP timestamps; Linux status-change time is never creation time."""
import struct
import zipfile
from datetime import datetime, timezone

FILETIME_EPOCH = 116444736000000000


def evidence_info(name, record):
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100600 << 16
    modified = record.get('mtime_ns')
    if isinstance(modified, int):
        # Legacy DOS date has no timezone and two-second precision. UTC is
        # deliberate; extra fields carry the authoritative UTC timestamps.
        seconds = modified // 1_000_000_000
        try:
            timestamp = datetime.fromtimestamp(seconds, timezone.utc)
            if 1980 <= timestamp.year <= 2107:
                info.date_time = timestamp.timetuple()[:6]
        except (ValueError, OverflowError, OSError):
            pass
        if -(1 << 31) <= seconds < (1 << 31):
            # Only mtime: valid in both local and central directory headers.
            info.extra += struct.pack('<HHBi', 0x5455, 5, 1, seconds)
        values = []
        for key in ('mtime_ns', 'atime_ns', 'birthtime_ns'):
            value = record.get(key)
            ticks = value // 100 + FILETIME_EPOCH if isinstance(value, int) else 0
            values.append(ticks if 0 <= ticks < (1 << 64) else 0)
        # Missing access/birth timestamps use the unset zero FILETIME sentinel.
        # In particular, POSIX ctime is never placed in the creation-time slot.
        info.extra += struct.pack('<HHIHHQQQ', 0x000A, 32, 0, 1, 24, *values)
    return info
