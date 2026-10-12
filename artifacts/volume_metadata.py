"""Read-only Linux mount metadata for logical export provenance."""
import os
import re
from datetime import datetime, timezone
from pathlib import Path


def mounted_volumes():
    captured_at = datetime.now(timezone.utc).isoformat()
    def decode(value):
        return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)
    result = []
    try:
        lines = Path('/proc/self/mountinfo').read_text().splitlines()
    except OSError:
        return result
    for line in lines:
        try:
            left, right = line.split(' - ', 1)
            fields, details = left.split(), right.split()
            major, minor = map(int, fields[2].split(':'))
            result.append(dict(mount_id=fields[0], device=os.makedev(major, minor),
                               mount_point=decode(fields[4]), filesystem_root=decode(fields[3]),
                               filesystem_type=details[0], device_source=decode(details[1]),
                               captured_at=captured_at, metadata_source='Linux mountinfo'))
        except (ValueError, IndexError, OverflowError):
            continue
    return result
