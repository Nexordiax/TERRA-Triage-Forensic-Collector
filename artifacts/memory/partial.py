"""Preserve stopped or failed captures without claiming a valid full image."""
import hashlib
import json
import os
import struct
from uuid import uuid4
from datetime import datetime, timezone
from artifacts.memory.coverage import coverage, merge_ranges


def publish(image, destination, reserved, expected, started, progress, backend_sha256, error=None):
    digest = hashlib.sha256()
    size = image.stat().st_size
    ranges = []
    expected = merge_ranges(expected)
    with open(image, 'rb') as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            progress({'phase': 'Saving failed RAM acquisition' if error else 'Saving stopped RAM acquisition',
                      'bytes': source.tell(), 'total': size})
        source.seek(0)
        while source.tell() < size:
            offset = source.tell()
            header = source.read(32)
            if len(header) != 32:
                break
            magic, version, start, end, reserved_header = struct.unpack('<IIQQQ', header)
            if (magic, version, reserved_header) != (0x4C694D45, 1, 0) or end < start or (ranges and start <= ranges[-1]['end']) or not any(left <= start <= end <= right for left, right in expected):
                break
            captured = min(end - start + 1, max(0, size - offset - 32))
            ranges.append(dict(start=start, end=end, payload_offset=offset + 32,
                               captured_bytes=captured, complete=captured == end - start + 1))
            if captured != end - start + 1:
                break
            source.seek(captured, 1)
        os.fsync(source.fileno())
    current = os.stat(destination, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (reserved.st_dev, reserved.st_ino):
        raise OSError('Destination was replaced during acquisition; it was not overwritten.')
    summary = coverage(expected, [(row['start'], row['start'] + row['captured_bytes'] - 1) for row in ranges if row['captured_bytes']])
    summary['complete_physical_ram'] = False
    record = dict(summary, path=str(destination), size=size, sha256=digest.hexdigest(), kind='file',
                  category='Physical RAM', matches={}, content_retained=False,
                  collection=('failed RAM acquisition (unverified bytes retained)' if error else 'stopped physical RAM acquisition (incomplete LiME stream)'),
                  memory_image=True, memory_scope='physical_ram',
                  acquisition_stopped=error is None, acquisition_failed=error is not None,
                  validation_status='failed' if error else 'stopped', validation_error=error, memory_ranges=ranges,
                  backend='AVML minimal 0.20.0', backend_sha256=backend_sha256,
                  physical_bytes=sum(row['captured_bytes'] for row in ranges),
                  acquired_at=started, completed_at=datetime.now(timezone.utc).isoformat(),
                  limitations=[('Acquisition or validation failed: ' + error if error else 'Stopped acquisition') + ': original bytes preserved exactly; this image may be incomplete or invalid and may require recovery before import. Full RAM coverage was not verified.'])
    sidecar = str(destination) + '.json'
    # Metadata must survive shutdown together with the partial stream.
    try:
        fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        sidecar = str(destination) + '.' + uuid4().hex + '.json'
        fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(record, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(image, 0o600)
        os.replace(image, destination)
    except Exception:
        os.unlink(sidecar)
        raise
    info = destination.stat()
    record.update(mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
                  device=info.st_dev, inode=info.st_ino, mode=info.st_mode, metadata_path=sidecar)
    return record
