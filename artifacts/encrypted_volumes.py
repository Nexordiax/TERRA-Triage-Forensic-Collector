"""Read-only kernel metadata for mounted encrypted volumes selected for triage."""
import re
from pathlib import Path

from artifacts.parser_support import check_cancelled

SOURCES = ['https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html']


def _unescape(value):
    return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)


def collect(targets, cancelled, diagnostic, proc_root='/proc', sys_root='/sys'):
    """Identify dm-crypt UUIDs on selected mountpoints and their stacked backing devices.

    No raw block device, mount, keyring daemon or device-mapper key table is opened.
    Folder-only selections do not trigger host-volume enumeration.
    """
    selected = {str(Path(path).absolute()) for path in targets['paths']}
    try:
        lines = (Path(proc_root) / 'self/mountinfo').read_text().splitlines()
    except OSError as error:
        diagnostic('Encrypted volumes', str(error), 'warning')
        return []
    rows, seen = [], set()
    for line in lines:
        check_cancelled(cancelled)
        fields = line.split()
        if len(fields) < 10 or '-' not in fields:
            continue
        separator = fields.index('-')
        if separator + 3 >= len(fields):
            continue
        mount = _unescape(fields[4])
        if mount not in selected:
            continue
        major_minor = fields[2]
        if not re.fullmatch(r'\d+:\d+', major_minor):
            continue
        filesystem = fields[separator + 1]
        source = _unescape(fields[separator + 2])
        if filesystem == 'fuse.dislocker':
            rows.append(dict(type='mounted_encrypted_volume', format='BitLocker', mountpoint=mount,
                             device=source, detection='Mounted dislocker filesystem reported by kernel mountinfo',
                             cipher_note='Cipher not exposed by mount metadata', locator='mountinfo:' + fields[0]))
        pending = [Path(sys_root) / 'dev/block' / major_minor]
        visited = set()
        while pending and len(visited) < 128:
            check_cancelled(cancelled)
            device = pending.pop()
            try:
                resolved = device.resolve()
            except (OSError, RuntimeError) as error:
                diagnostic(str(device), str(error), 'warning')
                continue
            if not resolved.is_relative_to(Path(sys_root).resolve()) or resolved in visited:
                continue
            visited.add(resolved)
            try:
                uuid_path = device / 'dm/uuid'
                if uuid_path.exists():
                    uuid = uuid_path.read_text().strip()
                    if uuid.startswith('CRYPT-') and (uuid, mount) not in seen:
                        seen.add((uuid, mount))
                        format_name = ('LUKS1' if uuid.startswith('CRYPT-LUKS1-') else
                                       'LUKS2' if uuid.startswith('CRYPT-LUKS2-') else 'dm-crypt')
                        rows.append(dict(type='mounted_encrypted_volume', format=format_name,
                                         mountpoint=mount, device=source, device_mapper_uuid=uuid,
                                         detection='Kernel device-mapper CRYPT UUID (including stacked backing devices)',
                                         cipher_note='Cipher not exposed by sysfs UUID; no key table requested',
                                         locator=str(uuid_path)))
                slaves = device / 'slaves'
                if slaves.is_dir():
                    pending.extend(sorted(slaves.iterdir()))
            except OSError as error:
                diagnostic(str(device), str(error), 'warning')
    return rows
