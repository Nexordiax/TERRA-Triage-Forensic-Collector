from pathlib import Path


def classify(path):
    # Source files describe the selected filesystem, not the examiner's host.
    normalized = Path(path).as_posix()
    if any(normalized.endswith(suffix) for suffix in (
        '/etc/os-release', '/usr/lib/os-release', '/etc/hostname', '/etc/machine-id',
        '/etc/passwd', '/etc/group', '/etc/fstab', '/var/lib/dpkg/status',
    )):
        return 'Device Information'
