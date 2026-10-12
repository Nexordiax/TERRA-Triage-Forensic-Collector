"""Package physical RAM and its companions without changing captured bytes."""
import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from artifacts.memory.coverage import estimated_image_size


def acquire_archive(collector, destination):
    destination = Path(os.path.abspath(destination))
    from artifacts.memory.collector import physical_ranges
    required = estimated_image_size(physical_ranges()) * 2 + 1048576
    if shutil.disk_usage(destination.parent).free < required:
        raise OSError(f'Insufficient space for RAM acquisition and ZIP packaging: {required} bytes needed.')
    work = Path(tempfile.mkdtemp(prefix='.terra-ram-', dir=destination.parent))
    # Reserve exclusively before acquisition; never overwrite existing evidence.
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    except Exception:
        shutil.rmtree(work)
        raise
    reserved = os.fstat(fd)
    os.close(fd)
    record = None
    published = False
    retain_work = False
    try:
        image = work / (destination.stem + '.lime')
        record = collector.acquire_physical(image)
        log = record.pop('backend_log', '')
        (work / 'backend.log').write_text(log)
        metadata = dict(record, path=image.name)
        metadata.pop('metadata_path', None)
        (work / 'acquisition.json').write_text(json.dumps(metadata, indent=2))
        (work / 'logs').mkdir()
        (work / 'logs' / 'acquisition.log').write_text(log + '\n' + json.dumps(metadata, indent=2))
        members = [image, work / 'acquisition.json', work / 'backend.log', work / 'logs' / 'acquisition.log']
        if record.get('metadata_path'):
            members.append(Path(record['metadata_path']))
        archive_path = work / 'acquisition.zip'
        # ZIP64 and stored entries support very large images with low CPU overhead.
        # Finalization deliberately ignores Stop so already captured bytes survive.
        with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for member in members:
                with member.open('rb') as source, archive.open(str(member.relative_to(work)), 'w', force_zip64=True) as output:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
                        collector.progress({'phase': 'Packaging RAM acquisition', 'bytes': source.tell(),
                                            'total': member.stat().st_size})
        digest = hashlib.sha256()
        with zipfile.ZipFile(archive_path) as archive, archive.open(image.name) as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                collector.progress({'phase': 'Verifying packaged RAM image', 'bytes': source.tell(),
                                    'total': record['size']})
            if digest.hexdigest() != record['sha256']:
                raise OSError('Packaged RAM image failed SHA-256 verification.')
            for member in members[1:]:
                if archive.read(str(member.relative_to(work))) != member.read_bytes():
                    raise OSError('Packaged RAM metadata failed verification.')
        digest = hashlib.sha256()
        with archive_path.open('rb') as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                collector.progress({'phase': 'Hashing RAM ZIP', 'bytes': source.tell(),
                                    'total': archive_path.stat().st_size})
            os.fsync(source.fileno())
        current = destination.stat(follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (reserved.st_dev, reserved.st_ino):
            raise OSError('Destination was replaced during acquisition; it was not overwritten.')
        os.chmod(archive_path, 0o600)
        os.replace(archive_path, destination)
        published = True
        info = destination.stat()
        record.pop('metadata_path', None)
        return dict(record, path=str(destination), size=info.st_size, sha256=digest.hexdigest(),
                    image_member=image.name, image_size=record['size'], image_sha256=record['sha256'],
                    archive_format='ZIP64', collection=record['collection'] + ' in ZIP',
                    mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
                    device=info.st_dev, inode=info.st_ino, mode=info.st_mode)
    except Exception as error:
        retain_work = record is not None or any(path.stat().st_size for path in work.rglob('*.lime') if path.is_file())
        if retain_work:
            raise OSError(f'RAM ZIP could not be saved: {error}. Captured evidence retained at {work}') from error
        raise
    finally:
        if published or not retain_work:
            shutil.rmtree(work)
        if not published:
            try:
                current = destination.stat(follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (reserved.st_dev, reserved.st_ino):
                    destination.unlink()
            except FileNotFoundError:
                pass
