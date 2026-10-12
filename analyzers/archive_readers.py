"""Read archive members into bounded consumers, never filesystem extractors."""
import io
import stat
import zipfile


class ArchiveLocked(ValueError):
    pass


def zip_members(source, passwords, consume, limitation, maximum):
    try:
        import pyzipper
        reader = pyzipper.AESZipFile
    except ImportError:
        reader = zipfile.ZipFile
    with reader(source) as archive:
        infos = archive.infolist()
        if len(infos) > maximum:
            limitation('Archive entry limit reached; remaining entries were not searched')
        seen = set()
        for index, info in enumerate(infos[:maximum]):
            if info.is_dir():
                continue
            if stat.S_ISLNK(info.external_attr >> 16):
                limitation(info.filename + ': symbolic link skipped')
                continue
            if info.filename in seen:
                limitation('Duplicate member name skipped: ' + info.filename)
                continue
            seen.add(info.filename)
            encrypted = bool(info.flag_bits & 1)
            attempts = passwords if encrypted else [None]
            if not attempts:
                limitation(info.filename + ': encrypted member; no discovered credential available')
                continue
            for candidate in attempts:
                try:
                    password = candidate['secret'].encode('utf-8') if candidate else None
                    with archive.open(info, pwd=password) as member:
                        consume(info.filename, iter(lambda: member.read(1024 * 1024), b''), info.file_size,
                                index, candidate)
                    break
                except (RuntimeError, zipfile.BadZipFile, NotImplementedError) as error:
                    if not encrypted:
                        limitation(info.filename + ': ' + str(error))
                        break
            else:
                limitation(info.filename + ': encrypted member; discovered credentials could not decrypt/verify it')


def native_members(source, suffix, passwords, consume, limitation, maximum):
    try:
        import libarchive
    except (ImportError, OSError):
        raise ValueError('Offline libarchive reader is unavailable for ' + suffix) from None
    source.seek(0)
    magic = source.read(8)
    source.seek(0)
    if suffix == '.rar' and not magic.startswith(b'Rar!\x1a\x07'):
        raise ValueError('Invalid RAR signature; file not parsed')
    if suffix == '.7z' and not magic.startswith(b'7z\xbc\xaf\x27\x1c'):
        raise ValueError('Invalid 7z signature; file not parsed')
    formats = {'.rar': 'rar', '.7z': '7zip'}
    # libarchive probes RAR4/RAR5 itself. Encrypted RAR is not supported by libarchive.
    with libarchive.stream_reader(source, format_name='all' if suffix == '.rar' else formats.get(suffix, 'all'), filter_name='none') as archive:
        seen = set()
        for index, entry in enumerate(archive):
            if index >= maximum:
                limitation('Archive entry limit reached; remaining entries were not searched')
                break
            if not entry.isreg or entry.issym or entry.islnk:
                if not entry.isdir:
                    limitation(str(entry.pathname) + ': nonregular member skipped')
                continue
            name = str(entry.pathname)
            if name in seen:
                limitation('Duplicate member name skipped: ' + name)
                continue
            seen.add(name)
            consume(name, entry.get_blocks(), entry.size, index, None)


def sevenzip_members(source, passwords, consume, limitation, maximum, byte_limit):
    """Encrypted 7z support through a custom, RAM-only streaming writer factory."""
    import py7zr
    from py7zr.io import Py7zIO, WriterFactory
    # The stream factory bounds RAM independently of the expanded-byte budget.
    # Large member bytes are consumed through a spool backed by anonymous RAM.
    import os
    failures = []
    for candidate in [None] + passwords:
        source.seek(0)
        members = []
        try:
            with py7zr.SevenZipFile(source, 'r', password=candidate['secret'] if candidate else None,
                                   max_extract_size=byte_limit, mp=False) as archive:
                infos = archive.list()
                if len(infos) > maximum:
                    raise ValueError('7z entry limit reached; archive not searched')
                regular = [info for info in infos if info.is_file and not info.is_symlink]
                names = [info.filename for info in regular]
                if len(set(names)) != len(names):
                    raise ValueError('Duplicate 7z member names; archive not searched')
                if sum(info.uncompressed for info in regular) > byte_limit:
                    raise ValueError('7z expanded byte limit reached; archive not searched')
                metadata = {info.filename: (index, info.uncompressed) for index, info in enumerate(regular)}
                class Sink(Py7zIO):
                    def __init__(self, name):
                        self.name = name
                        self.fd = os.memfd_create('terra-7z-member', os.MFD_CLOEXEC)
                        self.stream = os.fdopen(self.fd, 'w+b')
                        members.append(self)
                    def write(self, data):
                        if self.stream.tell() + len(data) > min(metadata[self.name][1], byte_limit):
                            raise ValueError('7z expanded member exceeds declared/bounded size')
                        return self.stream.write(data)
                    def read(self, size=None): return self.stream.read(-1 if size is None else size)
                    def seek(self, offset, whence=0): return self.stream.seek(offset, whence)
                    def flush(self): self.stream.flush()
                    def size(self): return os.fstat(self.fd).st_size
                    def close(self): pass  # Wait until archive CRC/authentication succeeds.
                class Factory(WriterFactory):
                    def create(self, filename):
                        if filename not in metadata:
                            raise ValueError('Unexpected 7z output member')
                        return Sink(filename)
                if names:
                    archive.extract(targets=names, factory=Factory())
                for item in members:
                    index, size = metadata[item.name]
                    item.stream.seek(0)
                    consume(item.name, iter(lambda: item.stream.read(1024 * 1024), b''), size, index, candidate)
                return
        except Exception as error:
            failures.append(type(error).__name__)
            # Never leak credential values through library exception text.
            if isinstance(error, ValueError) and ('limit' in str(error) or 'Duplicate' in str(error)):
                raise
        finally:
            for item in members:
                item.stream.close()
    raise ArchiveLocked('Encrypted/corrupt 7z archive: no discovered credential verified it (' + ', '.join(sorted(set(failures))) + ')')
