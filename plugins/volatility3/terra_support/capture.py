"""Read local process-memory evidence without extracting or importing TERRA."""
import hashlib
import json
import re
import zipfile
from pathlib import Path, PurePosixPath

CHUNK = 1024 * 1024
MANIFEST_LIMIT = 32 * 1024 * 1024


class Capture:
    """Validated v1/v2 manifest and bounded, segmented raw-memory reader.

    Structural validation does not imply hash verification or authenticity.
    All file offsets are offsets in the compact region member, not physical RAM.
    """

    def __init__(self, location):
        self.path = Path(location).expanduser().resolve(strict=True)
        self.archive = None
        try:
            if not self.path.is_dir():
                self.archive = zipfile.ZipFile(self.path, 'r')
                names = self.archive.namelist()
                if len(names) != len(set(names)):
                    raise ValueError('Ambiguous ZIP: duplicate member names')
            with self.open('manifest.json') as source:
                data = source.read(MANIFEST_LIMIT + 1)
            if len(data) > MANIFEST_LIMIT:
                raise ValueError('Manifest exceeds 32 MiB limit')
            self.manifest = json.loads(data)
            if (self.manifest.get('format') != 'terra-process-memory'
                    or self.manifest.get('format_version') not in (1, 2)
                    or self.manifest.get('complete_physical_ram') is not False):
                raise ValueError('Expected a TERRA partial process-memory capture (v1/v2), not LiME or a triage ZIP')
            seen_pids, seen_members = set(), set()
            for process in self.manifest['processes']:
                pid = self.integer(process['pid'], 'PID')
                if pid in seen_pids:
                    raise ValueError('Duplicate captured PID')
                seen_pids.add(pid)
                previous_region_end = 0
                for region in process['regions']:
                    start = self.integer(region['start'], 'region start')
                    end = self.integer(region['end_exclusive'], 'region end')
                    if end <= start or start < previous_region_end:
                        raise ValueError('Overlapping or invalid region range')
                    previous_region_end = end
                    member = region['archive_path']
                    self.member_path(member)
                    if not member.startswith(f'processes/{pid}/regions/') or member in seen_members:
                        raise ValueError('Invalid or duplicate region member')
                    seen_members.add(member)
                    offset, last_end = 0, start
                    for segment in region['segments']:
                        address = self.integer(segment['virtual_start'], 'segment address')
                        length = self.integer(segment['length'], 'segment length')
                        file_offset = self.integer(segment['file_offset'], 'segment file offset')
                        if length == 0 or address < last_end or address + length > end or file_offset != offset:
                            raise ValueError('Invalid segment mapping: range, overlap or compact-file offset')
                        last_end, offset = address + length, offset + length
                    if offset != self.integer(region['captured_bytes'], 'captured bytes') or self.size(member) != offset:
                        raise ValueError('Region member size does not match captured segments')
                    if not re.fullmatch(r'[0-9a-fA-F]{64}', region['sha256']):
                        raise ValueError('Invalid SHA-256 value')
        except BaseException:
            self.close()
            raise

    @staticmethod
    def integer(value, label):
        if type(value) is not int or value < 0:
            raise ValueError(f'Invalid {label}')
        return value

    @staticmethod
    def member_path(name):
        if not isinstance(name, str) or '\\' in name:
            raise ValueError('Unsafe member path')
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or str(path) != name or not path.parts:
            raise ValueError('Unsafe member path')
        return path

    def local_path(self, name):
        path = self.path.joinpath(*self.member_path(name).parts).resolve(strict=True)
        if not path.is_relative_to(self.path):
            raise ValueError('Evidence member escapes capture directory')
        return path

    def size(self, name):
        self.member_path(name)
        return self.archive.getinfo(name).file_size if self.archive else self.local_path(name).stat().st_size

    def open(self, name):
        self.member_path(name)
        return self.archive.open(name, 'r') if self.archive else self.local_path(name).open('rb')

    def close(self):
        if self.archive:
            self.archive.close()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def processes(self, pids=None):
        for process in self.manifest['processes']:
            if not pids or process['pid'] in pids:
                yield process

    def chunks(self, region, chunk_size=CHUNK):
        """Yield segment index, virtual address and data; never synthesize gaps."""
        if chunk_size < 1:
            raise ValueError('Invalid chunk size')
        with self.open(region['archive_path']) as source:
            for index, segment in enumerate(region['segments']):
                remaining = segment['length']
                address = segment['virtual_start']
                while remaining:
                    data = source.read(min(chunk_size, remaining))
                    if not data:
                        raise ValueError('Region truncated during read')
                    yield index, address, data
                    address += len(data)
                    remaining -= len(data)

    def digest(self, region):
        digest = hashlib.sha256()
        with self.open(region['archive_path']) as source:
            while data := source.read(CHUNK):
                digest.update(data)
        return digest.hexdigest()


def search(capture, region, needle, insensitive=False, chunk_size=CHUNK):
    """Literal byte search, retaining overlap only inside the same segment."""
    if not needle or len(needle) > 65536:
        raise ValueError('Search term must contain 1–65536 encoded bytes')
    needle = needle.lower() if insensitive else needle
    tail, previous = b'', None
    for index, address, data in capture.chunks(region, chunk_size):
        if index != previous:
            tail = b''
        previous = index
        block = tail + data
        haystack = block.lower() if insensitive else block
        position = haystack.find(needle)
        while position >= 0:
            if position + len(needle) > len(tail):
                yield address - len(tail) + position
            position = haystack.find(needle, position + 1)
        tail = block[-(len(needle) - 1):] if len(needle) > 1 else b''


def strings(capture, region, minimum=6, encoding='ascii', chunk_size=CHUNK):
    """Printable ASCII or ASCII-range UTF-16, with bounded 4096-char pieces.

    UTF-16 scans both alignments, independent of virtual-address parity.
    Results never join bytes from different captured segments.
    """
    if not 1 <= minimum <= 4096 or encoding not in ('ascii', 'utf-16-le', 'utf-16-be'):
        raise ValueError('Invalid strings minimum/encoding')
    width = 1 if encoding == 'ascii' else 2
    for alignment in range(width):
        previous, pending, run, run_start = None, b'', bytearray(), 0
        for index, address, data in capture.chunks(region, chunk_size):
            if previous != index:
                if len(run) >= minimum:
                    yield run_start, run.decode('ascii')
                pending, run = b'', bytearray()
                data, address = data[alignment:], address + alignment
            previous = index
            block, base = pending + data, address - len(pending)
            usable = len(block) - len(block) % width
            for offset in range(0, usable, width):
                unit = block[offset:offset + width]
                value = unit[0] if encoding != 'utf-16-be' else unit[-1]
                printable = 32 <= value <= 126 and (width == 1 or unit[1 if encoding == 'utf-16-le' else 0] == 0)
                if printable:
                    if not run:
                        run_start = base + offset
                    run.append(value)
                    if len(run) == 4096:
                        yield run_start, run.decode('ascii')
                        run = bytearray()
                else:
                    if len(run) >= minimum:
                        yield run_start, run.decode('ascii')
                    run = bytearray()
            pending = block[usable:]
        if len(run) >= minimum:
            yield run_start, run.decode('ascii')
