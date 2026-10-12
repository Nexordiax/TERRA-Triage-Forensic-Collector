"""RPM SQLite inventories and bounded RPM header decoding, without librpm."""
import struct
import zlib
import io

from artifacts.parser_support import ParseError, check_cancelled, entry, utc_time
from artifacts.sqlite_snapshot import table_rows

TAGS = {1000: 'name', 1001: 'version', 1002: 'release', 1003: 'epoch',
        1004: 'summary', 1005: 'description', 1006: 'build_time',
        1008: 'install_time', 1011: 'vendor', 1014: 'license',
        1020: 'url', 1022: 'architecture', 1044: 'source_rpm'}


def header(blob, cancelled):
    if not isinstance(blob, bytes) or len(blob) < 8:
        raise ParseError('Truncated RPM header.')
    if blob.startswith(b'\x8e\xad\xe8\x01'):
        if len(blob) < 16 or blob[4:8] != b'\0' * 4:
            raise ParseError('Invalid RPM header magic/reserved bytes.')
        blob = blob[8:]
    count, size = struct.unpack_from('>II', blob)
    start = 8 + count * 16
    if start + size != len(blob):
        raise ParseError('RPM header index/store lengths do not match the blob.')
    store = blob[start:]
    values = {}
    for index in range(count):
        check_cancelled(cancelled)
        tag, kind, offset, length = struct.unpack_from('>4I', blob, 8 + index * 16)
        if offset > size:
            raise ParseError('RPM tag offset outside data store.')
        if tag not in TAGS:
            continue
        name = TAGS[tag]
        if name in values:
            raise ParseError('Duplicate inventory tag in RPM header.')
        if kind in (6, 8, 9):
            if kind == 6 and length != 1:
                raise ParseError('Invalid RPM string count.')
            strings = []
            position = offset
            if length > size:
                raise ParseError('Invalid RPM string array count.')
            for _ in range(length):
                check_cancelled(cancelled)
                end = store.find(b'\0', position)
                if end < 0:
                    raise ParseError('Unterminated RPM string.')
                strings.append(store[position:end].decode('utf-8', errors='replace'))
                position = end + 1
            values[name] = strings[0] if kind == 6 else strings
        elif kind in (3, 4, 5):
            width, format_code = {3: (2, 'H'), 4: (4, 'I'), 5: (8, 'Q')}[kind]
            if offset % width or length * width > size - offset:
                raise ParseError('Invalid RPM numeric tag alignment/length.')
            numbers = list(struct.unpack_from('>' + format_code * length, store, offset))
            values[name] = numbers[0] if length == 1 else numbers
        else:
            raise ParseError('Unsupported type for RPM inventory tag.')
    if not isinstance(values.get('name'), str) or not values['name']:
        raise ParseError('RPM package name missing.')
    return values


def sqlite(connection, cancelled):
    rows = table_rows(connection, 'Packages', ('hnum', 'blob'))
    if rows is None:
        raise ParseError('RPM Packages table missing.')
    for row in rows:
        check_cancelled(cancelled)
        values = header(row['blob'], cancelled)
        yield entry('package_record', f"Packages:{row['hnum']}", manager='rpm',
                    package=values['name'], version=values.get('version'), release=values.get('release'),
                    architecture=values.get('architecture'), installed=True,
                    install_time_utc=utc_time(values.get('install_time')),
                    build_time_utc=utc_time(values.get('build_time')), fields=values,
                    note='RPM database inventory; does not prove binaries still exist or have been executed.')


def ndb(data, cancelled):
    if len(data) < 4096 or len(data) % 16 or data[:4] != b'RpmP':
        raise ParseError('Invalid/truncated RPM NDB package database.')
    version, generation, pages = struct.unpack_from('<III', data, 4)
    index_end = pages * 4096
    if version != 0 or not pages or index_end > len(data):
        raise ParseError('Unsupported RPM NDB version or slot page count.')
    slots = []
    ids = set()
    for offset in range(32, index_end, 16):
        check_cancelled(cancelled)
        magic, package_id, start, count = struct.unpack_from('<4sIII', data, offset)
        if magic != b'Slot':
            raise ParseError('RPM NDB slot magic mismatch.')
        if not start:
            continue
        begin, end = start * 16, (start + count) * 16
        if not package_id or package_id in ids or count < 2 or begin < index_end or end > len(data):
            raise ParseError('Invalid/duplicate RPM NDB package slot.')
        ids.add(package_id)
        slots.append((begin, end, offset, package_id))
    ordered = sorted(slots)
    previous_end = index_end
    for begin, end, _, _ in ordered:
        check_cancelled(cancelled)
        if begin < previous_end:
            raise ParseError('Overlapping RPM NDB package slots.')
        previous_end = end
    for begin, end, offset, package_id in ordered:
        check_cancelled(cancelled)
        magic, recorded_id, blob_generation, size = struct.unpack_from('<4sIII', data, begin)
        checksum, tail_size, tail_magic = struct.unpack_from('<II4s', data, end - 12)
        if (magic != b'BlbS' or recorded_id != package_id or tail_magic != b'BlbE'
                or tail_size != size or (size + 28 + 15) // 16 != (end - begin) // 16):
            raise ParseError('RPM NDB blob header/trailer mismatch.')
        if any(data[begin + 16 + size:end - 12]):
            raise ParseError('Nonzero RPM NDB blob padding.')
        actual = 1
        for position in range(begin, end - 12, 65536):
            check_cancelled(cancelled)
            actual = zlib.adler32(data[position:min(position + 65536, end - 12)], actual)
        if actual != checksum:
            raise ParseError('RPM NDB blob Adler32 checksum mismatch.')
        values = header(data[begin + 16:begin + 16 + size], cancelled)
        yield entry('package_record', f'slot:{offset}/blob:{begin}', manager='rpm',
                    backend='ndb', package_id=package_id, database_generation=generation,
                    blob_generation=blob_generation, package=values['name'],
                    version=values.get('version'), release=values.get('release'),
                    architecture=values.get('architecture'), installed=True,
                    install_time_utc=utc_time(values.get('install_time')), fields=values,
                    note='Indexed NDB package inventory only; unreferenced/deleted blobs are not recovered.')


def bdb(data, cancelled):
    """Parse a verified BDB byte snapshot without opening a Berkeley environment."""
    try:
        from dissect.database.bsd.db import DB, c_db
    except ImportError:
        raise ParseError('RPM BDB dependency missing: install requirements-forensics.txt.') from None

    class BoundedDB(DB):
        def __init__(self):
            super().__init__(io.BytesIO(data))
            if (self.page_size < 512 or self.page_size > 65536 or self.page_size & (self.page_size - 1)
                    or len(data) % self.page_size or self.meta.dbmeta.flags & (c_db.DB_AM_ENCRYPT | c_db.DB_AM_CHKSUM)):
                raise ParseError('Unsupported encrypted/checksummed or invalid BDB page format.')
            self.total_pages = len(data) // self.page_size
            if (self.meta.dbmeta.encrypt_alg or self.meta.dbmeta.last_pgno >= self.total_pages
                    or self.meta.dbmeta.version not in ((7, 8, 9) if self.is_hash else (8, 9))):
                raise ParseError('Unsupported BDB version/encryption or truncated page set.')
            if self.is_hash and self.meta.max_bucket >= self.total_pages:
                raise ParseError('BDB bucket count exceeds supplied pages.')
            self.visited = set()
            # Validate overflow chains before Dissect follows them (including cycles).
            complete = set()
            for number in range(1, self.total_pages):
                check_cancelled(cancelled)
                page = self.page(number)
                if page.type != c_db.P_OVERFLOW or number in complete:
                    continue
                chain = set()
                while number and number not in complete:
                    check_cancelled(cancelled)
                    if number in chain:
                        raise ParseError('Cyclic BDB overflow chain.')
                    chain.add(number)
                    page = self.page(number)
                    if page.type != c_db.P_OVERFLOW or not 0 < page.header.hf_offset <= len(page.data):
                        raise ParseError('Invalid BDB overflow page.')
                    number = page.header.next_pgno
                complete.update(chain)

        def page(self, number):
            check_cancelled(cancelled)
            if number < 0 or number * self.page_size >= len(data):
                raise ParseError('BDB page pointer outside the acquired snapshot.')
            page = super().page(number)
            if page.header.entries > (self.page_size - self._page_overhead) // 2:
                raise ParseError('BDB page entry count exceeds page size.')
            return page

        def _walk_btree(self, number):
            if number in self.visited:
                raise ParseError('Repeated/cyclic BDB tree page.')
            self.visited.add(number)
            yield from super()._walk_btree(number)

        def _walk_hash(self, number):
            while number:
                if number in self.visited:
                    raise ParseError('Repeated/cyclic BDB hash page.')
                self.visited.add(number)
                page = self.page(number)
                if page.header.entries:
                    yield from page.entries()
                number = page.header.next_pgno

    database = BoundedDB()
    for key, blob in database.records():
        check_cancelled(cancelled)
        if len(blob) <= 4:
            continue  # RPM's package counter, not a package header.
        values = header(blob, cancelled)
        yield entry('package_record', 'bdb-key:' + (key.hex() if isinstance(key, bytes) else str(key)),
                    manager='rpm', backend='bdb', package=values['name'], version=values.get('version'),
                    release=values.get('release'), architecture=values.get('architecture'), installed=True,
                    install_time_utc=utc_time(values.get('install_time')), fields=values,
                    note='Read-only BDB snapshot; package registration does not establish execution or file existence.')
