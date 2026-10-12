"""Replay verified committed WAL pages in RAM; SQLite never opens source paths."""
import sqlite3
import struct

from artifacts.parser_support import ParseError, check_cancelled, read_verified, verify_unchanged


def checksum(data, order, initial=(0, 0)):
    first, second = initial
    for left, right in struct.iter_unpack(order + 'II', data):
        first = (first + left + second) & 0xffffffff
        second = (second + right + first) & 0xffffffff
    return first, second


def merge_wal(database, wal, cancelled=lambda: False):
    warnings = []
    if len(database) < 100 or database[:16] != b'SQLite format 3\x00':
        raise ParseError('Not an unencrypted SQLite 3 database.')
    page_size = int.from_bytes(database[16:18], 'big')
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1) or len(database) % page_size:
        raise ParseError('Invalid SQLite page size or truncated database.')
    image = bytearray(database)
    if wal:
        if len(wal) < 32:
            raise ParseError('Truncated SQLite WAL header.')
        magic, version, wal_page_size, sequence, salt1, salt2, sum1, sum2 = struct.unpack('>8I', wal[:32])
        if magic not in (0x377f0682, 0x377f0683) or version != 3007000 or wal_page_size != page_size:
            raise ParseError('Invalid or incompatible SQLite WAL header.')
        order = '<' if magic == 0x377f0682 else '>'
        current = checksum(wal[:24], order)
        if current != (sum1, sum2):
            raise ParseError('SQLite WAL header checksum failed.')
        frames = []
        committed = 0
        db_pages = 0
        width = 24 + page_size
        for offset in range(32, len(wal), width):
            check_cancelled(cancelled)
            frame = wal[offset:offset + width]
            if len(frame) != width:
                warnings.append('Incomplete WAL tail omitted; only verified committed transactions were used.')
                break
            page, size, frame_salt1, frame_salt2, first, second = struct.unpack('>6I', frame[:24])
            if (frame_salt1, frame_salt2) != (salt1, salt2):
                warnings.append('Stale WAL tail omitted after a salt mismatch.')
                break
            current = checksum(frame[:8] + frame[24:], order, current)
            if current != (first, second) or page == 0:
                warnings.append('Invalid WAL tail omitted after a frame checksum/page failure.')
                break
            frames.append((page, offset + 24))
            if size:
                committed, db_pages = len(frames), size
        if committed:
            if db_pages * page_size > len(database) + committed * page_size:
                raise ParseError('WAL claims a database size exceeding supplied pages.')
            target_size = db_pages * page_size
            image = image[:target_size]
            if len(image) < target_size:
                image.extend(b'\x00' * (target_size - len(image)))
            for page, offset in frames[:committed]:
                check_cancelled(cancelled)
                if page <= db_pages:
                    start = (page - 1) * page_size
                    image[start:start + page_size] = wal[offset:offset + page_size]
        if len(frames) > committed:
            warnings.append('Uncommitted WAL frames omitted.')
    # SQLite deserialize cannot open a WAL-mode image; alter only the analysis
    # copy to rollback mode. Raw evidence and its hashes remain unchanged.
    image[18:20] = b'\x01\x01'
    return bytes(image), warnings


def open_snapshot(path, metadata, data, directory_fd, cancelled, image_decoder=None):
    inputs = [dict(path=path, sha256=metadata['sha256'], size=metadata['size'])]
    if not metadata.get('content_retained', True):
        data, source = read_verified(path, metadata, directory_fd, cancelled)
    else:
        verify_unchanged(path, metadata, directory_fd)
    wal_path = path + '-wal'
    try:
        wal, wal_metadata = read_verified(wal_path, directory_fd=directory_fd, cancelled=cancelled)
    except FileNotFoundError:
        wal, wal_metadata = b'', None
    journal_path = path + '-journal'
    try:
        journal, journal_metadata = read_verified(journal_path, directory_fd=directory_fd, cancelled=cancelled)
        if journal:
            raise ParseError('Rollback journal present; structured parsing deferred to avoid interpreting an inconsistent database.')
    except FileNotFoundError:
        pass
    verify_unchanged(path, metadata, directory_fd)
    if wal_metadata:
        verify_unchanged(wal_path, wal_metadata, directory_fd)
        inputs.append({key: wal_metadata[key] for key in ('path','sha256','size')})
    else:
        try:
            read_verified(wal_path, directory_fd=directory_fd, cancelled=cancelled)
        except FileNotFoundError:
            pass
        else:
            raise ParseError('WAL appeared during snapshot acquisition; parsing deferred.')
    image, warnings = (image_decoder(data, wal, cancelled) if image_decoder else merge_wal(data, wal, cancelled))
    connection = sqlite3.connect(':memory:')
    try:
        connection.deserialize(image)
        connection.execute('PRAGMA temp_store=MEMORY')
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA query_only=ON')
        connection.enable_load_extension(False)
        connection.row_factory = sqlite3.Row
        connection.set_progress_handler(lambda: int(cancelled()), 1000)
        supporting = [(dict(wal_metadata), wal)] if wal_metadata and wal else []
        return connection, inputs, warnings, supporting
    except Exception:
        connection.close()
        raise


def table_rows(connection, table, required=()):
    descriptor = connection.execute('SELECT type, sql FROM sqlite_master WHERE name=?', (table,)).fetchone()
    if descriptor is None:
        return None
    if descriptor['type'] != 'table' or 'CREATE VIRTUAL TABLE' in (descriptor['sql'] or '').upper():
        raise ParseError('Unsupported virtual table/view in artifact schema.')
    columns = {row['name'] for row in connection.execute(f'PRAGMA table_info("{table}")')}
    if not set(required) <= columns:
        raise ParseError(f'Unsupported {table} schema: required columns missing.')
    # The table name is a constant supplied by TERRA parsers, never evidence SQL.
    return connection.execute(f'SELECT * FROM "{table}"')
