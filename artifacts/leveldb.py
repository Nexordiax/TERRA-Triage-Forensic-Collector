"""Read individual LevelDB log/SST files in RAM; never open a writable DB.

Records are physical observations, including superseded values and tombstones.
Without a verified CURRENT/MANIFEST set they are not a reconstructed live DB.
"""
import struct
import re

from artifacts.parser_support import ParseError, check_cancelled, entry, utc_time

MAX_BLOCK = 64 * 1024 * 1024
MAGIC = 0xdb4775248b80fb57


def _crc_table():
    table = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
        table.append(value)
    return table


CRC_TABLE = _crc_table()


def masked_crc(data, cancelled=lambda: False):
    value = 0xffffffff
    for start in range(0, len(data), 65536):
        check_cancelled(cancelled)
        for byte in data[start:start + 65536]:
            value = CRC_TABLE[(value ^ byte) & 255] ^ (value >> 8)
    value ^= 0xffffffff
    return (((value >> 15) | (value << 17)) + 0xa282ead8) & 0xffffffff


def varint(data, offset, bits=64):
    value = 0
    for shift in range(0, bits, 7):
        if offset >= len(data):
            raise ParseError('Truncated LevelDB varint.')
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            if value >= 1 << bits:
                break
            return value, offset
    raise ParseError('Overflowing LevelDB varint.')


def _slice(data, offset):
    size, offset = varint(data, offset, 32)
    if size > len(data) - offset:
        raise ParseError('Truncated LevelDB length-prefixed value.')
    return data[offset:offset + size], offset + size


def snappy(data, cancelled):
    size, offset = varint(data, 0, 32)
    if size > MAX_BLOCK:
        raise ParseError('Snappy block exceeds the 64 MiB decoded-block safety limit.')
    output = bytearray()
    while offset < len(data):
        check_cancelled(cancelled)
        tag = data[offset]
        offset += 1
        kind = tag & 3
        if kind == 0:
            length = tag >> 2
            if length >= 60:
                width = length - 59
                if offset + width > len(data):
                    raise ParseError('Truncated Snappy literal length.')
                length = int.from_bytes(data[offset:offset + width], 'little')
                offset += width
            length += 1
            if offset + length > len(data) or len(output) + length > size:
                raise ParseError('Snappy literal outside input/output bounds.')
            output.extend(data[offset:offset + length])
            offset += length
        else:
            width = {1: 1, 2: 2, 3: 4}[kind]
            if offset + width > len(data):
                raise ParseError('Truncated Snappy copy.')
            distance = int.from_bytes(data[offset:offset + width], 'little')
            offset += width
            length = ((tag >> 2) & 7) + 4 if kind == 1 else (tag >> 2) + 1
            if kind == 1:
                distance |= (tag & 0xe0) << 3
            if not distance or distance > len(output) or len(output) + length > size:
                raise ParseError('Snappy copy outside output bounds.')
            for _ in range(length):
                output.append(output[-distance])
    if len(output) != size:
        raise ParseError('Snappy decoded length mismatch.')
    return bytes(output)


def log_records(data, cancelled):
    offset = 0
    pending = None
    first = 0
    while offset < len(data):
        check_cancelled(cancelled)
        remaining = min(32768 - offset % 32768, len(data) - offset)
        if remaining < 7:
            if any(data[offset:offset + remaining]):
                raise ParseError('Nonzero/truncated LevelDB block trailer.')
            offset += remaining
            continue
        checksum, length, kind = struct.unpack_from('<IHB', data, offset)
        if not checksum and not length and not kind:
            if any(data[offset:offset + remaining]):
                raise ParseError('Invalid LevelDB zero-filled block trailer.')
            offset += remaining
            continue
        if length + 7 > remaining or kind not in (1, 2, 3, 4):
            raise ParseError('Invalid/truncated LevelDB log fragment.')
        fragment = data[offset + 7:offset + 7 + length]
        if masked_crc(bytes([kind]) + fragment, cancelled) != checksum:
            raise ParseError('LevelDB log CRC32C mismatch.')
        location = offset
        offset += 7 + length
        if kind in (1, 2):
            if pending is not None:
                raise ParseError('Incomplete LevelDB fragmented record.')
            if kind == 1:
                yield location, fragment
            else:
                pending, first = bytearray(fragment), location
        else:
            if pending is None:
                raise ParseError('Orphan LevelDB continuation fragment.')
            if len(pending) + length > MAX_BLOCK:
                raise ParseError('LevelDB fragmented record exceeds safety limit.')
            pending.extend(fragment)
            if kind == 4:
                yield first, bytes(pending)
                pending = None
    if pending is not None:
        raise ParseError('Incomplete LevelDB log tail.')


def _block_entries(data, cancelled):
    if len(data) < 8:
        raise ParseError('Truncated LevelDB restart block.')
    count = struct.unpack_from('<I', data, len(data) - 4)[0]
    end = len(data) - 4 - count * 4
    if not count or end < 0:
        raise ParseError('Invalid LevelDB restart count.')
    restarts = list(struct.unpack_from('<' + 'I' * count, data, end))
    if restarts[0] != 0 or restarts != sorted(set(restarts)) or any(value >= end for value in restarts if value):
        raise ParseError('Invalid LevelDB restart offsets.')
    previous = b''
    offset = 0
    seen = set()
    content = data[:end]
    while offset < end:
        check_cancelled(cancelled)
        location = offset
        shared, offset = varint(content, offset, 32)
        unshared, offset = varint(content, offset, 32)
        size, offset = varint(content, offset, 32)
        if shared > len(previous) or unshared + size > end - offset:
            raise ParseError('Invalid LevelDB prefix-compressed entry.')
        if location in restarts:
            if shared:
                raise ParseError('LevelDB restart entry has a shared prefix.')
            seen.add(location)
        key = previous[:shared] + content[offset:offset + unshared]
        offset += unshared
        value = content[offset:offset + size]
        offset += size
        yield location, key, value
        previous = key
    if end and seen != set(restarts):
        raise ParseError('LevelDB restart does not point to an entry.')


def table_records(data, cancelled):
    if len(data) < 48 or int.from_bytes(data[-8:], 'little') != MAGIC:
        raise ParseError('Unsupported LevelDB SST footer/magic.')
    footer = data[-48:-8]
    _, position = varint(footer, 0)
    _, position = varint(footer, position)
    index_offset, position = varint(footer, position)
    index_size, position = varint(footer, position)
    if any(footer[position:]):
        raise ParseError('Nonzero LevelDB footer padding.')

    def block(start, size):
        if size > MAX_BLOCK or start + size + 5 > len(data) - 48:
            raise ParseError('LevelDB block handle outside file or safety limit.')
        raw = data[start:start + size]
        kind = data[start + size]
        checksum = struct.unpack_from('<I', data, start + size + 1)[0]
        if masked_crc(raw + bytes([kind]), cancelled) != checksum:
            raise ParseError('LevelDB table block CRC32C mismatch.')
        if kind == 0:
            return raw
        if kind == 1:
            return snappy(raw, cancelled)
        raise ParseError(f'Unsupported LevelDB compression type {kind}.')

    visited = set()
    for _, _, handle in _block_entries(block(index_offset, index_size), cancelled):
        start, position = varint(handle, 0)
        size, position = varint(handle, position)
        if position != len(handle) or start in visited or start + size + 5 > index_offset:
            raise ParseError('Invalid/duplicate LevelDB data block handle.')
        visited.add(start)
        for location, key, value in _block_entries(block(start, size), cancelled):
            if len(key) < 8:
                raise ParseError('LevelDB internal key missing sequence/type trailer.')
            tag = int.from_bytes(key[-8:], 'little')
            if tag & 255 not in (0, 1):
                raise ParseError('Unsupported LevelDB internal value type.')
            yield f'block:{start}/entry:{location}', tag >> 8, tag & 255, key[:-8], value


def _text(data):
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return None


def _dom_text(data):
    if not data or data[0] not in (0, 1):
        return None
    try:
        return data[1:].decode('utf-16-le' if data[0] == 0 else 'latin-1')
    except UnicodeDecodeError:
        return None


def _record(locator, sequence, kind, key, value, path):
    values = dict(sequence=sequence, operation='put' if kind else 'delete',
                  key_hex=key.hex(), value_hex=value.hex(), key_utf8=_text(key), value_utf8=_text(value),
                  interpretation='Physical record only; may be superseded or absent from the active manifest.')
    if '/Local Storage/' in path and key.startswith(b'_') and b'\0' in key:
        origin, stored_key = key[1:].split(b'\0', 1)
        values.update(origin=origin.decode('latin-1'), storage_key=_dom_text(stored_key),
                      storage_value=_dom_text(value) if kind else None)
    elif '/Local Storage/' in path and key.startswith(b'META:') and kind:
        values['origin'] = key[5:].decode('latin-1')
        try:
            offset = 0
            fields = {}
            while offset < len(value):
                tag, offset = varint(value, offset)
                if tag & 7 != 0 or tag >> 3 not in (1, 2) or tag >> 3 in fields:
                    raise ParseError('Unsupported Local Storage metadata protobuf.')
                fields[tag >> 3], offset = varint(value, offset)
            values.update(storage_metadata_time_raw=fields.get(1),
                          storage_metadata_time_utc=utc_time(fields.get(1), 1000000, 1601),
                          storage_size_bytes=fields.get(2),
                          timestamp_note='Timestamp belongs to this metadata record; not assigned to other keys or interpreted as a website visit.')
        except ParseError as error:
            values['storage_decode_error'] = str(error)
    elif '/Session Storage/' in path:
        text = _text(key)
        mapped = re.fullmatch(r'map-([0-9]+)-(.*)', text or '', re.DOTALL)
        namespace = re.fullmatch(r'namespace-([0-9a-fA-F_\-]{36})-(.*)', text or '', re.DOTALL)
        if mapped:
            values.update(storage_map_id=mapped[1], storage_key=mapped[2])
            if kind:
                try:
                    values['storage_value'] = value.decode('utf-16-le')
                except UnicodeDecodeError:
                    values['storage_decode_error'] = 'Invalid UTF-16-LE Session Storage value; binary bytes retained.'
        elif namespace:
            values.update(storage_namespace=namespace[1], origin=namespace[2],
                          storage_map_id=_text(value) if kind else None)
    return entry('leveldb_record', locator, **values)


def parse(data, path, cancelled):
    if path.endswith(('.ldb', '.sst')):
        for locator, sequence, kind, key, value in table_records(data, cancelled):
            yield _record(locator, sequence, kind, key, value, path)
        return
    for location, batch in log_records(data, cancelled):
        if len(batch) < 12:
            raise ParseError('Truncated LevelDB write batch.')
        sequence, count = struct.unpack_from('<QI', batch)
        if count > len(batch) - 12 or sequence + count > 1 << 56:
            raise ParseError('Invalid LevelDB batch count/sequence.')
        offset = 12
        for index in range(count):
            check_cancelled(cancelled)
            if offset >= len(batch) or batch[offset] not in (0, 1):
                raise ParseError('Invalid LevelDB write-batch operation.')
            kind = batch[offset]
            key, offset = _slice(batch, offset + 1)
            value = b''
            if kind:
                value, offset = _slice(batch, offset)
            yield _record(f'log:{location}/batch:{index}', sequence + index, kind, key, value, path)
        if offset != len(batch):
            raise ParseError('LevelDB write-batch count does not consume its payload.')
