"""Decode IndexedDB keys and Blink/V8 values after physical LevelDB validation."""
import dataclasses
import datetime
import enum
import math
import io
import os
import re

from artifacts.leveldb import parse as physical_records, snappy, varint, MAX_BLOCK, masked_crc
from artifacts.parser_support import check_cancelled, ParseError, entry
from artifacts.sqlite_snapshot import table_rows


def json_value(value, seen=None, depth=0):
    """Preserve JS types, binary data, non-string map keys and object references."""
    if depth > 128:
        raise ParseError('Decoded IndexedDB object exceeds the nesting safety limit.')
    if value is None or isinstance(value, (str, bool, int)) and not isinstance(value, enum.Enum):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {'js_type': 'Number', 'value': str(value)}
    if isinstance(value, bytes):
        return {'encoding': 'hex', 'value': value.hex(), 'byte_length': len(value)}
    if isinstance(value, enum.Enum):
        return {'enum': type(value).__name__, 'name': value.name, 'value': value.value}
    if isinstance(value, datetime.datetime):
        value = value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
        return {'js_type': 'Date', 'value': value.isoformat()}
    seen = {} if seen is None else seen
    identity = id(value)
    if identity in seen:
        return {'$ref': seen[identity]}
    marker = str(len(seen) + 1)
    seen[identity] = marker
    convert = lambda item: json_value(item, seen, depth + 1)
    if dataclasses.is_dataclass(value):
        return {'$id': marker, 'js_type': type(value).__name__,
                **{field.name: convert(getattr(value, field.name)) for field in dataclasses.fields(value)}}
    if isinstance(value, dict):
        return {'$id': marker, 'js_type': 'Object', 'entries': [[convert(key), convert(item)] for key, item in value.items()]}
    if isinstance(value, (tuple, list, set, frozenset)):
        return {'$id': marker, 'js_type': type(value).__name__, 'values': [convert(item) for item in value]}
    raise ParseError('Unsupported decoded IndexedDB object type.')


def script_value(data, cancelled):
    from artifacts.browsers.v8_objects import decode
    if data[:3] == b'\xff\x11\x02':
        data = snappy(data[3:], cancelled)
    if len(data) > MAX_BLOCK:
        raise ParseError('IndexedDB script value exceeds the decoded-object safety limit.')
    return decode(data, cancelled)


def parse(data, path, cancelled, companion_reader=None, companion_names=None):
    warnings = []
    try:
        from dfindexeddb.indexeddb.chromium import record, blink
    except ImportError:
        record = blink = None
        warnings.append('IndexedDB decoder missing: install requirements-forensics.txt.')
    rows = []
    partial = record is None
    physical = list(physical_records(data, path, cancelled))
    if companion_reader and companion_names:
        snapshots = getattr(companion_reader, 'snapshots', {})
        before = set(snapshots)
        try:
            from artifacts.leveldb_state import annotate
            physical = annotate(physical, path, companion_reader, companion_names(os.path.dirname(path)), cancelled,
                                include_companions=True)
        except Exception:
            check_cancelled(cancelled)
            # A failed reconstruction must not make later table files disappear
            # from normal traversal as opaque supporting snapshots.
            for source in set(snapshots) - before:
                if re.fullmatch(r'[0-9]+\.(?:log|ldb|sst)', os.path.basename(source)):
                    snapshots.pop(source)
            for row in physical:
                row['state_status'] = 'unverified_physical_record'
            warnings.append('IndexedDB active manifest state could not be validated; records remain physical observations.')
    external_sources = None
    for row in physical:
        check_cancelled(cancelled)
        row['indexeddb_decode_status'] = 'deleted' if row['operation'] == 'delete' else 'unsupported'
        if record is not None:
            try:
                key = record.IndexedDbKey.FromBytes(bytes.fromhex(row['key_hex']))
                row['indexeddb_key'] = json_value(key)
                row['database_id'] = key.key_prefix.database_id
                row['object_store_id'] = key.key_prefix.object_store_id
                if row['operation'] != 'delete':
                    raw = bytes.fromhex(row['value_hex'])
                    if isinstance(key, record.ObjectStoreDataKey):
                        version, start = varint(raw, 0)
                        wrapped = raw[start:]
                        if wrapped[:3] != b'\xff\x11\x01':
                            decoded = record.ObjectStoreDataValue(version=version, blob_size=None,
                                                                  blob_offset=None, value=script_value(wrapped, cancelled))
                        else:
                            decoded = key.ParseValue(raw)
                        if decoded.blob_size is not None:
                            partial = True  # Metadata candidates do not prove historical version correspondence.
                            row['indexeddb_decode_status'] = 'external_blob_required'
                            if companion_reader:
                                if external_sources is None:
                                    external_sources = [(path, physical)]
                                    names = companion_names(os.path.dirname(path)) if companion_names else []
                                    for name in names:
                                        check_cancelled(cancelled)
                                        sibling = os.path.join(os.path.dirname(path), name)
                                        if sibling == path or not re.fullmatch(r'\d+\.(?:log|ldb|sst)', name):
                                            continue
                                        try:
                                            sibling_data = companion_reader(sibling)
                                            external_sources.append((sibling, list(physical_records(sibling_data, sibling, cancelled))))
                                        except Exception:
                                            check_cancelled(cancelled)
                                            warnings.append('An external-object metadata companion could not be validated.')
                                candidates = blob_candidates(key, decoded, row, external_sources, path, companion_reader, cancelled)
                                row['external_blob_candidates'] = candidates
                                if candidates:
                                    row['indexeddb_decode_status'] = 'decoded_blob_candidates'
                            partial |= row['indexeddb_decode_status'] == 'external_blob_required'
                    else:
                        decoded = key.ParseValue(raw)
                    row['indexeddb_value'] = json_value(decoded)
                    if row['indexeddb_decode_status'] not in ('external_blob_required', 'decoded_blob_candidates'):
                        row['indexeddb_decode_status'] = 'decoded'
            except Exception:
                check_cancelled(cancelled)
                partial = True
                # Third-party exceptions can include evidence text; expose only a generic reason.
                row['indexeddb_decode_error'] = 'Unsupported or malformed IndexedDB key/value; raw bytes preserved.'
        rows.append(row)
    if partial:
        warnings.append('Some IndexedDB objects could not be decoded. External blob references and unknown serialization tags remain explicit; this is physical evidence, not reconstructed live state.')
    return rows, warnings, 'partial' if partial else 'parsed'


def blob_candidates(key, decoded, observation, sources, path, reader, cancelled):
    """Decode referenced blobs without silently assigning superseded metadata to a value."""
    from dfindexeddb.indexeddb.chromium import record
    result, observed = [], set()
    for source, rows in sources:
        for row in rows:
            check_cancelled(cancelled)
            if row['operation'] != 'put':
                continue
            try:
                candidate = record.IndexedDbKey.FromBytes(bytes.fromhex(row['key_hex']))
                if (not isinstance(candidate, record.BlobEntryKey)
                        or candidate.key_prefix.database_id != key.key_prefix.database_id
                        or candidate.key_prefix.object_store_id != key.key_prefix.object_store_id
                        or candidate.user_key != key.encoded_user_key):
                    continue
                value = candidate.ParseValue(bytes.fromhex(row['value_hex']))
                if decoded.blob_offset >= len(value.entries):
                    continue
                blob = value.entries[decoded.blob_offset]
                if blob.blob_number is None or not 0 <= decoded.blob_size <= MAX_BLOCK:
                    continue
                folder = os.path.dirname(path)
                if not folder.endswith('.leveldb'):
                    continue
                blob_path = os.path.join(folder[:-len('.leveldb')] + '.blob',
                                         f'{key.key_prefix.database_id:x}',
                                         f'{(blob.blob_number & 0xff00) >> 8:02x}', f'{blob.blob_number:x}')
                identity = (blob_path, row['value_hex'])
                if identity in observed:
                    continue
                observed.add(identity)
                raw = reader(blob_path)
                if len(raw) != decoded.blob_size or blob.size != len(raw):
                    continue
                result.append({'metadata_source': source, 'metadata_locator': row['locator'],
                               'metadata_sequence': row['sequence'], 'blob_path': blob_path,
                               'value': json_value(script_value(raw, cancelled)),
                               'association': 'Physical metadata candidate for the same user key; live state and historical version correspondence are not established.'})
            except Exception:
                check_cancelled(cancelled)
    return result


def gecko_value(data, cancelled):
    """Bound and verify Snappy before handing a RAM stream to Google's Gecko decoder."""
    if data.startswith(b'\xff\x06\x00\x00sNaPpY'):
        plain = bytearray()
        offset = 10
        while offset < len(data):
            check_cancelled(cancelled)
            if len(data) - offset < 4:
                raise ParseError('Truncated framed Snappy header.')
            kind, length = data[offset], int.from_bytes(data[offset + 1:offset + 4], 'little')
            start, end = offset + 4, offset + 4 + length
            if end > len(data):
                raise ParseError('Truncated framed Snappy chunk.')
            chunk = data[start:end]
            if kind in (0, 1):
                if len(chunk) < 4:
                    raise ParseError('Missing framed Snappy checksum.')
                decoded = snappy(chunk[4:], cancelled) if kind == 0 else chunk[4:]
                if masked_crc(decoded, cancelled) != int.from_bytes(chunk[:4], 'little'):
                    raise ParseError('Framed Snappy checksum failed.')
                plain.extend(decoded)
                if len(plain) > MAX_BLOCK:
                    raise ParseError('Gecko object exceeds the decoded-object safety limit.')
            elif kind < 128:
                raise ParseError('Unsupported unskippable Snappy chunk.')
            offset = end
        decoded = bytes(plain)
    else:
        decoded = snappy(data, cancelled)
    return gecko_clone(decoded, cancelled)


def gecko_clone(data, cancelled):
    from dfindexeddb.indexeddb.firefox import gecko, definitions
    class Decoder(gecko.JSStructuredCloneDecoder):
        def __init__(self, decoder):
            super().__init__(decoder)
            self.nodes = 0

        def _StartRead(self):
            check_cancelled(cancelled)
            self.nodes += 1
            tag, count = self._PeekTagAndData()
            if self.nodes > 1_000_000 or len(self._object_stack) > 128:
                raise ParseError('Gecko object exceeds the node/nesting safety limit.')
            if tag == definitions.StructuredDataType.ARRAY_OBJECT and count > 1_000_000:
                raise ParseError('Gecko array exceeds the node safety limit.')
            return super()._StartRead()
    if len(data) > MAX_BLOCK:
        raise ParseError('Gecko clone exceeds the decoded-object safety limit.')
    return Decoder.FromStream(io.BytesIO(data))


def firefox(connection, cancelled, path=None, companion_reader=None):
    rows = table_rows(connection, 'object_data', ('key', 'data', 'object_store_id'))
    if rows is None:
        raise ParseError('Firefox IndexedDB object_data table missing.')
    result, warnings, partial = [], [], False
    for index, source in enumerate(rows):
        check_cancelled(cancelled)
        source = dict(source)
        row = entry('indexeddb_object', f'object_data:{index}', object_store_id=source['object_store_id'],
                    raw_key=source['key'], raw_value=source['data'], file_ids=source.get('file_ids'))
        try:
            from dfindexeddb.indexeddb.firefox import gecko
            row['key'] = json_value(gecko.IDBKey.FromBytes(source['key']))
            if isinstance(source['data'], bytes):
                value = gecko_value(source['data'], cancelled)
            elif isinstance(source['data'], int) and path and companion_reader:
                # Mozilla stores flags in the high 32 bits and the file_ids
                # index in the low 32 bits for overflow structured clones.
                pointer = source['data'] & 0xffffffffffffffff
                flags, index = pointer >> 32, pointer & 0xffffffff
                ids = source.get('file_ids')
                ids = ids.decode('utf-8') if isinstance(ids, bytes) else ids
                ids = ids.split() if isinstance(ids, str) else []
                if flags not in (0, 1) or index >= len(ids) or not re.fullmatch(r'\.[1-9]\d{0,18}', ids[index]):
                    raise ParseError('Unsupported Gecko external clone reference.')
                file_path = os.path.splitext(path)[0] + '.files/' + ids[index][1:]
                raw = companion_reader(file_path)
                value = gecko_value(raw, cancelled) if flags & 1 else gecko_clone(raw, cancelled)
                row['external_clone_path'] = file_path
            else:
                raise ParseError('External Gecko clone reference requires its blob file.')
            row['value'] = json_value(value)
            row['indexeddb_decode_status'] = 'decoded'
        except Exception:
            check_cancelled(cancelled)
            partial = True
            row['indexeddb_decode_status'] = 'unsupported'
            row['indexeddb_decode_error'] = 'Decoder unavailable, external clone, or unsupported/malformed Gecko object; raw evidence preserved.'
        result.append(row)
    if partial:
        warnings.append('Some Firefox IndexedDB objects remain undecoded; see per-record status.')
    return result, warnings, 'partial' if partial else 'parsed'
