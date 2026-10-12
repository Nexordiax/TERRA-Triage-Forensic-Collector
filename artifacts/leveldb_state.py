"""Replay LevelDB manifests and identify latest observations in acquired active files.

Never open a database or claim an atomic view of a running browser's memory.
Unlisted tables remain physical history. Unknown manifest tags fail closed.
"""
import os
import re

from artifacts.leveldb import log_records, varint, _slice, parse
from artifacts.parser_support import ParseError, check_cancelled

MAX_FILES = 1000
MAX_BYTES = 256 * 1024 * 1024


def manifest(data, cancelled=lambda: False):
    files, fields = {}, {}
    edits = 0
    for _, value in log_records(data, cancelled):
        edits += 1
        if edits > 100000:
            raise ParseError('LevelDB manifest edit count exceeds the safety limit.')
        offset, deleted, added = 0, [], []
        while offset < len(value):
            check_cancelled(cancelled)
            tag, offset = varint(value, offset, 32)
            if tag == 1:
                comparator, offset = _slice(value, offset)
                if fields.get('comparator', comparator) != comparator:
                    raise ParseError('LevelDB manifest comparator changed.')
                fields['comparator'] = comparator
            elif tag in (2, 3, 4, 9):
                number, offset = varint(value, offset)
                name = {2: 'log_number', 3: 'next_file_number', 4: 'last_sequence', 9: 'previous_log_number'}[tag]
                if name == 'last_sequence' and (number >= 1 << 56 or number < fields.get(name, 0)):
                    raise ParseError('Invalid LevelDB manifest sequence.')
                fields[name] = number
            elif tag in (5, 6, 7):
                level, offset = varint(value, offset, 32)
                if level > 6:
                    raise ParseError('Unsupported LevelDB manifest level.')
                if tag == 5:
                    key, offset = _slice(value, offset)
                    if len(key) < 8:
                        raise ParseError('Truncated LevelDB compaction key.')
                else:
                    number, offset = varint(value, offset)
                    if tag == 6:
                        deleted.append((level, number))
                    else:
                        size, offset = varint(value, offset)
                        smallest, offset = _slice(value, offset)
                        largest, offset = _slice(value, offset)
                        if not number or len(smallest) < 8 or len(largest) < 8:
                            raise ParseError('Invalid LevelDB manifest table metadata.')
                        added.append(((level, number), size))
            else:
                raise ParseError('Unsupported LevelDB manifest tag; state is not reconstructed.')
        for identity in deleted:
            files.pop(identity, None)
        for identity, size in added:
            files[identity] = size
        if len(files) > MAX_FILES:
            raise ParseError('LevelDB active file count exceeds the safety limit.')
    if not edits or not all(name in fields for name in ('comparator', 'log_number', 'next_file_number', 'last_sequence')):
        raise ParseError('Incomplete LevelDB manifest metadata.')
    if len({number for _, number in files}) != len(files):
        raise ParseError('LevelDB table appears in multiple manifest levels.')
    return fields, {number: size for (_, number), size in files.items()}


def observations(path, reader, names, cancelled):
    directory = os.path.dirname(path)
    current_path = os.path.join(directory, 'CURRENT')
    current = reader(current_path)
    if not re.fullmatch(rb'MANIFEST-[0-9]+\n', current):
        raise ParseError('Invalid LevelDB CURRENT reference.')
    manifest_path = os.path.join(directory, current[:-1].decode('ascii'))
    fields, tables = manifest(reader(manifest_path), cancelled)
    selected = []
    for number, size in sorted(tables.items()):
        matches = [name for name in names if re.fullmatch(r'[0-9]+\.(?:ldb|sst)', name)
                   and int(name.split('.')[0]) == number]
        if len(matches) != 1:
            raise ParseError('A manifest table is missing or ambiguous.')
        selected.append((matches[0], size))
    previous = fields.get('previous_log_number', 0)
    logs = [name for name in names if re.fullmatch(r'[0-9]+\.log', name)
            and (int(name[:-4]) >= fields['log_number'] or int(name[:-4]) == previous)]
    # A zero previous-log number is the native sentinel, not a file reference.
    if fields['log_number'] and not any(int(name[:-4]) == fields['log_number'] for name in logs):
        raise ParseError('The manifest current log is missing.')
    if previous and not any(int(name[:-4]) == previous for name in logs):
        raise ParseError('The manifest previous log is missing.')
    selected.extend((name, None) for name in sorted(logs, key=lambda name: int(name[:-4])))
    if len(selected) > MAX_FILES:
        raise ParseError('LevelDB acquired active file count exceeds the safety limit.')
    latest, active, used, observed_rows = {}, set(), 0, []
    for name, size in selected:
        check_cancelled(cancelled)
        source = os.path.join(directory, name)
        data = reader(source)
        used += len(data)
        if used > MAX_BYTES or size is not None and len(data) != size:
            raise ParseError('LevelDB active snapshot size mismatch or RAM safety limit reached.')
        active.add(source)
        for row in parse(data, source, cancelled):
            observed_rows.append((source, row))
            if len(observed_rows) > 100000:
                raise ParseError('LevelDB physical state record count exceeds the safety limit.')
            if size is not None and row['sequence'] > fields['last_sequence']:
                raise ParseError('Table sequence exceeds its manifest sequence.')
            identity = row['key_hex']
            old = latest.get(identity)
            observation = (row['sequence'], row['operation'], row['value_hex'])
            if old and old[0] == observation[0] and old != observation:
                raise ParseError('Conflicting LevelDB records at the same sequence.')
            if old is None or observation[0] > old[0]:
                latest[identity] = observation
            if len(latest) > 100000:
                raise ParseError('LevelDB state key count exceeds the safety limit.')
    return latest, active, observed_rows, {'manifest_path': manifest_path, 'manifest_last_sequence': fields['last_sequence'],
                            'active_files_acquired': len(active), 'snapshot_bytes': used,
                            'note': 'Latest observations in the acquired manifest tables and recovery logs. '
                                    'A running process may have newer unflushed memory; this is not an atomic live database view.'}


def annotate(rows, path, reader, names, cancelled, include_companions=False):
    latest, active, observed_rows, metadata = observations(path, reader, names, cancelled)
    sources = [(path, row) for row in rows]
    if include_companions:
        sources.extend((source, row) for source, row in observed_rows if source != path)
    for source, row in sources:
        row['source_path'] = source
        row['manifest_state'] = metadata
        if source != path:
            row['locator'] = os.path.basename(source) + '/' + row['locator']
        if source not in active:
            row['state_status'] = 'outside_active_manifest'
        else:
            current = latest.get(row['key_hex'])
            observation = (row['sequence'], row['operation'], row['value_hex'])
            row['state_status'] = ('latest_acquired_delete' if row['operation'] == 'delete' else 'latest_acquired_put') if current == observation else 'superseded_acquired_record'
        row['interpretation'] = row['state_status'] + '; ' + metadata['note']
    return [row for _, row in sources]
