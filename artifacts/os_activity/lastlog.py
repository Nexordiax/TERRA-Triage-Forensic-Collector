"""Last-login records; never infer target architecture from the examiner host."""
import struct

from artifacts.parser_support import ParseError, check_cancelled, entry, utc_time
from artifacts.sqlite_snapshot import table_rows


def binary(data, cancelled):
    # Linux's traditional on-disk layout uses a 32-bit time followed by
    # ll_line[32] and ll_host[256]. UID is the record's sparse-file index.
    # Other ABIs are deliberately not guessed from a divisible file length.
    if len(data) % 292:
        raise ParseError('Unsupported lastlog layout: expected Linux LE 292-byte records.')
    for offset in range(0, len(data), 292):
        check_cancelled(cancelled)
        record = data[offset:offset + 292]
        seconds = struct.unpack_from('<i', record)[0]
        if not seconds:
            if any(record):
                raise ParseError('Nonempty lastlog record has no timestamp; layout is ambiguous.')
            continue
        if seconds < 0:
            raise ParseError('Negative lastlog timestamp; unsupported layout or corrupt record.')
        fields = []
        for raw in (record[4:36], record[36:292]):
            value, separator, padding = raw.partition(b'\0')
            if separator and any(padding):
                raise ParseError('Invalid lastlog string padding; layout cannot be established.')
            fields.append(value.decode('utf-8', errors='replace'))
        yield entry('last_login', f'offset:{offset}', uid=offset // 292,
                    terminal=fields[0], host=fields[1], timestamp_raw=seconds,
                    timestamp_utc=utc_time(seconds), layout='linux_le_292',
                    note='Most recent recorded login, not a complete login history; UID is not resolved against host accounts.')


def sqlite(connection, cancelled):
    rows = table_rows(connection, 'Lastlog2', ('Name', 'Time', 'TTY', 'RemoteHost', 'Service'))
    if rows is None:
        raise ParseError('Lastlog2 table missing.')
    for index, row in enumerate(rows):
        check_cancelled(cancelled)
        yield entry('last_login', f'Lastlog2:{index}', username=row['Name'],
                    timestamp_raw=row['Time'], timestamp_utc=utc_time(row['Time']),
                    terminal=row['TTY'], host=row['RemoteHost'], service=row['Service'],
                    note='Most recent recorded login, not a complete login history.')
