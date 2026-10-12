"""Firefox session/bookmark snapshots and permissions, decoded locally."""
import json
import struct

from artifacts.parser_support import ParseError, check_cancelled, entry, utc_time
from artifacts.sqlite_snapshot import table_rows

MAX_DECODED = 64 * 1024 * 1024


def mozlz4(data, cancelled):
    if len(data) < 12 or data[:8] != b'mozLz40\0':
        raise ParseError('Mozilla LZ4 header missing.')
    expected = struct.unpack_from('<I', data, 8)[0]
    if expected > MAX_DECODED:
        raise ParseError('Mozilla LZ4 exceeds the 64 MiB decoded-snapshot safety limit.')
    output = bytearray()
    offset = 12

    def length(base):
        nonlocal offset
        total = base
        if base == 15:
            while True:
                if offset >= len(data):
                    raise ParseError('Truncated Mozilla LZ4 extended length.')
                value = data[offset]
                offset += 1
                total += value
                if total > expected:
                    raise ParseError('Mozilla LZ4 length exceeds declared output.')
                if value != 255:
                    break
                check_cancelled(cancelled)
        return total

    while offset < len(data):
        check_cancelled(cancelled)
        token = data[offset]
        offset += 1
        literals = length(token >> 4)
        if literals > len(data) - offset or len(output) + literals > expected:
            raise ParseError('Mozilla LZ4 literal outside bounds.')
        output.extend(data[offset:offset + literals])
        offset += literals
        if offset == len(data):
            break
        if offset + 2 > len(data):
            raise ParseError('Truncated Mozilla LZ4 match distance.')
        distance = int.from_bytes(data[offset:offset + 2], 'little')
        offset += 2
        matched = length(token & 15) + 4
        if not distance or distance > len(output) or len(output) + matched > expected:
            raise ParseError('Mozilla LZ4 match outside bounds.')
        # Repeat a small already-decoded pattern rather than one Python loop per byte.
        pattern = bytes(output[-distance:])
        for start in range(0, matched, 65536):
            check_cancelled(cancelled)
            size = min(65536, matched - start)
            position = start % distance
            rotated = pattern[position:] + pattern[:position]
            output.extend((rotated * ((size + distance - 1) // distance))[:size])
    if len(output) != expected:
        raise ParseError('Mozilla LZ4 decoded length mismatch.')
    return bytes(output)


def parse(parser, data, cancelled):
    if data.startswith(b'mozLz40\0'):
        data = mozlz4(data, cancelled)
    document = json.loads(data)
    if not isinstance(document, dict):
        raise ParseError('Firefox snapshot must be a JSON object.')
    if parser == 'firefox_bookmark_backup':
        pending = [('root', document)]
        while pending:
            check_cancelled(cancelled)
            locator, node = pending.pop()
            if not isinstance(node, dict):
                raise ParseError('Malformed Firefox bookmark node.')
            if node.get('uri'):
                yield entry('bookmark', locator, url=node['uri'], title=node.get('title'), guid=node.get('guid'),
                            date_added_utc=utc_time(node.get('dateAdded'), 1000000),
                            last_modified_utc=utc_time(node.get('lastModified'), 1000000))
            children = node.get('children', [])
            if not isinstance(children, list):
                raise ParseError('Malformed Firefox bookmark children.')
            pending.extend((f'{locator}/children:{index}', child) for index, child in reversed(list(enumerate(children))))
        return
    if not any(key in document for key in ('windows', '_closedWindows')):
        raise ParseError('Firefox session window arrays missing.')
    for section in ('windows', '_closedWindows'):
        windows = document.get(section, [])
        if not isinstance(windows, list):
            raise ParseError('Invalid Firefox session windows.')
        for window_index, window in enumerate(windows):
            check_cancelled(cancelled)
            if not isinstance(window, dict):
                raise ParseError('Invalid Firefox session window.')
            tabs = window.get('tabs', [])
            closed = window.get('_closedTabs', [])
            if not isinstance(tabs, list) or not isinstance(closed, list):
                raise ParseError('Invalid Firefox session tabs.')
            for tab_section, tab_list in (('tabs', tabs), ('_closedTabs', closed)):
                for tab_index, wrapper in enumerate(tab_list):
                    check_cancelled(cancelled)
                    tab = wrapper.get('state') if tab_section == '_closedTabs' and isinstance(wrapper, dict) else wrapper
                    if not isinstance(tab, dict) or not isinstance(tab.get('entries', []), list):
                        raise ParseError('Invalid Firefox session tab state.')
                    for history_index, value in enumerate(tab.get('entries', [])):
                        check_cancelled(cancelled)
                        if not isinstance(value, dict):
                            raise ParseError('Invalid Firefox session history entry.')
                        yield entry('browser_session_entry', f'{section}:{window_index}/{tab_section}:{tab_index}/entries:{history_index}',
                                    url=value.get('url'), title=value.get('title'),
                                    closed=section == '_closedWindows' or tab_section == '_closedTabs',
                                    selected_entry=tab.get('index') == history_index + 1,
                                    last_accessed_utc=utc_time(tab.get('lastAccessed'), 1000),
                                    last_accessed_raw=tab.get('lastAccessed'),
                                    note='Tab/session state; lastAccessed describes the tab, not a verified visit time for every entry.')


def permissions(connection, cancelled):
    rows = table_rows(connection, 'moz_perms', ('id', 'origin', 'type', 'permission'))
    if rows is None:
        raise ParseError('Firefox moz_perms table missing.')
    for row in rows:
        check_cancelled(cancelled)
        values = dict(row)
        yield entry('browser_permission', f"moz_perms:{row['id']}", fields=values,
                    modified_utc=utc_time(values.get('modificationTime'), 1000),
                    expire_utc=utc_time(values.get('expireTime'), 1000),
                    note='Stored permission configuration, not proof of site access.')
