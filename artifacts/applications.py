"""Offline application configuration readers; never follow referenced paths."""
import configparser
import json
import re
from xml.etree import ElementTree

from artifacts.parser_support import ParseError, check_cancelled, entry
from artifacts.sqlite_snapshot import table_rows

MAX_CONFIG = 8 * 1024 * 1024
SECRET = re.compile(r'password|passwd|secret|token|private.?key|api.?key|credential', re.I)


def public_values(values):
    """Keep secrets in original evidence, rather than duplicating them in summaries."""
    return {key: {'value_present': bool(value), 'summary_redacted': True}
            if SECRET.search(key) else value for key, value in values.items()}


def parse(parser, data, path, cancelled):
    if len(data) > MAX_CONFIG:
        raise ParseError('Application configuration exceeds the 8 MiB parsing limit; raw evidence retained.')
    check_cancelled(cancelled)
    text = data.decode('utf-8-sig', errors='strict')
    if any(line.strip() == 'RCLONE_ENCRYPT_V0:' for line in text.splitlines()):
        return [entry('encrypted_application_config', 'offset:0', decryption_status='locked', format='rclone')]
    if parser == 'app_path':
        return [entry('application_directory_reference', 'line:1', path=text.strip(),
                      interpretation='Referenced path recorded; not followed outside selected targets.')]
    if parser in ('app_json', 'app_dropbox'):
        obj = json.loads(text)
        if not isinstance(obj, dict):
            raise ParseError('Application JSON must contain an object.')
        rows = []
        # Flatten objects with stable JSON locators, preserving account/folder context.
        def walk(value, locator, depth=0):
            check_cancelled(cancelled)
            if depth > 32:
                raise ParseError('Application JSON nesting limit exceeded.')
            if isinstance(value, dict):
                scalar = {key: item for key, item in value.items() if not isinstance(item, (dict, list))}
                if scalar:
                    rows.append(entry('application_settings', locator, values=public_values(scalar)))
                for key, item in value.items():
                    if not SECRET.search(key) and isinstance(item, (dict, list)):
                        walk(item, locator + '/' + key.replace('~', '~0').replace('/', '~1'), depth + 1)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    walk(item, locator + '/' + str(index), depth + 1)
        walk(obj, 'json:')
        return rows
    if parser == 'app_xml':
        if re.search(r'<!\s*(DOCTYPE|ENTITY)', text, re.I) or '\x00' in text:
            raise ParseError('DTD/entity declarations and non-UTF-8 XML are unsupported.')
        root = ElementTree.fromstring(text)
        allowed = {'VirtualBox', 'domain', 'pool', 'volume', 'configuration', 'cleaner'}
        if root.tag.split('}')[-1] not in allowed:
            raise ParseError('Unrecognized application XML root.')
        rows = []
        def walk(node, locator, depth=0):
            check_cancelled(cancelled)
            if depth > 64:
                raise ParseError('Application XML nesting limit exceeded.')
            tag = node.tag.split('}')[-1]
            if SECRET.search(tag):
                return
            values = public_values(node.attrib)
            if node.text and node.text.strip():
                values['text'] = node.text.strip()
            if values:
                rows.append(entry('application_xml', locator, element=tag, values=values))
            for index, child in enumerate(node):
                walk(child, locator + '/' + child.tag.split('}')[-1] + '[' + str(index) + ']', depth + 1)
        walk(root, 'xml:/' + root.tag.split('}')[-1])
        return rows
    if parser == 'app_ini' and any(line.lstrip().startswith('[') for line in text.splitlines()):
        config = configparser.ConfigParser(interpolation=None, strict=False)
        config.optionxform = str
        config.read_string(text)
        return [entry('application_settings', 'ini:' + section, section=section,
                      values=public_values(dict(config.items(section)))) for section in config.sections()]
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        check_cancelled(cancelled)
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        parts = line.split(None, 1) if parser == 'app_tor' else line.split('=', 1)
        if len(parts) != 2:
            continue
        key, value = (part.strip() for part in parts)
        rows.append(entry('application_setting', f'line:{number}', values=public_values({key: value.strip('"')})))
    return rows


def sqlite(parser, connection, cancelled):
    table, required = ('item', ('id', 'name', 'driveId', 'parentId')) if parser == 'app_onedrive_db' else ('metadata', ('path',))
    cursor = table_rows(connection, table, required)
    if cursor is None:
        raise ParseError('Unsupported application database schema: missing ' + table)
    for number, row in enumerate(cursor, 1):
        check_cancelled(cancelled)
        yield entry('cloud_sync_inventory', f'table:{table}/row:{number}', values=public_values(dict(row)),
                    interpretation='Local synchronization metadata; remote file bytes not acquired.')
