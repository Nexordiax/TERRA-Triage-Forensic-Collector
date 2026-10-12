"""Read-only distribution metadata parsers; never evaluate package scripts."""
import configparser
import bz2
import csv
import gzip
import io
import json
import lzma
import plistlib
import re
from datetime import datetime
from pathlib import Path

from artifacts.parser_support import ParseError, check_cancelled, entry, text_lines, utc_time

MAX_INPUT = 32 * 1024 * 1024
MAX_RECORDS = 100000


def bounded_input(data, cancelled, path=''):
    check_cancelled(cancelled)
    if len(data) > MAX_INPUT:
        raise ParseError('Distribution metadata exceeds 32 MiB parser limit; raw evidence retained.')
    wrapper = (gzip.GzipFile if data.startswith(b'\x1f\x8b') or str(path).endswith('.gz') else
               bz2.BZ2File if data.startswith(b'BZh') or str(path).endswith('.bz2') else
               lzma.LZMAFile if data.startswith(b'\xfd7zXZ\0') or str(path).endswith('.xz') else None)
    if wrapper:
        output = bytearray()
        stream = io.BytesIO(data)
        with (wrapper(fileobj=stream) if wrapper is gzip.GzipFile else wrapper(stream)) as source:
            while chunk := source.read(min(1024 * 1024, MAX_INPUT + 1 - len(output))):
                check_cancelled(cancelled)
                output.extend(chunk)
                if len(output) > MAX_INPUT:
                    raise ParseError('Expanded package metadata exceeds 32 MiB; raw evidence retained.')
        data = bytes(output)
    return data


def json_values(value):
    if isinstance(value, datetime):
        return dict(timestamp_raw=value.isoformat(), timezone_note='Original plist date representation')
    if isinstance(value, dict):
        return {key: json_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_values(item) for item in value]
    return value


def parse(parser, data, path, cancelled):
    data = bounded_input(data, cancelled, path)
    if parser == 'distro_gentoo':
        parent = Path(path).parent
        match = re.fullmatch(r'(.+?)-([0-9].*)', parent.name)
        if not match:
            raise ParseError('Portage VDB directory lacks a package/version name.')
        value = data.decode('utf-8', errors='replace').strip()
        values = dict(manager='portage', package=match[1], version=match[2],
                      package_category=parent.parent.name, metadata_field=Path(path).name,
                      value=value, registered=True,
                      note='VDB metadata presence, not proof of execution. Build time is not installation time.')
        if Path(path).name == 'BUILD_TIME':
            if not value.isdecimal():
                raise ParseError('Invalid Portage BUILD_TIME.')
            values.update(build_time_raw=value, build_time_utc=utc_time(int(value)))
        yield entry('package_metadata', 'offset:0', **values)
    elif parser == 'distro_slackware':
        headers = {}
        for number, line in text_lines(data, '', cancelled):
            if line.strip() == 'FILE LIST:':
                break
            match = re.match(r'^(PACKAGE [A-Z ]+):\s*(.*)$', line)
            if match:
                headers[match[1]] = match[2]
        tag = headers.get('PACKAGE NAME')
        if not tag:
            raise ParseError('Slackware PACKAGE NAME header missing.')
        fields = tag.rsplit('-', 3)
        if len(fields) != 4 or not all(fields):
            raise ParseError('Invalid Slackware package name/version/architecture/build.')
        removed = any(part in ('removed-packages', 'removed_packages') for part in Path(path).parts)
        yield entry('package_record', 'PACKAGE NAME', manager='pkgtools', package=fields[0],
                    version=fields[1], architecture=fields[2], build=fields[3],
                    installed=not removed, removed_record=removed, fields=headers,
                    note='Registration or historical removal record; no execution or installation timestamp inferred.')
    elif parser == 'distro_nix':
        document = json.loads(data)
        if not isinstance(document, dict) or type(document.get('version')) is not int or document['version'] not in (1, 2, 3):
            raise ParseError('Unsupported Nix profile manifest version.')
        elements = document.get('elements')
        if not isinstance(elements, (list, dict)) or len(elements) > MAX_RECORDS:
            raise ParseError('Invalid/oversized Nix profile elements.')
        for key, value in (elements.items() if isinstance(elements, dict) else enumerate(elements)):
            check_cancelled(cancelled)
            if not isinstance(value, dict) or not isinstance(value.get('storePaths'), list) or not all(isinstance(item, str) for item in value['storePaths']):
                raise ParseError('Invalid Nix profile element/storePaths.')
            yield entry('profile_package', f'elements:{key}', manager='nix', profile_element=str(key),
                        manifest_version=document['version'], attribute=value.get('attrPath'),
                        store_paths=value['storePaths'], active_in_profile=value.get('active'),
                        source_url=value.get('url', value.get('uri')),
                        original_url=value.get('originalUrl', value.get('originalUri')), fields=value,
                        note='May describe a historical profile generation. Manifest and referenced Nix expressions are not evaluated.')
    elif parser == 'distro_xbps':
        if b'<!ENTITY' in data.replace(b'\x00', b'').upper():
            raise ParseError('XML entity declarations are not accepted.')
        document = plistlib.loads(data)
        if not isinstance(document, dict) or len(document) > MAX_RECORDS:
            raise ParseError('Invalid/oversized XBPS package database dictionary.')
        for name, values in document.items():
            check_cancelled(cancelled)
            if not isinstance(values, dict) or not isinstance(values.get('pkgver'), str):
                raise ParseError('XBPS package record lacks pkgver.')
            pkgver = values['pkgver']
            prefix = name + '-'
            yield entry('package_record', f'package:{name}', manager='xbps', package=name,
                        version=pkgver[len(prefix):] if pkgver.startswith(prefix) else None,
                        package_version_raw=pkgver, architecture=values.get('architecture'),
                        status=values.get('state'), installed=values.get('state') == 'installed',
                        install_date_raw=values.get('install-date'), automatic=values.get('automatic-install'),
                        fields=json_values(values), note='Unpacked/half-removed states are not labelled fully installed.')
    elif parser == 'distro_zypp':
        record_count = 0
        for number, line in text_lines(data, '', cancelled):
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            check_cancelled(cancelled)
            record_count += 1
            if record_count > MAX_RECORDS:
                raise ParseError('Zypp transaction count exceeds parser limit; raw evidence retained.')
            fields = [value.strip() for value in next(csv.reader([line], delimiter='|', escapechar='\\', quoting=csv.QUOTE_NONE))]
            if len(fields) < 2:
                yield entry('unparsed_package_transaction', f'line:{number}', raw=line, error='Missing pipe-separated timestamp/action')
                continue
            action = fields[1]
            values = dict(manager='zypp', timestamp_raw=fields[0], action=action, columns=fields, raw=line,
                          timestamp_note='Original wall-clock timestamp retained; timezone is not inferred.')
            if action in ('install', 'remove') and len(fields) >= 6:
                values.update(package=fields[2], version=fields[3], architecture=fields[4], requested_by=fields[5])
                if action == 'install':
                    values.update(repository=fields[6] if len(fields) > 6 else None,
                                  checksum=fields[7] if len(fields) > 7 else None,
                                  transaction_id=fields[8] if len(fields) > 8 else None)
                else:
                    values['transaction_id'] = fields[6] if len(fields) > 6 else None
            elif action in ('radd', 'rremove', 'ralias', 'rurl') and len(fields) >= 3:
                values.update(repository=fields[2], repository_value=fields[3] if len(fields) > 3 else None)
            yield entry('package_transaction', f'line:{number}', **values)
    elif parser == 'distro_accountsservice':
        document = configparser.ConfigParser(interpolation=None, strict=False)
        document.optionxform = str
        document.read_string(data.decode('utf-8', errors='replace'))
        if not document.has_section('User'):
            raise ParseError('AccountsService User section missing.')
        yield entry('desktop_account_metadata', 'User', username=Path(path).name,
                    fields=dict(document['User']), note='Cached desktop preferences, not proof of an active login.')
    else:
        raise ParseError('Unsupported distribution metadata parser.')
