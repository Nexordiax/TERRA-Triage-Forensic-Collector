"""Interpret stored persistence/application metadata without evaluating it."""
import base64
import hashlib
import json
import re
import shlex
import struct

from artifacts.parser_support import ParseError, check_cancelled, entry, text_lines

KEY_TYPE = re.compile(r'^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-.*@openssh.com)$')


def parse(parser, data, path, cancelled):
    if parser in ('extension_manifest', 'firefox_extensions'):
        document = json.loads(data)
        if not isinstance(document, dict):
            raise ParseError('Expected extension JSON object')
        if parser == 'extension_manifest':
            if not all(key in document for key in ('manifest_version', 'name', 'version')):
                raise ParseError('Extension manifest fields missing')
            check_cancelled(cancelled)
            yield entry('browser_extension', 'manifest.json', fields=document,
                        name=document['name'], version=document['version'],
                        permissions=document.get('permissions', []), host_permissions=document.get('host_permissions', []),
                        note='Manifest presence does not prove the extension was enabled; localized names are retained unresolved.')
        else:
            addons = document.get('addons')
            if not isinstance(addons, list):
                raise ParseError('Firefox addons list missing')
            for index, addon in enumerate(addons):
                check_cancelled(cancelled)
                if not isinstance(addon, dict):
                    raise ParseError('Malformed Firefox addon record')
                yield entry('browser_extension', f'addons:{index}', fields=addon,
                            extension_id=addon.get('id'), version=addon.get('version'), active=addon.get('active'),
                            note='Stored addon state, not an observation of execution.')
        return
    if parser == 'apt_sources' and str(path).endswith('.sources'):
        values, previous, start = {}, None, 1
        lines = list(text_lines(data, path, cancelled))
        for number, line in [*lines, (len(lines) + 1, '')]:
            check_cancelled(cancelled)
            if not line.strip():
                if values:
                    yield entry('package_repository', f'line:{start}', manager='apt', fields=values,
                                enabled=values.get('Enabled', 'yes').lower() != 'no',
                                note='Configured repository; not proof of installation or download.')
                values, previous, start = {}, None, number + 1
            elif line.lstrip().startswith('#'):
                continue
            elif line[0].isspace() and previous:
                values[previous] += '\n' + line.strip()
            elif ':' in line:
                previous, value = line.split(':', 1)
                values[previous] = value.strip()
            else:
                raise ParseError(f'Malformed apt source stanza at line {number}')
        return
    for number, line in text_lines(data, path, cancelled):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        locator = f'line:{number}'
        if parser in ('authorized_keys', 'known_hosts'):
            try:
                tokens = shlex.split(line, comments=False)
                index = next(i for i, token in enumerate(tokens) if KEY_TYPE.fullmatch(token))
                key = base64.b64decode(tokens[index + 1], validate=True)
                length = struct.unpack_from('>I', key)[0]
                if length > len(key) - 4 or key[4:4 + length].decode('ascii') != tokens[index]:
                    raise ValueError('Public key type/encoding mismatch')
                fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
                yield entry('ssh_authorized_key' if parser == 'authorized_keys' else 'ssh_known_host', locator,
                            key_type=tokens[index], public_key=tokens[index + 1], fingerprint=fingerprint,
                            prefix_fields=tokens[:index], comment=' '.join(tokens[index + 2:]),
                            note='Stored authorization/trust metadata; does not prove authentication or a connection. Hashed hostnames are not resolved.')
            except (ValueError, IndexError, StopIteration, UnicodeError, struct.error) as error:
                yield entry('ssh_unparsed_record', locator, definition=line, error=str(error))
        elif parser == 'apt_sources':
            yield entry('package_repository', locator, manager='apt', definition=line,
                        note='Configured repository; not proof of installation or download.')
        elif parser == 'repository_config':
            yield entry('package_repository_configuration', locator, definition=line,
                        note='Stored repository configuration; not proof of installation or download.')
        elif parser == 'anacron_state':
            yield entry('scheduler_timestamp', locator, date_raw=stripped,
                        note='Scheduler stored last-run date; timezone and command execution outcome unknown.')
        elif parser == 'remote_trace':
            yield entry('remote_access_log', locator, message=line,
                        note='Original application log line; session outcome/timestamps are not inferred.')
        elif parser == 'loader_config':
            yield entry('loader_configuration', locator, definition=line,
                        note='Stored loader/module configuration; referenced libraries/modules are not loaded or executed.')
        elif parser == 'sudoers':
            yield entry('privilege_policy', locator, definition=line,
                        note='Physical policy line; includes, aliases and effective permissions are not evaluated.')
        elif parser == 'startup_script':
            yield entry('startup_configuration', locator, definition=line,
                        note='Stored shell/startup definition, not proof of command execution.')
        elif parser == 'logging_config':
            yield entry('logging_configuration', locator, definition=line,
                        note='Stored configuration; referenced include files are collected only when inside selected targets.')
        else:
            raise ParseError('Unknown persistence parser')
