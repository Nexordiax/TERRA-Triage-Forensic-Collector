"""Indexed, same-user/application key discovery within selected evidence only."""
import configparser
import json
import os
from pathlib import Path

from artifacts.companions import read_companion, companion_names
from artifacts.parser_support import ParseError, check_cancelled

INDEX = json.loads(Path(__file__).with_name('protected_key_index.json').read_text())
APPLICATIONS = {
    'google-chrome': ('Chrome', 'chrome'), 'google-chrome-beta': ('Chrome', 'chrome'),
    'google-chrome-unstable': ('Chrome', 'chrome'), 'chromium': ('Chromium', 'chromium'),
    'BraveSoftware': ('Brave', 'brave'), 'microsoft-edge': ('Microsoft Edge', 'microsoft-edge'),
    'Signal': ('Signal', 'signal'),
}


def _item_secret(data, label, application, password='', cancelled=lambda: False):
    """Decode the documented textual keyring; never treat binary encrypted keyrings as text."""
    if data.startswith(b'GnomeKeyring\n\r\0\n'):
        from artifacts.keyrings import gnome
        rows = gnome(data, password, cancelled)
        values = []
        for row in rows:
            item_label = row.get('label')
            if not isinstance(item_label, str) or item_label.casefold() != (label + ' Safe Storage').casefold():
                continue
            attributes = row.get('attributes', {})
            if 'application' in attributes and attributes['application'] != application:
                continue
            try:
                secret = row['secret'].decode('utf-8')
            except (UnicodeError, AttributeError):
                continue
            if secret and len(secret) <= 4096 and '\0' not in secret:
                values.append((secret, row['locator'] + '/secret'))
        return values
    file = configparser.ConfigParser(interpolation=None, strict=True)
    file.optionxform = str
    try:
        text = data.decode('utf-8-sig')
        file.read_string(text)
        # GNOME stores text secrets with g_key_file_set_value/get_value, not escaped strings.
        # Preserve significant leading/trailing spaces that ConfigParser otherwise strips.
        raw_values, current = {}, None
        for line in text.splitlines():
            if line.strip().startswith('[') and line.strip().endswith(']'):
                current = line.strip()[1:-1]
            elif current and '=' in line and not line.lstrip().startswith(('#', ';')):
                name, value = line.split('=', 1)
                raw_values[(current, name.strip())] = value
        if not file.has_section('keyring'):
            return []
        values = []
        for section in file.sections():
            if ':' in section or section == 'keyring':
                continue
            if file.get(section, 'display-name', fallback='').casefold() != (label + ' Safe Storage').casefold():
                continue
            attributes = [file.get(group, 'value', fallback='') for group in file.sections()
                          if group.startswith(section + ':attribute') and
                          file.get(group, 'name', fallback='') == 'application']
            if attributes and attributes != [application]:
                continue
            secret = raw_values.get((section, 'secret'))
            if secret is None:
                encoded = file.get(section, 'binary-secret', fallback='')
                secret = bytes.fromhex(encoded).decode('utf-8') if encoded else None
            if secret and len(secret) <= 4096 and '\0' not in secret:
                values.append((secret, 'section:' + section + '/secret'))
        return values
    except (UnicodeError, ValueError, configparser.Error):
        raise ParseError('Malformed or unsupported textual GNOME keyring.') from None


def resolve_safestorage(path, targets, cancelled, passwords=None):
    """Return one unambiguous SafeStorage value plus hashed provenance, never a generic password guess."""
    path = os.path.abspath(path)
    if '/.config/' not in path:
        return {}, [], []
    home, relative = path.split('/.config/', 1)
    app = relative.split('/', 1)[0]
    if app not in APPLICATIONS:
        return {}, [], []
    label, application = APPLICATIONS[app]
    passwords = passwords or {}
    found, supporting, warnings = [], [], []
    for directory in (home + '/.local/share/keyrings', home + '/.gnome2/keyrings'):
        check_cancelled(cancelled)
        if not any(os.path.commonpath((directory, os.path.abspath(root))) == os.path.abspath(root) for root in targets):
            continue
        # Pin and validate every directory component before enumerating names.
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in directory.split('/')[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_fd
            names = sorted(name for name in os.listdir(descriptor) if name.endswith('.keyring'))
            if len(names) > 64:
                raise ParseError('SafeStorage keyring discovery exceeded its 64-file limit.')
            for name in names:
                check_cancelled(cancelled)
                candidate = os.path.join(directory, name)
                try:
                    data, metadata = read_companion(candidate, targets, cancelled, 2 * 1024 * 1024)
                    password = passwords.get('keyring_passwords', {}).get(candidate, passwords.get('gnome_password', ''))
                    secrets = _item_secret(data, label, application, password, cancelled)
                    for secret, locator in secrets:
                        found.append(secret)
                        rule = 'gnome_binary_safestorage' if data.startswith(b'GnomeKeyring') else 'gnome_text_safestorage'
                        supporting.append((dict(metadata, path=candidate, key_rule=rule, key_locator=locator), data))
                except (OSError, ParseError) as error:
                    warnings.append(str(error))
        except FileNotFoundError:
            continue
        except (OSError, ParseError) as error:
            warnings.append(str(error))
        finally:
            os.close(descriptor)
    # Classic KWallet files: exact same-user browser folder/key association.
    if label in ('Chrome', 'Chromium'):
        from artifacts.keyrings import kwallet
        for directory in (home + '/.local/share/kwalletd', home + '/.kde/share/apps/kwallet', home + '/.kde4/share/apps/kwallet'):
            if not any(os.path.commonpath((directory, os.path.abspath(root))) == os.path.abspath(root) for root in targets):
                continue
            try:
                names = [name for name in companion_names(directory, targets) if name.endswith('.kwl')]
                if len(names) > 64:
                    raise ParseError('SafeStorage wallet discovery exceeded its 64-file limit.')
                for name in names:
                    check_cancelled(cancelled)
                    candidate = os.path.join(directory, name)
                    try:
                        data, metadata = read_companion(candidate, targets, cancelled, 2 * 1024 * 1024)
                        salt, salt_input = None, []
                        if len(data) >= 16 and data[13] == 1:
                            salt, salt_metadata = read_companion(candidate[:-4] + '.salt', targets, cancelled, 56)
                            salt_input = [(salt_metadata, salt)]
                        password = passwords.get('keyring_passwords', {}).get(candidate, passwords.get('kwallet_password', ''))
                        for row in kwallet(data, password, salt, cancelled):
                            if row.get('folder') != label + ' Keys' or row.get('label') != label + ' Safe Storage' or row.get('item_type') != 1:
                                continue
                            if not isinstance(row.get('secret'), bytes):
                                continue
                            secret = row['secret'].decode('utf-8')
                            if not secret or len(secret) > 4096 or '\0' in secret:
                                continue
                            found.append(secret)
                            supporting.append((dict(metadata, key_rule='kwallet_safestorage', key_locator=row['locator']), data))
                            supporting.extend((dict(item, key_rule='kwallet_safestorage', key_locator='salt:0'), raw)
                                              for item, raw in salt_input)
                    except (OSError, ParseError, UnicodeError, ImportError) as error:
                        warnings.append(str(error))
            except FileNotFoundError:
                continue
            except (OSError, ParseError) as error:
                warnings.append(str(error))
    if len(set(found)) > 1:
        return {}, [], warnings + ['Conflicting same-application SafeStorage items; automatic decryption was not attempted.']
    return ({'safe_storage_password': found[0]} if found else {}), supporting, list(dict.fromkeys(warnings))
