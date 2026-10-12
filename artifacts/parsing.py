"""Dispatch structured parsers independently of file hashing and raw collection."""
from artifacts.catalog import source_links
from artifacts.parser_support import check_cancelled, read_verified
from artifacts.sqlite_snapshot import open_snapshot
from artifacts.accounts.parser import parse as accounts
from artifacts.installed_apps.parser import parse as packages
from artifacts.device_info.parser import parse as device
from artifacts.os_activity.parser import parse as activity
from artifacts.browsers.parser import browser_json, browser_sqlite
from artifacts.email.parser import parse as mail, thunderbird_index
from artifacts.communication.parser import skype, telegram_export
from artifacts.devices import bluetooth
from artifacts.persistence import parse as persistence
from artifacts.os_activity.journal import parse as journal
from artifacts.os_activity.lastlog import binary as lastlog, sqlite as lastlog2
from artifacts.installed_apps.rpm import sqlite as rpm_sqlite, ndb as rpm_ndb, bdb as rpm_bdb
from artifacts.installed_apps.app_state import parse as app_state
from artifacts.leveldb import parse as leveldb
from artifacts.browsers.sessions import parse as firefox_snapshot, permissions as firefox_permissions
from artifacts.email.pff import parse as pff
from artifacts.communication.native_metadata import signal_config, signal_messages
from artifacts.communication.protected import signal_key
from artifacts.communication.sqlcipher import RawKeyDecoder
from artifacts.communication.telegram_crypto import parse as telegram_protected
from artifacts.browsers.credentials import firefox_keys, firefox_value
from artifacts.browsers.legacy_credentials import keys as firefox_legacy_keys
from artifacts.browsers.indexeddb import parse as indexeddb, firefox as firefox_indexeddb
from artifacts.decryption import chromium_value
from artifacts.companions import read_companion, companion_names, verify_companion
from artifacts.protected_keys import resolve_safestorage, INDEX as KEY_INDEX
from artifacts.parser_support import ParseError, entry
import os

PERSISTENCE_PARSERS = {'extension_manifest', 'firefox_extensions', 'apt_sources', 'authorized_keys',
                      'known_hosts', 'anacron_state', 'remote_trace', 'loader_config', 'sudoers',
                      'startup_script', 'logging_config', 'repository_config'}

SQLITE_PARSERS = {'app_onedrive_db', 'app_sync_db', 'firefox_places','firefox_cookies','firefox_forms','firefox_downloads',
                  'chromium_history','chromium_cookies','chromium_logins','chromium_autofill',
                  'thunderbird_index','skype','lastlog2','rpm_sqlite','firefox_permissions','signal_messages','firefox_indexeddb'}


def parse_artifact(definition,path,metadata,data,directory_fd,cancelled,context=None):
    result = {'artifact_id':definition['id'],'parser':definition['parser'],'parser_version':1,
              'status':'raw_only','record_count':0,'entries':[], 'sources':source_links(definition),
              'limitations':[definition['notes']] if definition['notes'] else [],
              'inputs':[{'path':path,'sha256':metadata['sha256'],'size':metadata['size']}]}
    parser = definition['parser']
    if parser is None:
        return result
    check_cancelled(cancelled)
    connection = None
    context = context or {}
    enabled = context.get('decrypt_protected', True)
    secrets = context.get('_decryption_secrets', {}) if enabled else {}
    targets = context.get('_selected_paths', [os.path.dirname(path)])
    rule_id = {'firefox_logins': 'firefox_nss', 'signal_messages': 'signal_config',
               'telegram_native_metadata': 'telegram_local'}.get(parser)
    if enabled and rule_id:
        result['key_discovery_rules'] = [rule for rule in KEY_INDEX['rules'] if rule['id'] == rule_id]
    discovered_supporting = []
    if enabled and parser in ('chromium_logins', 'chromium_cookies', 'signal_messages') and not secrets.get('safe_storage_password'):
        discovered, discovered_supporting, warnings = resolve_safestorage(path, targets, cancelled, secrets)
        secrets = dict(secrets, **discovered)
        result['limitations'].extend(warnings)
        result['inputs'].extend({key: item[key] for key in ('path', 'sha256', 'size')} for item, _ in discovered_supporting)
        result['_supporting_snapshots'] = discovered_supporting
        if discovered_supporting:
            used_rules = {item['key_rule'] for item, _ in discovered_supporting}
            result['key_discovery_rules'] = result.get('key_discovery_rules', []) + [rule for rule in KEY_INDEX['rules'] if rule['id'] in used_rules]
            result['key_discovery_inputs'] = [dict(path=item['path'], sha256=item['sha256'],
                                                 rule=item['key_rule'], locator=item['key_locator'])
                                             for item, _ in discovered_supporting]
    companions = {}
    def companion_reader(companion_path):
        if parser == 'leveldb' and os.path.abspath(companion_path) == os.path.abspath(path):
            return data
        if companion_path not in companions:
            from artifacts.leveldb import MAX_BLOCK
            companion_data, companion_metadata = read_companion(companion_path, targets, cancelled, MAX_BLOCK)
            companions[companion_path] = (companion_metadata, companion_data)
        return companions[companion_path][1]
    companion_reader.snapshots = companions
    try:
        if parser in SQLITE_PARSERS:
            decoder = None
            key_inputs = []
            if parser == 'signal_messages' and not metadata.get('content_retained', True):
                data, _ = read_verified(path, metadata, directory_fd, cancelled)
            if parser == 'signal_messages' and not data.startswith(b'SQLite format 3\0'):
                try:
                    if not enabled:
                        raise ParseError('Offline decryption disabled.')
                    key, key_inputs = signal_key(path, targets, secrets, cancelled)
                    decoder = RawKeyDecoder(key)
                except (ParseError, OSError) as error:
                    check_cancelled(cancelled)
                    result.update(status='partial', entries=[entry('encrypted_chat_store', 'offset:0',
                                  content_decrypted=False, decryption_error=str(error))], record_count=1)
                    result['limitations'].append(str(error))
                    return result
            connection,result['inputs'],warnings,supporting = open_snapshot(path,metadata,data,directory_fd,cancelled, decoder)
            result['inputs'].extend({key: item[key] for key in ('path', 'sha256', 'size')} for item, _ in discovered_supporting)
            supporting.extend(key_inputs)
            result['inputs'].extend({key: item[key] for key in ('path','sha256','size')} for item, _ in key_inputs)
            result['limitations'].extend(warnings)
            result['_supporting_snapshots'] = discovered_supporting + supporting
            sqlite_handlers = {'thunderbird_index': thunderbird_index, 'skype': skype,
                               'lastlog2': lastlog2, 'rpm_sqlite': rpm_sqlite,
                               'firefox_permissions': firefox_permissions, 'signal_messages': signal_messages}
            credential_decoder = (lambda raw: chromium_value(raw, secrets.get('safe_storage_password', ''))) if enabled else None
            if parser == 'firefox_indexeddb':
                rows, warnings, result['status'] = firefox_indexeddb(connection, cancelled, path, companion_reader)
                result['limitations'].extend(warnings)
                supporting.extend(companions.values())
                result['inputs'].extend({key: item[key] for key in ('path','sha256','size')} for item, _ in companions.values())
            else:
                if parser.startswith('app_'):
                    from artifacts.applications import sqlite as application_sqlite
                    rows = application_sqlite(parser, connection, cancelled)
                else:
                    rows = sqlite_handlers[parser](connection, cancelled) if parser in sqlite_handlers else browser_sqlite(parser,connection,cancelled,credential_decoder)
                if parser == 'signal_messages':
                    from artifacts.communication.attachments import extract as signal_attachments
                    rows = list(rows)
                    extracted, warnings = signal_attachments(connection, path, companion_reader, cancelled, enabled)
                    rows.extend(extracted)
                    result['limitations'].extend(warnings)
                    if warnings:
                        result['status'] = 'partial'
                    result['_supporting_snapshots'].extend(companions.values())
                    result['inputs'].extend({key: item[key] for key in ('path', 'sha256', 'size')} for item, _ in companions.values())
        else:
            if parser.startswith('distro_'):
                from artifacts.distribution_metadata import MAX_INPUT
                if metadata['size'] > MAX_INPUT:
                    raise ParseError('Distribution metadata exceeds 32 MiB parser limit; raw evidence retained.')
            if not metadata.get('content_retained',True):
                data,_ = read_verified(path,metadata,directory_fd,cancelled)
            if parser.startswith('distro_'):
                from artifacts.distribution_metadata import parse as distribution_metadata
                rows = distribution_metadata(parser, data, path, cancelled)
            elif parser.startswith('app_'):
                from artifacts.applications import parse as application_config
                rows = application_config(parser, data, path, cancelled)
            elif parser in ('passwd','group','shadow','subids'):
                rows = accounts(parser,data,path,cancelled)
            elif parser in ('dpkg','apk','pacman','desktop','package_log'):
                rows = packages(parser,data,path,cancelled)
            elif parser in ('os_release','identity','fstab','ssh','network_profile','network_text'):
                rows = device(parser,data,path,cancelled)
            elif parser in ('firefox_logins','chromium_bookmarks','chromium_preferences'):
                credential_decoder = None
                if parser == 'firefox_logins' and enabled:
                    try:
                        key_path = os.path.join(os.path.dirname(path), 'key4.db')
                        try:
                            key_data, key_metadata = read_companion(key_path, targets, cancelled)
                        except FileNotFoundError:
                            key_path = os.path.join(os.path.dirname(path), 'key3.db')
                            key_data, key_metadata = read_companion(key_path, targets, cancelled)
                            keys = firefox_legacy_keys(key_data, secrets.get('firefox_password', ''), cancelled)
                            inputs = [{key: key_metadata[key] for key in ('path', 'size', 'sha256')}]
                            warnings, supporting = [], []
                        else:
                            key_connection, inputs, warnings, supporting = open_snapshot(key_path, key_metadata, key_data, directory_fd, cancelled)
                            try:
                                keys = firefox_keys(key_connection, secrets.get('firefox_password', ''), cancelled)
                            finally:
                                key_connection.close()
                        credential_decoder = lambda value: firefox_value(value, keys)
                        result['inputs'].extend(inputs)
                        result['_supporting_snapshots'] = [(key_metadata, key_data)] + supporting
                        result['limitations'].extend(warnings)
                    except (ParseError, OSError) as error:
                        check_cancelled(cancelled)
                        result['limitations'].append('Firefox credentials locked: ' + str(error))
                rows = browser_json(parser,data,cancelled,credential_decoder)
            elif parser in ('mail','thunderbird_mail'):
                rows = mail(parser,data,path,cancelled)
            elif parser.startswith('crypto_'):
                from artifacts.cryptocurrency.parser import parse as cryptocurrency
                rows, warnings, result['status'] = cryptocurrency(parser, data, path, cancelled)
                result['limitations'].extend(warnings)
            elif parser == 'telegram_export':
                rows = telegram_export(data,cancelled)
            elif parser == 'bluez_info':
                rows = bluetooth(data,path,cancelled)
            elif parser in PERSISTENCE_PARSERS:
                rows = persistence(parser,data,path,cancelled)
            elif parser == 'journal':
                rows = journal(data,cancelled,path,metadata,directory_fd)
            elif parser == 'lastlog':
                rows = lastlog(data, cancelled)
            elif parser == 'rpm_ndb':
                rows = rpm_ndb(data, cancelled)
            elif parser == 'rpm_bdb':
                rows = rpm_bdb(data, cancelled)
            elif parser in ('snap_state', 'flatpak_metadata'):
                rows = app_state(parser, data, cancelled)
            elif parser == 'leveldb':
                if '/IndexedDB/' in str(path):
                    rows, warnings, status = indexeddb(data, path, cancelled, companion_reader,
                                                      lambda directory: companion_names(directory, targets))
                    result['_supporting_snapshots'] = list(companions.values())
                    result['inputs'].extend({key: item[key] for key in ('path','sha256','size')} for item, _ in companions.values())
                    result['limitations'].extend(warnings)
                    result['status'] = status
                else:
                    rows = leveldb(data, path, cancelled)
            elif parser in ('firefox_session', 'firefox_bookmark_backup'):
                rows = firefox_snapshot(parser, data, cancelled)
            elif parser == 'pff':
                rows, warnings, status = pff(data, cancelled)
                result['limitations'].extend(warnings)
                result['status'] = status
            elif parser == 'telegram_native_metadata':
                rows, warnings, status, supporting = telegram_protected(data, path, targets, secrets, enabled, cancelled)
                result['limitations'].extend(warnings)
                result['status'] = status
                result['_supporting_snapshots'] = supporting
                result['inputs'].extend({key: item[key] for key in ('path','sha256','size')} for item, _ in supporting)
            elif parser == 'signal_config':
                rows = signal_config(data, cancelled)
                result['status'] = 'partial'
            elif parser in ('gnome_keyring', 'kwallet'):
                from artifacts.keyrings import gnome, kwallet
                try:
                    if not enabled:
                        raise ParseError('Offline decryption disabled.')
                    password = secrets.get('keyring_passwords', {}).get(path, secrets.get('gnome_password' if parser == 'gnome_keyring' else 'kwallet_password', ''))
                    if parser == 'gnome_keyring':
                        rows = gnome(data, password, cancelled)
                    else:
                        salt = companion_reader(path[:-4] + '.salt') if len(data) >= 16 and data[13] == 1 else None
                        rows = kwallet(data, password, salt, cancelled)
                        result['_supporting_snapshots'] = list(companions.values())
                        result['inputs'].extend({key: item[key] for key in ('path', 'sha256', 'size')} for item, _ in companions.values())
                except (ParseError, ImportError, OSError) as error:
                    check_cancelled(cancelled)
                    rows = [entry('protected_keyring', 'offset:0', format=parser, decryption_status='locked', decryption_error=str(error))]
                    result['status'] = 'partial'
                    result['limitations'].append(str(error))
            else:
                rows = activity(parser,data,path,cancelled)
        if parser == 'leveldb' and companions:
            verify_companion(path, metadata, targets)
            for companion_path, (companion_metadata, _) in companions.items():
                verify_companion(companion_path, companion_metadata, targets)
        result['entries'] = [_json_safe(row) for row in rows]
        check_cancelled(cancelled)
        result['record_count'] = len(result['entries'])
        if any(row.get('decryption_status') == 'locked' for row in result['entries']):
            result['status'] = 'partial'
            result['limitations'].append('Some protected artifact values remain locked; see per-record decryption status.')
        if result['status'] == 'raw_only':
            result['status'] = 'parsed'
        return result
    finally:
        if connection is not None:
            connection.close()


def _json_safe(value):
    if isinstance(value, bytes):
        return {'encoding': 'hex', 'value': value.hex(), 'byte_length': len(value)}
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value
