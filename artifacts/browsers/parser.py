"""Firefox and Chromium-family schemas with optional offline credential decoding."""
import hashlib
import json

from artifacts.parser_support import ParseError, check_cancelled, entry, utc_time
from artifacts.sqlite_snapshot import table_rows


def browser_json(parser, data, cancelled, credential_decoder=None):
    document = json.loads(data)
    if not isinstance(document, dict):
        raise ParseError('Browser JSON root must be an object.')
    if parser == 'firefox_logins':
        if not isinstance(document.get('logins'), list):
            raise ParseError('Unsupported Firefox logins schema.')
        for index, login in enumerate(document['logins']):
            check_cancelled(cancelled)
            credentials = {'credentials_encrypted': True, 'decryption_status': 'locked'}
            if credential_decoder:
                try:
                    credentials.update(username=credential_decoder(login.get('encryptedUsername')),
                                       password=credential_decoder(login.get('encryptedPassword')),
                                       credentials_encrypted=False, decryption_status='decrypted',
                                       decryption_note='NSS CBC does not authenticate individual login records.')
                except ParseError as error:
                    credentials['decryption_error'] = str(error)
            yield entry('saved_login_metadata', f'logins[{index}]', hostname=login.get('hostname'),
                        form_submit_url=login.get('formSubmitURL'), http_realm=login.get('httpRealm'),
                        created_utc=utc_time(login.get('timeCreated'), 1000),
                        last_used_utc=utc_time(login.get('timeLastUsed'), 1000),
                        times_used=login.get('timesUsed'), **credentials)
    elif parser == 'chromium_bookmarks':
        roots = document.get('roots')
        if not isinstance(roots, dict):
            raise ParseError('Unsupported Chromium bookmarks schema.')
        stack = [(name, node) for name, node in roots.items()]
        while stack:
            check_cancelled(cancelled)
            locator, node = stack.pop()
            if node.get('type') == 'url':
                yield entry('bookmark', locator, title=node.get('name'), url=node.get('url'),
                            added_utc=utc_time(node.get('date_added'), 1000000, 1601))
            stack.extend((locator + '/' + str(index), child) for index, child in enumerate(node.get('children', [])))
    elif parser == 'chromium_preferences':
        yield entry('browser_preferences', 'JSON root', homepage=document.get('homepage'),
                    download_directory=document.get('download', {}).get('default_directory'),
                    startup_urls=document.get('session', {}).get('startup_urls', []),
                    extensions=document.get('extensions', {}).get('settings', {}))


def browser_sqlite(parser, connection, cancelled, credential_decoder=None):
    if parser == 'firefox_places':
        if table_rows(connection, 'moz_places', ('id','url')) is None:
            raise ParseError('Firefox moz_places table missing.')
        recognized = False
        if table_rows(connection, 'moz_historyvisits', ('id','place_id','visit_date')) is not None:
            recognized = True
            for row in connection.execute('SELECT v.*, p.url, p.title FROM moz_historyvisits v JOIN moz_places p ON p.id=v.place_id'):
                check_cancelled(cancelled)
                row = dict(row)
                yield entry('browser_visit', f"moz_historyvisits:{row['id']}", url=row['url'], title=row.get('title'),
                            timestamp_utc=utc_time(row['visit_date'], 1000000), timestamp_raw=row['visit_date'],
                            visit_type=row.get('visit_type'), from_visit=row.get('from_visit'))
        if table_rows(connection, 'moz_bookmarks', ('id','fk','type')) is not None:
            recognized = True
            for row in connection.execute('SELECT b.*, p.url FROM moz_bookmarks b LEFT JOIN moz_places p ON p.id=b.fk WHERE b.type=1'):
                check_cancelled(cancelled)
                row = dict(row)
                yield entry('bookmark', f"moz_bookmarks:{row['id']}", url=row['url'], title=row.get('title'),
                            added_utc=utc_time(row.get('dateAdded'),1000000), modified_utc=utc_time(row.get('lastModified'),1000000))
        if table_rows(connection, 'moz_annos', ('id','place_id','anno_attribute_id','content')) is not None and table_rows(connection, 'moz_anno_attributes', ('id','name')) is not None:
            recognized = True
            for row in connection.execute("SELECT a.*, t.name, p.url FROM moz_annos a JOIN moz_anno_attributes t ON t.id=a.anno_attribute_id JOIN moz_places p ON p.id=a.place_id WHERE t.name IN ('downloads/destinationFileURI','downloads/metaData')"):
                check_cancelled(cancelled)
                row = dict(row)
                content = row['content']
                if row['name'] == 'downloads/metaData':
                    try:
                        content = json.loads(content)
                    except (ValueError, TypeError):
                        pass
                yield entry('download_annotation', f"moz_annos:{row['id']}", url=row['url'], annotation=row['name'], value=content,
                            added_utc=utc_time(row.get('dateAdded'),1000000))
        if not recognized:
            raise ParseError('No supported Firefox Places tables.')
    elif parser == 'chromium_history':
        recognized = False
        if table_rows(connection, 'urls', ('id','url')) is not None and table_rows(connection, 'visits', ('id','url','visit_time')) is not None:
            recognized = True
            for row in connection.execute('SELECT v.*, u.url AS visited_url, u.title FROM visits v JOIN urls u ON u.id=v.url'):
                check_cancelled(cancelled)
                row = dict(row)
                yield entry('browser_visit', f"visits:{row['id']}", url=row['visited_url'], title=row.get('title'),
                            timestamp_utc=utc_time(row['visit_time'],1000000,1601), timestamp_raw=row['visit_time'],
                            transition=row.get('transition'), from_visit=row.get('from_visit'))
        chains = {}
        chain_rows = table_rows(connection,'downloads_url_chains',('id','chain_index','url'))
        if chain_rows is not None:
            for row in chain_rows:
                check_cancelled(cancelled)
                chains.setdefault(row['id'], []).append((row['chain_index'], row['url']))
        downloads = table_rows(connection,'downloads',('id','start_time'))
        if downloads is not None:
            recognized = True
            for row in downloads:
                check_cancelled(cancelled)
                row = dict(row)
                modern = 'target_path' in row
                yield entry('browser_download', f"downloads:{row['id']}",
                            target_path=row.get('target_path',row.get('full_path')),
                            urls=[url for _,url in sorted(chains.get(row['id'],[]))] or ([row['url']] if row.get('url') else []),
                            started_utc=utc_time(row['start_time'],1000000 if modern else 1,1601 if modern else 1970),
                            ended_utc=utc_time(row.get('end_time'),1000000 if modern else 1,1601 if modern else 1970),
                            state=row.get('state'), received_bytes=row.get('received_bytes'), total_bytes=row.get('total_bytes'))
        if not recognized:
            raise ParseError('No supported Chromium history/download tables.')
    else:
        specification = {
            'firefox_cookies': ('moz_cookies',('host','name'), 'cookie'),
            'firefox_forms': ('moz_formhistory',('fieldname','value'),'form_history'),
            'firefox_downloads': ('moz_downloads',('id','source'),'browser_download'),
            'chromium_cookies': ('cookies',('host_key','name'),'cookie'),
            'chromium_logins': ('logins',('origin_url','username_value'),'saved_login_metadata'),
            'chromium_autofill': ('autofill',('name','value'),'autofill'),
        }
        table, required, kind = specification[parser]
        rows = table_rows(connection,table,required)
        if rows is None:
            raise ParseError(f'{table} table missing.')
        cookie_version = None
        if parser == 'chromium_cookies' and credential_decoder:
            meta = table_rows(connection, 'meta', ('key', 'value'))
            if meta is not None:
                cookie_version = next((int(item['value']) for item in meta if item['key'] == 'version'), None)
        for index, row in enumerate(rows):
            check_cancelled(cancelled)
            row = dict(row)
            values = {}
            for key,value in row.items():
                if isinstance(value,bytes):
                    values[key + '_encrypted_bytes' if key in ('encrypted_value','password_value') else key + '_bytes'] = len(value)
                else:
                    values[key] = value
            for key in ('creationTime','lastAccessed','firstUsed','lastUsed','startTime','endTime','creation_utc','last_access_utc','expires_utc','date_created','date_last_used'):
                if key in values:
                    values[key + '_utc'] = (utc_time(values[key]) if parser == 'chromium_autofill' else
                                           utc_time(values[key],1000000,1601 if parser.startswith('chromium') else 1970))
            if parser == 'firefox_cookies' and 'expiry' in values:
                values['expiry_utc'] = utc_time(values['expiry'])
            protected = 'password_value' if parser == 'chromium_logins' else 'encrypted_value'
            if parser in ('chromium_logins', 'chromium_cookies') and isinstance(row.get(protected), bytes) and row[protected]:
                values['decryption_status'] = 'locked'
                if credential_decoder:
                    try:
                        plain = credential_decoder(row[protected])
                        if parser == 'chromium_cookies':
                            host_hash = hashlib.sha256(row['host_key'].encode('utf-8')).digest()
                            if cookie_version is None:
                                raise ParseError('Cookie schema version missing; host-bound decoding deferred.')
                            if cookie_version >= 24:
                                if plain[:32] != host_hash:
                                    raise ParseError('Decrypted cookie host binding failed.')
                                plain = plain[32:]
                        values['password' if parser == 'chromium_logins' else 'value'] = plain.decode('utf-8')
                        values['decryption_status'] = 'decrypted'
                        values['decryption_note'] = 'Linux CBC ciphertext has no per-record authentication; padding and UTF-8 were validated.'
                    except (ParseError, UnicodeError) as error:
                        values['decryption_error'] = str(error) if isinstance(error, ParseError) else 'Decrypted value is not valid UTF-8.'
            yield entry(kind, f'{table}:{row.get("id",index)}', **values)
