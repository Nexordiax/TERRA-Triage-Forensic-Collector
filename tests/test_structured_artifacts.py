import gzip
import hashlib
import json
import os
import sqlite3
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from artifacts.catalog import CATALOG, definition_for
from artifacts.file_collector import FileCollector, CollectionCancelled
from artifacts.parsing import parse_artifact
from artifacts.parser_support import ParseError, utc_time
from artifacts.sqlite_snapshot import merge_wal
from controllers.scan_controller import ScanEngine
from controllers.export_controller import ZipExporter
from storage.memory_store import MemoryStore
from interface.widgets.file_details import FileDetails

APP = QApplication.instance() or QApplication([])


class StructuredArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / 'disk'
        self.target.mkdir()
        self.config = {'collection_mode':'all_supported','hashes':[],'keywords':[],
                       'options':dict(folder_names=False,file_names=False,file_contents=False,hash_matches=False)}

    def file(self,path,data):
        source = self.target / path
        source.parent.mkdir(parents=True,exist_ok=True)
        source.write_bytes(data.encode() if isinstance(data,str) else bytes(data))
        return source

    def parse(self,path,max_file_bytes=32*1024*1024):
        data,metadata = FileCollector(max_file_bytes).collect(str(path),lambda:False)
        directory = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:
            return parse_artifact(definition_for(path),str(path),metadata,data,directory,lambda:False)
        finally:
            os.close(directory)

    def database(self,path,schema,rows=(),wal=False):
        source = self.target / path
        source.parent.mkdir(parents=True,exist_ok=True)
        connection = sqlite3.connect(source)
        if wal:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA wal_autocheckpoint=0')
        connection.executescript(schema)
        for query,values in rows:
            connection.execute(query,values)
        connection.commit()
        if wal:
            self.addCleanup(connection.close)
            return source,connection
        connection.close()
        return source

    def scan(self):
        store = MemoryStore()
        summary = ScanEngine({'paths':[str(self.target)]},self.config,store).run()
        return summary,store

    def test_catalog_unique_and_sources_resolve(self):
        ids = [item['id'] for item in CATALOG['artifacts']]
        self.assertEqual(len(ids),len(set(ids)))
        for item in CATALOG['artifacts']:
            self.assertTrue(item['paths'])
            self.assertTrue(all(source in CATALOG['sources'] for source in item['sources']))
            self.assertEqual(item['support'],'structured' if item['parser'] else 'raw_collection')

    def test_categories_and_profiles_include_external_roots_and_flatpak_firefox(self):
        paths = {
            '/media/disk/etc/passwd': 'User Accounts',
            '/media/disk/var/lib/dpkg/status': 'Installed Applications',
            '/home/test/.var/app/org.mozilla.firefox/.mozilla/firefox/p/places.sqlite':'Browsers',
            '/home/test/.config/BraveSoftware/Brave-Browser/Profile 1/History':'Browsers',
            '/home/test/.config/opera/History':'Browsers',
            '/home/test/.config/Signal/sql/db.sqlite':'Communication',
            '/media/disk/var/log/journal/a/system.journal':'OS Activity'}
        for path,category in paths.items():
            with self.subTest(path=path):
                self.assertEqual(definition_for(path)['category'],category)
        self.assertIsNone(definition_for('/home/test/passwd'))

    def test_accounts_groups_and_shadow_metadata(self):
        passwd = self.parse(self.file('etc/passwd','test:x:1000:1000:Test User:/home/test:/bin/bash\n'))
        self.assertEqual(passwd['entries'][0]['uid'],1000)
        self.assertEqual(passwd['entries'][0]['home'],'/home/test')
        group = self.parse(self.file('etc/group','sudo:x:27:test,examiner\n'))
        self.assertEqual(group['entries'][0]['members'],['test','examiner'])
        shadow = self.parse(self.file('etc/shadow','test:!$6$hash:20000:0:99999:7:::\n'))
        self.assertTrue(shadow['entries'][0]['locked'])
        self.assertNotIn('$6$hash',json.dumps(shadow['entries']))

    def test_packages_dpkg_pacman_apk(self):
        cases = [('var/lib/dpkg/status','Package: test\nStatus: install ok installed\nVersion: 1.2\nArchitecture: amd64\nDescription: first\n second\n\n'),
                 ('var/lib/pacman/local/test-1.2/desc','%NAME%\ntest\n\n%VERSION%\n1.2\n\n%ARCH%\nx86_64\n'),
                 ('lib/apk/db/installed','P:test\nV:1.2\nA:x86_64\nT:Description\n\n')]
        for path,data in cases:
            with self.subTest(path=path):
                parsed = self.parse(self.file(path,data))
                self.assertEqual(parsed['record_count'],1)
                self.assertEqual(parsed['entries'][0]['package'],'test')
                self.assertEqual(parsed['entries'][0]['version'],'1.2')

    def test_desktop_launchers_are_recorded_not_executed(self):
        marker = self.root / 'should-not-exist'
        parsed = self.parse(self.file('usr/share/applications/test.desktop',f'[Desktop Entry]\nType=Application\nName=Test\nExec=touch {marker}\n'))
        self.assertIn('touch',parsed['entries'][0]['exec_command'])
        self.assertFalse(marker.exists())

    def test_device_info_and_configured_mounts(self):
        release = self.parse(self.file('etc/os-release','NAME="Kali Linux"\nID=kali\n'))
        self.assertEqual(release['entries'][0]['fields']['NAME'],'Kali Linux')
        mounts = self.parse(self.file('etc/fstab','UUID=test / ext4 defaults 0 1\n'))
        self.assertEqual(mounts['entries'][0]['mountpoint'],'/')

    def test_bash_and_zsh_timestamps_are_not_invented(self):
        parsed = self.parse(self.file('home/test/.bash_history','#1700000000\necho first\necho second\n#1700000001\npwd\n'))
        self.assertEqual(parsed['record_count'],2)
        self.assertEqual(parsed['entries'][0]['command'],'echo first\necho second')
        zsh = self.parse(self.file('home/test/.zsh_history',': 1700000000:2;whoami\nplain command\n'))
        self.assertEqual(zsh['entries'][0]['duration_seconds'],2)
        self.assertIsNone(zsh['entries'][1]['timestamp_utc'])

    def test_syslog_audit_and_compressed_logs(self):
        log = self.parse(self.file('var/log/auth.log.1.gz',gzip.compress(b'Oct  9 10:20:30 device sshd[10]: Accepted password for test\n')))
        self.assertEqual(log['entries'][0]['host'],'device')
        self.assertNotIn('timestamp_utc',log['entries'][0])
        audit = self.parse(self.file('var/log/audit/audit.log','type=USER_LOGIN msg=audit(1700000000.123:20): uid=1000 res=success\n'))
        self.assertEqual(audit['entries'][0]['event_serial'],'20')
        self.assertEqual(audit['entries'][0]['fields']['uid'],'1000')

    def test_utmp_binary_and_truncation(self):
        data = bytearray(384)
        struct.pack_into('<h',data,0,7)
        struct.pack_into('<i',data,4,123)
        data[44:48]=b'test'
        struct.pack_into('<ii',data,340,1700000000,123456)
        parsed = self.parse(self.file('var/log/wtmp',data))
        self.assertEqual(parsed['entries'][0]['username'],'test')
        self.assertTrue(parsed['entries'][0]['timestamp_utc'].endswith('.123456+00:00'))
        with self.assertRaises(ParseError):
            self.parse(self.file('var/log/btmp',b'truncated'))

    def test_recent_documents_trash_and_xml_entities(self):
        recent = self.parse(self.file('home/test/.local/share/recently-used.xbel','<xbel><bookmark href="file:///home/test/report.pdf" visited="2026-10-09T10:00:00Z"><title>Report</title></bookmark></xbel>'))
        self.assertEqual(recent['entries'][0]['title'],'Report')
        trash = self.parse(self.file('home/test/.local/share/Trash/info/a.trashinfo','[Trash Info]\nPath=/home/test/a%20b.txt\nDeletionDate=2026-10-09T10:00:00\n'))
        self.assertEqual(trash['entries'][0]['original_path'],'/home/test/a b.txt')
        with self.assertRaises(ParseError):
            self.parse(self.file('home/test/.recently-used.xbel','<!DOCTYPE xbel [<!ENTITY a "expanded">]><xbel/>'))

    def test_firefox_visits_bookmarks_and_timestamp_precision(self):
        source = self.database('home/test/.mozilla/firefox/p/places.sqlite',
            'CREATE TABLE moz_places(id INTEGER,url TEXT,title TEXT); CREATE TABLE moz_historyvisits(id INTEGER,place_id INTEGER,visit_date INTEGER,visit_type INTEGER); CREATE TABLE moz_bookmarks(id INTEGER,fk INTEGER,type INTEGER,title TEXT,dateAdded INTEGER);',
            [('INSERT INTO moz_places VALUES (1,?,?)',('https://example.test','Example')),
             ('INSERT INTO moz_historyvisits VALUES (1,1,?,1)',(1700000000123456,)),
             ('INSERT INTO moz_bookmarks VALUES(1,1,1,?,?)',('Bookmark',1700000000123456))])
        parsed = self.parse(source)
        self.assertEqual(parsed['record_count'],2)
        self.assertEqual(parsed['entries'][0]['url'],'https://example.test')
        self.assertTrue(parsed['entries'][0]['timestamp_utc'].endswith('.123456+00:00'))
        self.assertTrue(any(row['type']=='bookmark' for row in parsed['entries']))

    def test_chromium_downloads_and_visits(self):
        stamp = 13344473600123456
        source = self.database('home/test/.config/chromium/Default/History',
            'CREATE TABLE urls(id INTEGER,url TEXT,title TEXT); CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER); CREATE TABLE downloads(id INTEGER,target_path TEXT,start_time INTEGER,total_bytes INTEGER); CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT);',
            [('INSERT INTO urls VALUES(1,?,?)',('https://example.test','Test')),
             ('INSERT INTO visits VALUES(1,1,?)',(stamp,)),
             ('INSERT INTO downloads VALUES(1,?,?,123)',('/home/test/report.pdf',stamp)),
             ('INSERT INTO downloads_url_chains VALUES(1,0,?)',('https://example.test/report.pdf',))])
        parsed = self.parse(source)
        self.assertEqual(parsed['record_count'],2)
        self.assertTrue(parsed['entries'][0]['timestamp_utc'].startswith('2023-'))
        self.assertTrue(parsed['entries'][0]['timestamp_utc'].endswith('.123456+00:00'))
        self.assertEqual(parsed['entries'][1]['urls'],['https://example.test/report.pdf'])

    def test_wal_committed_rows_are_replayed_without_source_writes(self):
        source,connection = self.database('home/test/.config/chromium/Default/History',
            'CREATE TABLE urls(id INTEGER,url TEXT,title TEXT); CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER);',
            [('INSERT INTO urls VALUES(1,?,?)',('https://wal.test','WAL')),
             ('INSERT INTO visits VALUES(1,1,?)',(13344473600000000,))],wal=True)
        paths = [source,Path(str(source)+'-wal'),Path(str(source)+'-shm')]
        before = {path:hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        parsed = self.parse(source)
        self.assertEqual(parsed['entries'][0]['url'],'https://wal.test')
        self.assertEqual(len(parsed['inputs']),2)
        self.assertEqual(before,{path:hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})
        self.assertEqual(sorted(source.parent.iterdir()),sorted(paths))

    def test_wal_corruption_and_truncated_tail_are_detected(self):
        source,connection = self.database('home/test/.config/chromium/Default/History','CREATE TABLE urls(id INTEGER,url TEXT,title TEXT);',wal=True)
        wal = bytearray(Path(str(source)+'-wal').read_bytes())
        wal[24] ^= 1
        with self.assertRaises(ParseError):
            merge_wal(source.read_bytes(),bytes(wal))
        original = Path(str(source)+'-wal').read_bytes()
        image,warnings = merge_wal(source.read_bytes(),original+b'bad-tail')
        self.assertTrue(warnings)
        self.assertTrue(image.startswith(b'SQLite format 3'))

    def test_unsupported_views_are_not_executed(self):
        source = self.database('home/test/.config/chromium/Default/History',
            "CREATE VIEW urls AS SELECT load_extension('/bad/path') AS url; CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER);")
        with self.assertRaises(ParseError):
            self.parse(source)

    def test_parser_works_when_file_byte_cache_is_disabled(self):
        parsed = self.parse(self.file('etc/passwd','test:x:1000:1000:Test:/home/test:/bin/bash\n'),max_file_bytes=0)
        self.assertEqual(parsed['entries'][0]['username'],'test')

    def test_email_and_mbox_headers_body_attachments(self):
        content = b'From: Test <test@example.test>\nTo: Examiner <examiner@example.test>\nSubject: =?utf-8?q?T=C3=A9st?=\nDate: Tue, 14 Nov 2023 22:13:20 +0000\nMessage-ID: <id@example.test>\n\nEmail body\n'
        parsed = self.parse(self.file('home/test/message.eml',content))
        self.assertEqual(parsed['entries'][0]['subject'],'Tést')
        self.assertIn('Email body',parsed['entries'][0]['text_body'])
        mbox = self.parse(self.file('home/test/archive.mbox',b'From test Tue Nov 14 22:13:20 2023\n'+content+b'From test Tue Nov 14 22:13:21 2023\n'+content))
        self.assertEqual(mbox['record_count'],2)

    def test_skype_and_telegram_export(self):
        source = self.database('home/test/.Skype/account/main.db','CREATE TABLE Messages(id INTEGER,author TEXT,timestamp INTEGER,body_xml TEXT,convo_id INTEGER);',
                               [('INSERT INTO Messages VALUES(1,?,?,?,2)',('test',1700000000,'<message>Hello</message>'))])
        self.assertEqual(self.parse(source)['entries'][0]['author'],'test')
        telegram = self.file('home/test/ChatExport_2026/result.json',json.dumps({'name':'Test chat','id':1,'messages':[{'id':2,'from':'Test','date_unixtime':'1700000000','text':['Hello ',{'text':'world','type':'bold'}]}]}))
        self.assertEqual(self.parse(telegram)['entries'][0]['text'],'Hello world')

    def test_failed_parser_keeps_raw_evidence_and_logs_diagnostic(self):
        self.file('home/test/.config/chromium/Default/History',b'not sqlite')
        summary,store = self.scan()
        self.assertEqual(summary['parser_failures'],1)
        self.assertEqual(store.records[0]['data'],b'not sqlite')
        self.assertEqual(store.records[0]['parsed_artifact']['status'],'failed')
        self.assertTrue(any('raw evidence retained' in entry['message'] for entry in store.diagnostics))

    def test_raw_only_artifacts_do_not_claim_parsed_findings(self):
        self.file('home/test/.config/Signal/attachments.noindex/opaque',b'encrypted bytes')
        summary,store = self.scan()
        self.assertEqual(summary['parsed_records'],0)
        self.assertEqual(store.records[0]['parsed_artifact']['status'],'raw_only')

    def test_matches_only_does_not_include_unmatched_account_files(self):
        self.file('etc/passwd','test:x:1000:1000:Test:/home/test:/bin/bash\n')
        self.config['collection_mode']='matches_only'
        self.config['keywords']=['absent keyword']
        self.config['options']['file_contents']=True
        summary,store=self.scan()
        self.assertEqual(store.records,[])

    def test_scan_keeps_wal_companion_and_hash_matching(self):
        source,connection = self.database('home/test/.config/chromium/Default/History',
            'CREATE TABLE urls(id INTEGER,url TEXT,title TEXT); CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER);',
            [('INSERT INTO urls VALUES(1,?,?)',('https://wal.test','WAL')),('INSERT INTO visits VALUES(1,1,?)',(13344473600000000,))],wal=True)
        wal = Path(str(source)+'-wal')
        self.config['hashes']=[hashlib.md5(wal.read_bytes()).hexdigest()]
        self.config['options']['hash_matches']=True
        summary,store=self.scan()
        records=[record for record in store.records if record['path']==str(wal)]
        self.assertEqual(len(records),1)
        self.assertTrue(records[0]['matches']['hashes'])
        self.assertEqual(summary['parsed_records'],1)

    def test_export_contains_jsonl_csv_metadata_raw_and_catalog(self):
        source = self.file('etc/passwd','test:x:1000:1000:Test:/home/test:/bin/bash\n')
        summary,store=self.scan()
        records,diagnostics,count=store.snapshot()
        output=self.root/'result.zip'
        ZipExporter(records,diagnostics,count,{'targets':{'paths':[str(self.target)]}}).save(output)
        with zipfile.ZipFile(output) as archive:
            manifest=json.loads(archive.read('terra/manifest.json'))
            parsed=manifest['entries'][0]['parsed_artifact']
            row=json.loads(archive.read(parsed['jsonl_path']).decode().splitlines()[0])
            self.assertEqual(row['username'],'test')
            self.assertEqual(row['provenance']['source_sha256'],hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertIn(b'username',archive.read(parsed['csv_path']))
            self.assertEqual(archive.read(manifest['entries'][0]['archive_path']),source.read_bytes())
            self.assertIn('terra/analysis/linux-artifact-catalog.json',archive.namelist())
            self.assertNotIn('entries',parsed)

    def test_gui_shows_parsed_findings_and_full_row_values(self):
        self.file('etc/passwd','test:x:1000:1000:Test:/home/test:/bin/bash\n')
        summary,store=self.scan()
        dialog=FileDetails(store.get(0))
        from interface.widgets.structured_findings import StructuredFindings
        view=dialog.findChild(StructuredFindings)
        self.assertEqual(view.model.rowCount(),1)
        view.select_row(view.model.index(0,0),view.model.index(-1,-1))
        self.assertIn('test',view.details.toPlainText())
        dialog.close()

    def test_cancelled_parser_propagates_cancellation(self):
        source=self.file('etc/passwd','test:x:1000:1000:Test:/home/test:/bin/bash\n')
        data,metadata=FileCollector().collect(str(source),lambda:False)
        with self.assertRaises(CollectionCancelled):
            parse_artifact(definition_for(source),str(source),metadata,data,None,lambda:True)

    def test_additional_browser_sqlite_schemas(self):
        cases=[
            ('home/test/.mozilla/firefox/p/cookies.sqlite','CREATE TABLE moz_cookies(id INTEGER,host TEXT,name TEXT,value TEXT,creationTime INTEGER);','INSERT INTO moz_cookies VALUES(1,?,?,?,?)',('example.test','test','value',1700000000000000),'cookie'),
            ('home/test/.mozilla/firefox/p/formhistory.sqlite','CREATE TABLE moz_formhistory(id INTEGER,fieldname TEXT,value TEXT,firstUsed INTEGER);','INSERT INTO moz_formhistory VALUES(1,?,?,?)',('name','Test',1700000000000000),'form_history'),
            ('home/test/.mozilla/firefox/p/downloads.sqlite','CREATE TABLE moz_downloads(id INTEGER,source TEXT,target TEXT,startTime INTEGER);','INSERT INTO moz_downloads VALUES(1,?,?,?)',('https://example.test','file:///test',1700000000000000),'browser_download'),
            ('home/test/.config/chromium/Default/Cookies','CREATE TABLE cookies(host_key TEXT,name TEXT,encrypted_value BLOB,creation_utc INTEGER);','INSERT INTO cookies VALUES(?,?,?,?)',('example.test','cookie',b'encrypted',13344473600000000),'cookie'),
            ('home/test/.config/chromium/Default/Login Data','CREATE TABLE logins(origin_url TEXT,username_value TEXT,password_value BLOB);','INSERT INTO logins VALUES(?,?,?)',('https://example.test','test',b'encrypted'),'saved_login_metadata'),
            ('home/test/.config/chromium/Default/Web Data','CREATE TABLE autofill(name TEXT,value TEXT,date_created INTEGER);','INSERT INTO autofill VALUES(?,?,?)',('name','test',1700000000),'autofill')]
        for path,schema,query,values,kind in cases:
            with self.subTest(path=path):
                result=self.parse(self.database(path,schema,[(query,values)]))
                row=result['entries'][0]
                self.assertEqual(row['type'],kind)
                if kind=='saved_login_metadata':
                    self.assertEqual(row['password_value_encrypted_bytes'],9)
                    self.assertNotIn('password_value',row)
                if kind=='autofill':
                    self.assertTrue(row['date_created_utc'].startswith('2023-'))

    def test_browser_json_metadata_and_bookmarks(self):
        login=self.parse(self.file('home/test/.mozilla/firefox/p/logins.json',json.dumps({'logins':[{'hostname':'https://example.test','encryptedPassword':'ciphertext','timeCreated':1700000000000}]})))
        self.assertTrue(login['entries'][0]['credentials_encrypted'])
        self.assertNotIn('ciphertext',json.dumps(login['entries']))
        bookmark=self.parse(self.file('home/test/.config/chromium/Default/Bookmarks',json.dumps({'roots':{'bookmark_bar':{'type':'folder','children':[{'type':'url','name':'Test','url':'https://example.test','date_added':'13344473600000000'}]}}})))
        self.assertEqual(bookmark['entries'][0]['url'],'https://example.test')
        preferences=self.parse(self.file('home/test/.config/chromium/Default/Preferences',json.dumps({'homepage':'https://example.test','download':{'default_directory':'/home/test/Downloads'}})))
        self.assertEqual(preferences['entries'][0]['download_directory'],'/home/test/Downloads')

    def test_thunderbird_index_fish_and_subordinate_ids(self):
        index=self.database('home/test/.thunderbird/p/global-messages-db.sqlite','CREATE TABLE messages(id INTEGER,date INTEGER,headerMessageID TEXT,folderID INTEGER,messageKey INTEGER);',
                            [('INSERT INTO messages VALUES(1,?,?,2,3)',(1700000000123456,'id@example.test'))])
        self.assertTrue(self.parse(index)['entries'][0]['timestamp_utc'].endswith('.123456+00:00'))
        fish=self.parse(self.file('home/test/.local/share/fish/fish_history','- cmd: echo test\n  when: 1700000000\n'))
        self.assertEqual(fish['entries'][0]['command'],'echo test')
        subids=self.parse(self.file('etc/subuid','test:100000:65536\n'))
        self.assertEqual(subids['entries'][0]['count'],65536)

    def test_scheduled_jobs_systemd_and_ssh_network_configuration(self):
        cases=[('etc/crontab','0 * * * * root /bin/test\n','scheduled_job_configuration'),
               ('etc/systemd/system/test.service','[Service]\nExecStart=/bin/test\nExecStart=/bin/test2\n','service_configuration'),
               ('home/test/.ssh/known_hosts','example.test ssh-ed25519 keydata\n','ssh_unparsed_record'),
               ('etc/NetworkManager/system-connections/test.nmconnection','[connection]\nid=Test\n','network_configuration'),
               ('etc/hosts','127.0.0.1 localhost\n','network_configuration')]
        for path,data,kind in cases:
            with self.subTest(path=path):
                parsed=self.parse(self.file(path,data))
                self.assertEqual(parsed['entries'][0]['type'],kind)
                if path.endswith('.service'):
                    self.assertEqual(parsed['record_count'],2)

    def test_zsh_continued_command_keeps_single_record(self):
        parsed=self.parse(self.file('home/test/.zsh_history',': 1700000000:2;echo first\\\necho second\n'))
        self.assertEqual(parsed['record_count'],1)
        self.assertEqual(parsed['entries'][0]['command'],'echo first\necho second')

    def test_database_changed_during_pair_snapshot_is_rejected(self):
        source=self.database('home/test/.config/chromium/Default/History','CREATE TABLE urls(id INTEGER,url TEXT,title TEXT); CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER);')
        with patch('artifacts.sqlite_snapshot.verify_unchanged',side_effect=ParseError('source changed')):
            with self.assertRaises(ParseError):
                self.parse(source)

    def test_authentication_and_package_events_have_structured_fields(self):
        authentication=self.parse(self.file('var/log/auth.log','Oct  9 10:20:30 device sshd[10]: Accepted publickey for test from 192.0.2.1 port 12345 ssh2\n'))
        row=authentication['entries'][0]
        self.assertEqual(row['type'],'authentication_event')
        self.assertEqual(row['username'],'test')
        self.assertEqual(row['remote_address'],'192.0.2.1')
        packages=self.parse(self.file('var/log/dpkg.log','2026-10-09 10:20:30 install test:amd64 <none> 1.2\n'))
        self.assertEqual(packages['entries'][0]['action'],'install')
        self.assertEqual(packages['entries'][0]['new_version'],'1.2')
