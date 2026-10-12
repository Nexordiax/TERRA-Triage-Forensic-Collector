"""Offline application schemas, selected scopes and independent image review."""
import hashlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from PIL import Image
from artifacts.applications import parse, sqlite
from artifacts.catalog import definition_for
from artifacts.registry import category_for
from artifacts.parser_support import ParseError
from controllers.scan_controller import ScanEngine
from storage.memory_store import MemoryStore
from tests.test_scan import configuration
from analyzers.content_worker import analyze


class ApplicationGroupTests(unittest.TestCase):
    def test_linux_paths_and_browser_parser_preserved(self):
        cases = {'.dropbox/info.json': 'Cloud Storage', '.config/Nextcloud/nextcloud.cfg': 'Cloud Storage',
                 '.config/onedrive/items.sqlite3': 'Cloud Storage', '.config/rclone/rclone.conf': 'Cloud Storage',
                 '.local/state/syncthing/config.xml': 'Cloud Storage', '.i2p/router.config': 'Dark Web Apps',
                 '.i2pd/i2pd.conf': 'Dark Web Apps', '.config/onionshare/persistent/test.json': 'Dark Web Apps',
                 '.config/bleachbit/bleachbit.ini': 'Anti-forensics Apps',
                 '.config/VirtualBox/VirtualBox.xml': 'Virtual Machines', 'machines/demo.vmx': 'Virtual Machines',
                 'machines/demo.qcow2': 'Virtual Machines'}
        for name, category in cases.items():
            self.assertEqual(category_for('/mnt/selected/home/user/' + name), category)
        definition = definition_for('/home/u/tor-browser/Browser/TorBrowser/Data/Browser/profile.default/places.sqlite')
        self.assertEqual(definition['parser'], 'firefox_places')
        self.assertIsNone(definition_for('/home/u/picture.jpg'))

    def test_config_formats_secrets_and_locked_state(self):
        rows = parse('app_ini', b'[drive]\ntype=s3\nendpoint=https://example.test\nsecret_access_key=hidden\n', '', lambda:False)
        self.assertEqual(rows[0]['values']['type'], 's3')
        self.assertNotIn('hidden', json.dumps(rows))
        rows = parse('app_dropbox', b'{"personal":{"path":"/home/u/Dropbox","host":123}}', '', lambda:False)
        self.assertEqual(rows[0]['values']['path'], '/home/u/Dropbox')
        rows = parse('app_tor', b'HiddenServiceDir /outside/secret\nHiddenServicePort 80 localhost:8080\n', '', lambda:False)
        self.assertEqual(rows[0]['locator'], 'line:1')
        self.assertEqual(parse('app_ini', b'RCLONE_ENCRYPT_V0:\nopaque', '', lambda:False)[0]['decryption_status'], 'locked')

    def test_xml_namespaces_and_reject_entities(self):
        rows = parse('app_xml', b'<VirtualBox xmlns="urn:vbox"><Machine name="demo" uuid="123"><HardDisk location="/outside/disk.vdi"/></Machine></VirtualBox>', '', lambda:False)
        self.assertEqual(rows[0]['values']['name'], 'demo')
        self.assertEqual(rows[1]['values']['location'], '/outside/disk.vdi')
        for data in (b'<!DOCTYPE domain [<!ENTITY x "payload">]><domain>&x;</domain>', b'<unrelated/>'):
            with self.assertRaises(ParseError):
                parse('app_xml', data, '', lambda:False)

    def test_sqlite_inventory_and_unsupported_schema(self):
        connection=sqlite3.connect(':memory:'); self.addCleanup(connection.close)
        connection.row_factory=sqlite3.Row
        connection.execute('CREATE TABLE item(id TEXT,name TEXT,driveId TEXT,parentId TEXT,size INTEGER)')
        connection.execute("INSERT INTO item VALUES('1','example.jpg','drive','root',123)")
        rows=list(sqlite('app_onedrive_db',connection,lambda:False))
        self.assertEqual(rows[0]['values']['name'],'example.jpg')
        connection.execute('CREATE VIEW metadata AS SELECT name AS path FROM item')
        with self.assertRaises(ParseError):list(sqlite('app_sync_db',connection,lambda:False))

    def test_live_scope_matches_only_and_raw_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); selected=root/'selected'; selected.mkdir()
            path=selected/'.config/rclone/rclone.conf';path.parent.mkdir(parents=True)
            data=b'[example]\ntype=drive\nroot_folder_id=/outside\n';path.write_bytes(data)
            outside=root/'outside';outside.mkdir();(outside/'private.txt').write_text('outside')
            store=MemoryStore(); ScanEngine({'paths':[str(selected)]},configuration(),store).run()
            self.assertEqual(len(store.records),1)
            record=store.records[0]
            self.assertEqual(record['category'],'Cloud Storage')
            self.assertEqual(record['parsed_artifact']['status'],'parsed')
            self.assertEqual(record['data'],data)
            self.assertEqual(path.read_bytes(),data)
            store=MemoryStore();ScanEngine({'paths':[str(selected)]},configuration(mode='matches_only'),store).run()
            self.assertEqual(store.records,[])
            config=configuration(mode='matches_only',hashes=[hashlib.md5(data).hexdigest()],hash_matches=True)
            store=MemoryStore();ScanEngine({'paths':[str(selected)]},config,store).run()
            self.assertEqual(len(store.records),1)
            self.assertIn('hashes',store.records[0]['matches'])


    def test_live_categories_locked_and_failed_configs_export(self):
        from reporting.structured_export import write_structured
        import zipfile
        fixtures = {
            '.config/rclone/rclone.conf': b'# Encrypted rclone configuration File\nRCLONE_ENCRYPT_V0:\nopaque',
            'etc/tor/torrc': b'SocksPort 9050\nHiddenServiceDir /not-selected\n',
            '.config/bleachbit/bleachbit.ini': b'[tree]\nfirefox.cache=true\n',
            'vm/demo.vbox': b'<VirtualBox xmlns="urn:example"><Machine name="demo"/></VirtualBox>',
            'vm/disk.vdi': b'raw disk fixture',
            '.config/onionshare/onionshare.json': b'not valid JSON',
            'tor-browser/Browser/TorBrowser/Data/Browser/profile.default/unrecognized.state': b'raw browser state',
        }
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name, data in fixtures.items():
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            store=MemoryStore();summary=ScanEngine({'paths':[str(root)]},configuration(),store).run()
            self.assertEqual(summary['collected'],len(fixtures))
            by_path={Path(row['path']).relative_to(root).as_posix():row for row in store.records}
            self.assertEqual(by_path['.config/rclone/rclone.conf']['parsed_artifact']['status'],'partial')
            self.assertEqual(by_path['.config/onionshare/onionshare.json']['parsed_artifact']['status'],'failed')
            self.assertEqual(by_path['vm/disk.vdi']['parsed_artifact']['status'],'raw_only')
            self.assertEqual({row['category'] for row in store.records},
                             {'Cloud Storage','Dark Web Apps','Anti-forensics Apps','Virtual Machines'})
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w') as archive:
                checksums={}
                for index,record in enumerate(store.records):
                    write_structured(archive,record,index,checksums,lambda:None)
            with zipfile.ZipFile(io.BytesIO(output.getvalue())) as archive:
                exported=b''.join(archive.read(name) for name in archive.namelist() if name.endswith('.jsonl'))
            self.assertIn(b'apps_rclone',exported)
            self.assertIn(b'"parser_status": "partial"',exported)
            self.assertIn(by_path['vm/demo.vbox']['sha256'].encode(),exported)
            for name,data in fixtures.items():
                self.assertEqual(by_path[name]['data'],data)
                self.assertEqual((root/name).read_bytes(),data)
