"""Cross-distribution fixtures, provenance and end-to-end evidence preservation."""
import bz2
import gzip
import hashlib
import json
import lzma
import os
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from tests.test_ram import APP  # keep a shared QApplication alive for PDF export
from artifacts.catalog import CATALOG, DISTRO, definition_for
from artifacts.distribution_metadata import parse
from artifacts.file_collector import CollectionCancelled
from artifacts.parsing import parse_artifact
from artifacts.parser_support import ParseError
from artifacts.registry import category_for
from controllers.export_controller import ZipExporter
from controllers.scan_controller import ScanEngine
from storage.memory_store import MemoryStore


class DistributionCoverageTests(unittest.TestCase):
    def rows(self, parser, data, path='fixture'):
        return list(parse(parser, data.encode() if isinstance(data, str) else data, path, lambda: False))

    def test_every_new_definition_resolves_its_own_paths_and_sources(self):
        for definition in DISTRO['artifacts']:
            self.assertEqual(definition['support'], 'structured' if definition['parser'] else 'raw_collection')
            for source in definition['sources']:
                self.assertTrue(CATALOG['sources'][source]['url'].startswith('https://'))
            for pattern in definition['paths']:
                example = pattern.replace('**/', 'nested/').replace('**', 'nested/file').replace('*', 'fixture')
                if definition['parser'] == 'distro_gentoo':
                    example = example.replace('/fixture/fixture/', '/app-shells/bash-5.2/')
                with self.subTest(artifact=definition['id'], path=example):
                    found = definition_for('/media/disk' + example)
                    self.assertIsNotNone(found)
                    self.assertEqual(found['category'], definition['category'])
                    self.assertEqual(found['id'], definition['id'])

    def test_extended_paths_reuse_existing_parsers_and_categories(self):
        cases = {
            '/media/disk/etc/systemd/system/test.socket': ('systemd', 'OS Activity'),
            '/media/disk/etc/systemd/system/test.path.d/override.conf': ('systemd', 'OS Activity'),
            '/media/disk/usr/lib/systemd/user/test.automount': ('systemd', 'OS Activity'),
            '/media/disk/usr/lib/NetworkManager/system-connections/test.nmconnection': ('network_profile', 'Network Connections'),
            '/media/disk/etc/containers/systemd/users/1000/example.container': ('systemd', 'Virtual Machines'),
            '/home/user/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/Default/History': ('chromium_history', 'Browsers'),
            '/home/user/.var/app/org.chromium.Chromium/config/chromium/Default/Cookies-wal': (None, 'Browsers'),
            '/home/user/.var/app/com.discordapp.Discord/config/discord/Local Storage/leveldb/000001.ldb': ('leveldb', 'Communication'),
            '/home/user/.var/app/com.slack.Slack/config/Slack/Local Storage/leveldb/CURRENT': (None, 'Communication'),
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                definition = definition_for(path)
                self.assertIsNotNone(definition)
                self.assertEqual((definition['parser'], category_for(path)), expected)
        self.assertIsNone(definition_for('/home/user/random/manifest.json'))
        self.assertIsNone(definition_for('/home/user/metadata/BUILD_TIME'))

    def test_portage_version_and_build_time_semantics(self):
        row = self.rows('distro_gentoo', '1700000000\n', '/media/disk/var/db/pkg/app-shells/bash-5.2_p37/BUILD_TIME')[0]
        self.assertEqual(row['package'], 'bash')
        self.assertEqual(row['version'], '5.2_p37')
        self.assertEqual(row['package_category'], 'app-shells')
        self.assertEqual(row['build_time_utc'], '2023-11-14T22:13:20+00:00')
        self.assertNotIn('install_time_utc', row)
        with self.assertRaises(ParseError):
            self.rows('distro_gentoo', 'bad', '/var/db/pkg/app-shells/bash-5.2/BUILD_TIME')

    def test_slackware_current_and_removed_records(self):
        data = 'PACKAGE NAME:  example-tool-1.2-x86_64-3\nPACKAGE LOCATION: /var/cache/packages\nFILE LIST:\netc/example\n'
        for directory, installed in [('packages', True), ('removed-packages', False), ('removed_packages', False)]:
            row = self.rows('distro_slackware', data, '/var/log/' + directory + '/example-tool-1.2-x86_64-3')[0]
            self.assertEqual(row['installed'], installed)
            self.assertEqual(row['package'], 'example-tool')
            self.assertEqual(row['version'], '1.2')
            self.assertEqual(row['architecture'], 'x86_64')
        with self.assertRaises(ParseError):
            self.rows('distro_slackware', 'PACKAGE DESCRIPTION: unrelated')

    def test_nix_all_versions_and_inactive_historical_profiles(self):
        value = dict(active=False, storePaths=['/nix/store/hash-example-1.0'], attrPath='packages.x86_64-linux.example', originalUrl='flake:nixpkgs', url='github:NixOS/nixpkgs/hash')
        for version in (1, 2, 3):
            for elements in ([value], {'example': value}):
                row = self.rows('distro_nix', json.dumps(dict(version=version, elements=elements)))[0]
                self.assertFalse(row['active_in_profile'])
                self.assertEqual(row['store_paths'], value['storePaths'])
                self.assertNotIn('installed', row)
        for document in ({'version': 99, 'elements': []}, {'version': 3, 'elements': [{}]}):
            with self.assertRaises(ParseError):
                self.rows('distro_nix', json.dumps(document))

    def test_xbps_xml_binary_and_gzip_state_preservation(self):
        fixture = dict(example=dict(pkgver='example-1.2_3', state='installed', architecture='x86_64', **{'install-date': '2026-10-10 12:00 UTC'}),
                       removed=dict(pkgver='removed-2.0_1', state='half-removed'))
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            data = plistlib.dumps(fixture, fmt=fmt)
            for wrapped in (data, gzip.compress(data)):
                rows = self.rows('distro_xbps', wrapped)
                self.assertTrue(rows[0]['installed'])
                self.assertFalse(rows[1]['installed'])
                self.assertEqual(rows[0]['version'], '1.2_3')
                self.assertEqual(rows[0]['install_date_raw'], '2026-10-10 12:00 UTC')
        with self.assertRaises(ParseError):
            self.rows('distro_xbps', plistlib.dumps(dict(example={})))

    def test_zypp_rotated_logs_action_specific_fields_and_unknown_lines(self):
        data = b'# header\n2026-10-10 12:00:00|install|example|1.0-2|x86_64|root@host|repo|abc|txn\n2026-10-10 12:01:00|remove|example|1.0-2|x86_64|root@host|txn2\n2026-10-10 12:02:00|radd|repo|https://example.test\nunknown line\n'
        for suffix, compress in [('', lambda value: value), ('.gz', gzip.compress), ('.bz2', bz2.compress), ('.xz', lzma.compress)]:
            rows = self.rows('distro_zypp', compress(data), '/var/log/zypp/history.1' + suffix)
            self.assertEqual(rows[0]['package'], 'example')
            self.assertEqual(rows[0]['transaction_id'], 'txn')
            self.assertEqual(rows[1]['transaction_id'], 'txn2')
            self.assertEqual(rows[2]['repository_value'], 'https://example.test')
            self.assertEqual(rows[3]['type'], 'unparsed_package_transaction')
            self.assertNotIn('timestamp_utc', rows[0])

    def test_accountsservice_literal_preferences(self):
        row = self.rows('distro_accountsservice', '[User]\nLanguage=de_DE.UTF-8\nSession=xfce\nIcon=/tmp/picture%20.png\n', '/var/lib/AccountsService/users/test')[0]
        self.assertEqual(row['username'], 'test')
        self.assertEqual(row['fields']['Icon'], '/tmp/picture%20.png')

    def test_bounds_cancellation_and_xml_entities(self):
        with self.assertRaises(CollectionCancelled):
            list(parse('distro_nix', b'{}', 'fixture', lambda: True))
        with patch('artifacts.distribution_metadata.MAX_INPUT', 64):
            for data in (b'x' * 65, gzip.compress(b'x' * 65)):
                with self.assertRaises(ParseError):
                    self.rows('distro_xbps', data)
        with self.assertRaises(ParseError):
            self.rows('distro_xbps', b'<!DOCTYPE plist [<!ENTITY evidence SYSTEM "file:///etc/passwd">]><plist/>')
        with patch('artifacts.distribution_metadata.MAX_RECORDS', 1):
            with self.assertRaises(ParseError):
                self.rows('distro_zypp', 'time|action\ntime|action\n')
        definition = definition_for('/var/db/xbps/pkgdb-0.38.plist')
        with patch('artifacts.parsing.read_verified') as reread:
            with self.assertRaises(ParseError):
                parse_artifact(definition, '/var/db/xbps/pkgdb-0.38.plist',
                               dict(sha256='placeholder', size=33 * 1024 * 1024, content_retained=False),
                               b'', None, lambda: False)
            reread.assert_not_called()

    def test_scan_and_export_preserve_bytes_categories_and_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            fixtures = {
                'var/db/pkg/app-shells/bash-5.2/BUILD_TIME': b'1700000000\n',
                'var/lib/pkgtools/packages/example-1.0-x86_64-1': b'PACKAGE NAME: example-1.0-x86_64-1\nFILE LIST:\n',
                'var/db/xbps/pkgdb-0.38.plist': plistlib.dumps(dict(example=dict(pkgver='example-1.0_1', state='installed'))),
                'nix/store/hash-profile/manifest.json': json.dumps(dict(version=3, elements=dict(example=dict(active=True, storePaths=['/nix/store/hash-example'])))).encode(),
                'var/log/zypp/history': b'2026-10-10 12:00:00|install|example|1.0|x86_64||repo|sha\n',
                'var/lib/AccountsService/users/test': b'[User]\nSession=xfce\n',
                'etc/systemd/system/example.socket': b'[Socket]\nListenStream=9000\n',
                'etc/polkit-1/rules.d/example.rules': b'polkit.addRule(function() { return polkit.Result.NO; });',
                'var/lib/fwupd/pending.db': b'raw firmware history',
                'var/lib/iwd/test.psk': b'[Security]\nPassphrase=fixture\n',
                'var/lib/containers/storage/overlay-containers/containers.json': b'[]',
                'var/db/pkg/app-test/broken-1.0/BUILD_TIME': b'not-a-time',
            }
            for name, data in fixtures.items():
                path = target / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            # Symlinked/external references must never expand collection scope.
            outside = root / 'outside'
            outside.write_bytes(b'outside evidence')
            (target / 'etc/polkit-1/rules.d/outside.rules').symlink_to(outside)
            config = dict(collection_mode='all_supported', hashes=[], keywords=[], options=dict(file_names=False, folder_names=False, file_contents=False, hash_matches=False))
            store = MemoryStore()
            summary = ScanEngine(dict(paths=[str(target)]), config, store).run()
            self.assertEqual(summary['status'], 'completed', store.snapshot()[1])
            self.assertEqual(summary['collected'], len(fixtures))
            self.assertEqual(summary['parser_failures'], 1)
            records, diagnostics, count = store.snapshot()
            self.assertTrue(any('raw evidence retained' in item['message'] for item in diagnostics))
            self.assertTrue({'Installed Applications', 'OS Activity', 'User Accounts', 'Connected Devices', 'Network Connections', 'Virtual Machines'}.issubset({item['category'] for item in records}))
            destination = root / 'export.zip'
            ZipExporter(records, diagnostics, count, dict(targets=dict(paths=[str(target)]), scan_summary=summary)).save(destination)
            with zipfile.ZipFile(destination) as archive:
                manifest = json.loads(archive.read('terra/manifest.json'))
                for item in manifest['entries']:
                    relative = Path(item['source_path']).relative_to(target).as_posix()
                    self.assertEqual(archive.read(item['archive_path']), fixtures[relative])
                    self.assertEqual(item['sha256'], hashlib.sha256(fixtures[relative]).hexdigest())
                    parsed = item['parsed_artifact']
                    if parsed['status'] == 'parsed':
                        self.assertTrue(parsed['sources'])
                        self.assertIn(parsed['jsonl_path'], archive.namelist())
            for name, data in fixtures.items():
                self.assertEqual((target / name).read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
