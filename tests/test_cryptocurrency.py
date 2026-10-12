"""Wallet/path identification, live category, scoped collection and portable export."""
import hashlib
import json
import tempfile
import unittest
import io
import zipfile
from pathlib import Path
from shiboken6 import delete
from PySide6.QtWidgets import QApplication

from artifacts.registry import category_for
from artifacts.cryptocurrency.parser import identify, parse
from artifacts.parser_support import ParseError
from controllers.scan_controller import ScanEngine
from interface.pages.analysis import AnalysisPage
from interface.main_window import MainWindow
from interface.widgets.branding import WelcomeIllustration
from storage.memory_store import MemoryStore
from tests.test_scan import configuration
from reporting.structured_export import write_structured


class CryptocurrencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def file(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_researched_path_families_and_unrelated_files(self):
        for relative in ('.bitcoin/wallets/examiner/wallet.dat', '.electrum/wallets/default_wallet',
                         '.ethereum/keystore/UTC--fixture', '.config/Exodus/Backups/Wallet/fixture',
                         '.walletwasabi/client/WalletBackups/fixture.json', '.sparrow/wallets/wallet.mv.db',
                         '.local/share/sparrow/wallets/fixture', '.bitmonero/wallets/fixture.keys',
                         '.electron-cash/wallets/fixture', '.config/chromium/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000001.ldb'):
            self.assertEqual(category_for('/mnt/evidence/home/user/' + relative), 'Cryptocurrency', relative)
        for relative in ('random.keys', 'wallet.dat', 'document.json'):
            self.assertNotEqual(category_for('/home/user/' + relative), 'Cryptocurrency')

    def test_renamed_wallets_public_metadata_and_live_collapsed_category(self):
        wallet = {'wallet_type': 'standard', 'seed_version': 17, 'keystore': {'xprv': 'synthetic-secret'},
                  'addresses': {'receiving': ['bc1fixture']}, 'transactions': {'a' * 64: 'raw transaction'}}
        data = json.dumps(wallet).encode()
        path = self.file('selected/renamed.json', data)
        self.file('outside/.electrum/wallets/default_wallet', data)
        store = MemoryStore()
        page = AnalysisPage()
        self.addCleanup(delete, page)
        summary = ScanEngine({'paths': [str(path.parent)]}, configuration(), store, on_finding=page.add_finding).run()
        self.assertEqual(summary['collected'], 1)
        self.assertEqual(store.records[0]['category'], 'Cryptocurrency')
        self.assertEqual(store.records[0]['data'], data)
        self.assertEqual(path.read_bytes(), data)
        parsed = store.records[0]['parsed_artifact']
        self.assertEqual(parsed['status'], 'parsed')
        self.assertEqual(parsed['record_count'], 3)
        self.assertNotIn('synthetic-secret', json.dumps(parsed))
        self.assertFalse(page.categories['Cryptocurrency'].isExpanded())
        output, checksums = io.BytesIO(), {}
        with zipfile.ZipFile(output, 'w') as archive:
            exported = write_structured(archive, store.records[0], 0, checksums, lambda: None)
        with zipfile.ZipFile(output) as archive:
            rows = [json.loads(line) for line in archive.read(exported['jsonl_path']).splitlines()]
            self.assertEqual(rows[0]['provenance']['source_sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(len(rows), 3)

    def test_ethereum_keystore_recognized_and_locked_without_secret_extraction(self):
        value = dict(version=3, address='a' * 40, id='fixture', crypto=dict(cipher='aes-128-ctr',
                     ciphertext='ab' * 32, mac='cd' * 32, cipherparams={'iv': '00' * 16},
                     kdf='scrypt', kdfparams={'n': 8192, 'r': 8, 'p': 1, 'dklen': 32, 'salt': '01' * 32}))
        data = json.dumps(value).encode()
        self.assertEqual(identify(data), 'crypto_ethereum')
        rows, warnings, status = parse('crypto_ethereum', data, '/renamed.json', lambda: False)
        self.assertEqual(status, 'partial')
        self.assertEqual(rows[0]['public_address'], 'a' * 40)
        self.assertEqual(rows[0]['decryption_status'], 'locked')
        self.assertNotIn('ciphertext', rows[0])
        self.assertTrue(warnings)
        value['version'] = 2
        self.assertIsNone(identify(json.dumps(value).encode()))
        self.assertIsNone(identify(b'{"wallet_type":"example document"}'))

    def test_matches_only_does_not_collect_wallets_without_a_requested_match(self):
        data = b'{"wallet_type":"standard","seed_version":17,"addresses":[]}'
        path = self.file('.electrum/wallets/fixture', data)
        store = MemoryStore()
        ScanEngine({'paths': [str(self.root)]}, configuration('matches_only', hashes=['0' * 32], hash_matches=True), store).run()
        self.assertEqual(store.records, [])
        store = MemoryStore()
        ScanEngine({'paths': [str(self.root)]}, configuration('matches_only', hashes=[hashlib.md5(data).hexdigest()], hash_matches=True), store).run()
        self.assertEqual(store.records[0]['category'], 'Cryptocurrency')
        self.assertIn('md5', store.records[0]['matches']['hashes'])

    def test_config_custom_scope_not_followed_and_password_not_summarized(self):
        rows, _, _ = parse('crypto_config', b'datadir=/outside\nrpcpassword=synthetic-password\nchain=regtest\n', '/bitcoin.conf', lambda: False)
        self.assertEqual([row['setting'] for row in rows], ['datadir', 'chain'])
        self.assertNotIn('synthetic-password', json.dumps(rows))
        with self.assertRaises(ParseError):
            parse('crypto_electrum', b'{}', '/.electrum/wallets/fixture', lambda: False)

    def test_welcome_only_image_and_window_icon(self):
        window = MainWindow()
        self.addCleanup(delete, window)
        self.assertFalse(window.windowIcon().isNull())
        self.assertEqual(len(window.findChildren(WelcomeIllustration)), 1)
        window.show()
        self.app.processEvents()
        self.assertTrue(window.welcome.illustration.isVisible())
        window.stack.setCurrentWidget(window.targets)
        self.app.processEvents()
        self.assertFalse(window.welcome.illustration.isVisible())
