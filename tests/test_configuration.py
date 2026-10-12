import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ['QT_QPA_PLATFORMTHEME'] = 'generic'

from PySide6.QtWidgets import QApplication
from controllers.configuration_controller import ConfigurationController, ConfigurationError
from interface.main_window import MainWindow
from interface.pages.configuration import ConfigurationPage


class ConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.hashes = self.write('hashes.txt', 'A' * 32 + '\n' + 'b' * 64 + '\n')
        self.keywords = self.write('keywords.txt', '\ufeff# comment\nexample phrase\nexample phrase\n')
        self.page = ConfigurationPage()
        self.addCleanup(self.page.deleteLater)
        self.emitted = []
        self.page.start_requested.connect(self.emitted.append)

    def write(self, name, content):
        path = self.directory / name
        path.write_text(content, encoding='utf-8')
        return str(path)

    def import_lists(self):
        self.page.hash_lists.add_files([self.hashes])
        self.page.keyword_lists.add_files([self.keywords])

    def test_defaults_and_required_lists(self):
        self.assertTrue(all(option.isChecked() for option in self.page.options.values()))
        self.assertTrue(self.page.all_artifacts.isChecked())
        self.page.submit()
        self.assertIn('Hash list missing', self.page.error.text())
        self.page.hash_lists.add_files([self.hashes])
        self.page.submit()
        self.assertIn('Keyword list missing', self.page.error.text())
        self.assertFalse(self.emitted)

    def test_multiple_lists_and_memory_snapshot(self):
        other = self.write('more.txt', 'b' * 64 + '\n' + 'c' * 40 + '\n')
        self.import_lists()
        self.page.hash_lists.add_files([self.hashes, other])
        self.assertEqual(len(self.page.hash_lists.paths()), 2)
        self.page.matches_only.setChecked(True)
        self.page.submit()
        result = self.emitted[0]
        self.assertEqual(result['hashes'], ['a' * 32, 'b' * 64, 'c' * 40])
        self.assertEqual(result['keywords'], ['example phrase'])
        self.assertEqual(result['collection_mode'], 'matches_only')
        Path(self.keywords).write_text('changed', encoding='utf-8')
        self.assertEqual(result['keywords'], ['example phrase'])
        self.page.submit()
        self.assertEqual(self.emitted[1]['keywords'], ['changed'])

    def test_bad_lists_and_removed_file(self):
        bad = self.write('bad.txt', 'invalid hash')
        self.page.hash_lists.add_files([bad])
        self.assertFalse(self.page.hash_lists.paths())
        self.assertIn('line 1', self.page.hash_lists.error.text())
        self.import_lists()
        Path(self.hashes).unlink()
        self.page.submit()
        self.assertIn('Cannot read list', self.page.error.text())
        self.assertFalse(self.emitted)

    def test_disabled_matching_and_matches_only(self):
        for option in self.page.options.values():
            option.setChecked(False)
        self.page.submit()
        self.assertEqual(len(self.emitted), 1)
        self.page.matches_only.setChecked(True)
        self.page.submit()
        self.assertIn('Enable at least one', self.page.error.text())
        self.assertEqual(len(self.emitted), 1)

    def test_empty_non_text_and_invalid_encoding(self):
        controller = ConfigurationController()
        for path in (self.write('empty.txt', '# comment\n'), self.write('list.csv', 'keyword')):
            with self.assertRaises(ConfigurationError):
                controller.read_list(path)
        binary = self.directory / 'binary.txt'
        binary.write_bytes(b'\xff')
        with self.assertRaises(ConfigurationError):
            controller.read_list(str(binary))

    def test_standard_hash_tool_formats_and_uppercase(self):
        controller = ConfigurationController()
        lines = ['A' * 32, 'b' * 40 + '  test file.txt', 'C' * 64 + ' *binary.dat',
                 'SHA512 (test.txt) = ' + 'D' * 128, 'MD5: ' + 'e' * 32]
        path = self.write('formats.txt', '\n'.join(lines))
        self.assertEqual(controller.read_list(path, hashes=True),
                         ['a' * 32, 'b' * 40, 'c' * 64, 'd' * 128, 'e' * 32])
        bad = self.write('wrong-algorithm.txt', 'SHA256 (file) = ' + 'a' * 32)
        with self.assertRaises(ConfigurationError):
            controller.read_list(bad, hashes=True)

    def test_collection_scope_is_outside_scrolling_form(self):
        from PySide6.QtWidgets import QScrollArea
        scroll = self.page.findChild(QScrollArea)
        self.assertNotIn(self.page.all_artifacts, scroll.findChildren(type(self.page.all_artifacts)))
        self.page.resize(620, 460)
        self.page.show()
        self.app.processEvents()
        self.assertTrue(self.page.all_artifacts.isVisible())
        self.assertTrue(self.page.matches_only.isVisible())
        self.assertTrue(self.page.all_artifacts.isChecked())
        self.page.close()

    def test_dialog_cancel_and_remove(self):
        with patch('interface.pages.configuration.QFileDialog.getOpenFileNames', return_value=([], '')):
            self.page.hash_lists.import_files()
        self.assertFalse(self.page.hash_lists.paths())
        self.import_lists()
        self.page.hash_lists.files.item(0).setSelected(True)
        self.page.hash_lists.remove_selected()
        self.assertFalse(self.page.hash_lists.paths())

    def test_navigation_preserves_settings_and_starts_controller(self):
        window = MainWindow()
        self.addCleanup(window.deleteLater)
        window.welcome.quick_triage.emit()
        window.privileges.current.setChecked(True)
        window.privileges.next_button.click()
        window.accept_targets({'paths': [str(self.directory)], 'all_volumes': False, 'acquire_ram': False})
        page = window.configuration
        page.hash_lists.add_files([self.hashes])
        page.keyword_lists.add_files([self.keywords])
        page.options['file_contents'].setChecked(False)
        window.go_back()
        self.assertIs(window.stack.currentWidget(), window.targets)
        window.accept_targets({'paths': [str(self.directory)], 'all_volumes': False, 'acquire_ram': False})
        self.assertFalse(page.options['file_contents'].isChecked())
        self.assertEqual(page.hash_lists.paths(), [self.hashes])
        with patch.object(window.scan_controller, 'start') as start:
            page.submit()
            start.assert_called_once()
        self.assertEqual(window.triage_configuration['keywords'], ['example phrase'])
        self.assertIs(window.stack.currentWidget(), window.analysis)
        self.assertFalse(window.analysis.back_button.isEnabled())
