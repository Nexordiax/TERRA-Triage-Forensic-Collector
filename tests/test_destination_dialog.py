"""USB destination discovery, explicit selection and shared RAM/export dialogs."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtWidgets import QApplication, QFileDialog
from shiboken6 import delete

from interface.widgets.destination_dialog import (DestinationDialog, storage_destinations,
                                                  choose_save_destination, configure_native_dialogs)
from interface.pages.export import ExportPage
from interface.pages.ram import RamPage


class DestinationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sys = self.root / 'sys/class/block'
        self.sys.mkdir(parents=True)

    def volume(self, root, device, label='Evidence USB', readonly=False, filesystem=b'ext4'):
        volume = Mock()
        volume.rootPath.return_value = root
        volume.device.return_value = device.encode()
        volume.name.return_value = label
        volume.displayName.return_value = label
        volume.fileSystemType.return_value = filesystem
        volume.isValid.return_value = volume.isReady.return_value = True
        volume.isReadOnly.return_value = readonly
        volume.bytesAvailable.return_value = 16 * 1024 ** 3
        return volume

    def usb_disk(self, name):
        real = self.root / 'devices/pci/usb1/1-1/block' / name
        (real / 'device').mkdir(parents=True)
        (real / 'device/model').write_text('Backup USB')
        (self.sys / name).symlink_to(real, target_is_directory=True)
        return real

    def test_usb_labels_mount_paths_free_space_and_unmounted_disks(self):
        disk = self.usb_disk('sdb')
        partition = disk / 'sdb1'
        partition.mkdir()
        (partition / 'partition').write_text('1')
        (self.sys / 'sdb1').symlink_to(partition, target_is_directory=True)
        self.usb_disk('sdc')
        volumes = [self.volume('/media/examiner/EVIDENCE', '/dev/sdb1'),
                   self.volume('/', '/dev/nvme0n1p1', label='System'),
                   self.volume('/proc', 'proc', filesystem=b'proc')]
        with patch('interface.widgets.destination_dialog.SYS_BLOCK', self.sys), \
             patch('interface.widgets.destination_dialog.QStorageInfo.mountedVolumes', return_value=volumes):
            rows = storage_destinations()
        mounted = next(row for row in rows if row['path'] == '/media/examiner/EVIDENCE')
        self.assertTrue(mounted['usb'])
        self.assertIn('Evidence USB', mounted['text'])
        self.assertIn('/dev/sdb1', mounted['text'])
        self.assertIn('16.0 GiB free', mounted['text'])
        self.assertEqual(len(rows), 3)
        self.assertFalse(any(row['device'] == '/dev/sdb' for row in rows))
        unavailable = next(row for row in rows if row['device'] == '/dev/sdc')
        self.assertFalse(unavailable['writable'])
        self.assertIsNone(unavailable['path'])
        self.assertIn('not mounted', unavailable['text'])

    def test_encrypted_usb_mount_is_identified_without_duplicate_unmounted_disk(self):
        disk = self.usb_disk('sdb')
        partition = disk / 'sdb1'
        partition.mkdir()
        (partition / 'partition').write_text('1')
        (self.sys / 'sdb1').symlink_to(partition, target_is_directory=True)
        mapper = self.root / 'devices/virtual/block/dm-test/slaves'
        mapper.mkdir(parents=True)
        (mapper / 'sdb1').symlink_to(partition, target_is_directory=True)
        (self.sys / 'dm-test').symlink_to(mapper.parent, target_is_directory=True)
        with patch('interface.widgets.destination_dialog.SYS_BLOCK', self.sys), \
             patch('interface.widgets.destination_dialog.QStorageInfo.mountedVolumes',
                   return_value=[self.volume('/media/Encrypted', '/dev/dm-test')]):
            rows = storage_destinations()
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]['usb'])

    def test_select_usb_preserves_filename_refresh_does_not_change_destination(self):
        usb = self.root / 'USB'
        usb.mkdir()
        rows = [dict(text='USB: EVIDENCE — /dev/sdb1 — ' + str(usb), path=str(usb), writable=True),
                dict(text='USB: Unmounted — /dev/sdc', path=None, writable=False)]
        with patch('interface.widgets.destination_dialog.storage_destinations', return_value=rows):
            dialog = DestinationDialog(None, 'Save RAM', str(self.root / 'case-RAM.zip'), 'ZIP (*.zip)')
            self.addCleanup(delete, dialog)
            self.assertEqual(dialog.selectedFiles(), [str(self.root / 'case-RAM.zip')])
            dialog.select_device(1)
            self.assertEqual(dialog.selectedFiles(), [str(usb / 'case-RAM.zip')])
            self.assertFalse(dialog.devices.model().item(2).isEnabled())
            before = dialog.selectedFiles()
            dialog.refresh_devices()
            self.assertEqual(dialog.selectedFiles(), before)
            self.assertIn(str(usb), [url.toLocalFile() for url in dialog.sidebarUrls()])
        self.assertEqual(list(usb.iterdir()), [])

    def test_read_only_volume_is_visible_and_disabled(self):
        with patch('interface.widgets.destination_dialog.SYS_BLOCK', self.sys), \
             patch('interface.widgets.destination_dialog.QStorageInfo.mountedVolumes',
                   return_value=[self.volume(str(self.root), '/dev/sdz', readonly=True)]):
            rows = storage_destinations()
        self.assertIn('read-only', rows[0]['text'])
        with patch('interface.widgets.destination_dialog.storage_destinations', return_value=rows):
            dialog = DestinationDialog(None, 'Save', 'export.zip', 'ZIP (*.zip)')
            self.addCleanup(delete, dialog)
            self.assertFalse(dialog.devices.model().item(1).isEnabled())

    def test_ram_and_triage_use_shared_browser_and_preserve_zip_names(self):
        export = ExportPage()
        ram = RamPage()
        self.addCleanup(delete, export)
        self.addCleanup(delete, ram)
        ram.prepare({'paths': []}, None)
        selected = str(self.root / 'USB/export')
        with patch('interface.pages.export.choose_save_destination', return_value=selected) as chooser:
            export.choose_destination()
            self.assertEqual(export.destination.text(), selected + '.zip')
            self.assertEqual(chooser.call_args.args[2], export.default_name)
        with patch('interface.pages.ram.choose_save_destination', return_value=selected) as chooser:
            ram.choose()
            self.assertEqual(ram.destination.text(), selected + '.zip')
            self.assertEqual(chooser.call_args.args[2], ram.default_name)
        original = ram.destination.text()
        with patch('interface.pages.ram.choose_save_destination', return_value=''):
            ram.choose()
        self.assertEqual(ram.destination.text(), original)

    def test_native_chooser_used_without_forcing_qt_browser(self):
        selected = str(self.root / 'case-RAM.zip')
        with patch('interface.widgets.destination_dialog.native_dialogs_available', return_value=True), \
             patch('interface.widgets.destination_dialog.QFileDialog.getSaveFileName', return_value=(selected, 'ZIP (*.zip)')) as native, \
             patch('interface.widgets.destination_dialog.DestinationDialog') as fallback:
            self.assertEqual(choose_save_destination(None, 'Save RAM', 'case-RAM.zip', 'ZIP (*.zip)'), selected)
            fallback.assert_not_called()
            flags = native.call_args.kwargs['options']
            self.assertFalse(flags & QFileDialog.Option.DontUseNativeDialog)
            self.assertTrue(flags & QFileDialog.Option.DontConfirmOverwrite)

    def test_native_cancel_does_not_open_second_dialog(self):
        with patch('interface.widgets.destination_dialog.native_dialogs_available', return_value=True), \
             patch('interface.widgets.destination_dialog.QFileDialog.getSaveFileName', return_value=('', '')), \
             patch('interface.widgets.destination_dialog.DestinationDialog') as fallback:
            self.assertEqual(choose_save_destination(None, 'Save', 'export.zip', 'ZIP (*.zip)'), '')
            fallback.assert_not_called()

    def test_native_unavailable_keeps_storage_browser_fallback(self):
        with patch('interface.widgets.destination_dialog.native_dialogs_available', return_value=False), \
             patch('interface.widgets.destination_dialog.DestinationDialog') as fallback:
            fallback.return_value.exec.return_value = QFileDialog.DialogCode.Accepted
            fallback.return_value.selectedFiles.return_value = [str(self.root / 'export.zip')]
            self.assertEqual(choose_save_destination(None, 'Save', 'export.zip', 'ZIP (*.zip)'), str(self.root / 'export.zip'))
            fallback.return_value.deleteLater.assert_called_once()

    def test_xfce_selects_gtk_and_kde_selects_portal_before_application_start(self):
        plugins = self.root / 'platformthemes'
        plugins.mkdir()
        for name in ('gtk3', 'xdgdesktopportal'):
            (plugins / f'libq{name}.so').touch()
        for desktop, theme in (('XFCE', 'gtk3'), ('KDE', 'xdgdesktopportal')):
            with patch.dict(os.environ, {'QT_QPA_PLATFORM': 'xcb', 'QT_QPA_PLATFORMTHEME': 'generic',
                                         'XDG_CURRENT_DESKTOP': desktop}), \
                 patch('interface.widgets.destination_dialog.QLibraryInfo.path', return_value=str(self.root)), \
                 patch('interface.widgets.destination_dialog.sys.platform', 'linux'):
                configure_native_dialogs()
                self.assertEqual(os.environ['QT_QPA_PLATFORMTHEME'], theme)
