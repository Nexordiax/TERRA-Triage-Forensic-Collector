"""Shared ZIP destination browser with visible mounted storage and USB labels."""
import os
import sys
from pathlib import Path

from PySide6.QtCore import QStorageInfo, QUrl, Qt, QLibraryInfo
from PySide6.QtWidgets import QFileDialog, QWidget, QHBoxLayout, QLabel, QComboBox, QPushButton

PSEUDO_FILESYSTEMS = {'proc', 'sysfs', 'devtmpfs', 'devpts', 'tmpfs', 'cgroup', 'cgroup2',
                      'securityfs', 'debugfs', 'tracefs', 'pstore', 'configfs', 'hugetlbfs',
                      'mqueue', 'fusectl', 'autofs', 'squashfs'}
SYS_BLOCK = Path('/sys/class/block')


def configure_native_dialogs():
    """Choose desktop integration before QApplication loads its platform theme."""
    if not sys.platform.startswith('linux') or os.environ.get('QT_QPA_PLATFORM') in ('offscreen', 'minimal'):
        return
    theme = os.environ.get('QT_QPA_PLATFORMTHEME', '')
    if theme and theme != 'generic':
        return
    directory = Path(QLibraryInfo.path(QLibraryInfo.LibraryPath.PluginsPath)) / 'platformthemes'
    desktop = os.environ.get('XDG_CURRENT_DESKTOP', '').lower()
    candidates = ['xdgdesktopportal', 'gtk3'] if 'kde' in desktop else ['gtk3', 'xdgdesktopportal']
    for candidate in candidates:
        if (directory / f'libq{candidate}.so').is_file():
            os.environ['QT_QPA_PLATFORMTHEME'] = candidate
            return


def native_dialogs_available():
    if os.environ.get('QT_QPA_PLATFORM') in ('offscreen', 'minimal'):
        return False
    if not sys.platform.startswith('linux'):
        return True
    return os.environ.get('QT_QPA_PLATFORMTHEME', '').split(':')[0] in ('gtk3', 'xdgdesktopportal', 'kde')


def block_path(device):
    return SYS_BLOCK / Path(os.path.realpath(device)).name


def block_nodes(node, seen=None):
    seen = set() if seen is None else seen
    if node.name in seen or len(seen) >= 16:
        return []
    seen.add(node.name)
    nodes = [node]
    try:
        for slave in (node / 'slaves').iterdir():
            nodes.extend(block_nodes(slave, seen))
    except OSError:
        pass
    return nodes


def usb_device(node):
    for source in block_nodes(node):
        try:
            if any(part.startswith('usb') for part in source.resolve(strict=True).parts):
                return True
        except OSError:
            pass
    return False


def space_text(value):
    return f'{max(0, value) / (1024 ** 3):.1f} GiB'


def storage_destinations():
    """Read mount/sysfs information only; never mount devices or probe file contents."""
    rows, seen, mounted_nodes = [], set(), []
    for volume in QStorageInfo.mountedVolumes():
        root = volume.rootPath()
        filesystem = bytes(volume.fileSystemType()).decode(errors='replace')
        if not volume.isValid() or not volume.isReady() or filesystem in PSEUDO_FILESYSTEMS or root in seen:
            continue
        seen.add(root)
        device = bytes(volume.device()).decode(errors='replace')
        node = block_path(device)
        mounted_nodes.extend(block_nodes(node))
        usb = usb_device(node)
        label = volume.name() or volume.displayName() or Path(root).name or 'Filesystem'
        prefix = 'USB' if usb else 'Volume'
        readonly = volume.isReadOnly()
        text = f'{prefix}: {label} — {device} — {root} — {space_text(volume.bytesAvailable())} free'
        if readonly:
            text += ' (read-only)'
        rows.append(dict(text=text, path=root, device=device, usb=usb, writable=not readonly))
    # Connected but unmounted USB disks are shown, never mounted automatically.
    try:
        for node in SYS_BLOCK.iterdir():
            if (node / 'partition').exists() or not usb_device(node):
                continue
            resolved = node.resolve()
            if any(resolved == mounted.resolve() or resolved in mounted.resolve().parents
                   for mounted in mounted_nodes):
                continue
            model_file = node / 'device/model'
            model = (model_file.read_text().strip() if model_file.exists() else '') or node.name
            rows.append(dict(text=f'USB: {model} — /dev/{node.name} (not mounted; unavailable as a destination)',
                             path=None, device=f'/dev/{node.name}', usb=True, writable=False))
    except OSError:
        pass
    return sorted(rows, key=lambda row: (not row['usb'], not row['writable'], row['text']))


class DestinationDialog(QFileDialog):
    def __init__(self, parent, title, initial, name_filter):
        super().__init__(parent, title, initial, name_filter)
        self.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        self.setOption(QFileDialog.Option.DontConfirmOverwrite, True)
        self.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        self.setFileMode(QFileDialog.FileMode.AnyFile)
        self.setDefaultSuffix('zip')
        self.initial_name = Path(initial).name
        panel = QWidget(self)
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.addWidget(QLabel('Storage destination', panel))
        self.devices = QComboBox(panel)
        self.devices.setMinimumContentsLength(35)
        self.devices.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.devices.setToolTip('Select a mounted USB drive or volume to browse it. Device names and mount paths identify the destination.')
        self.devices.activated.connect(self.select_device)
        layout.addWidget(self.devices, 1)
        refresh = QPushButton('Refresh devices', panel)
        refresh.clicked.connect(self.refresh_devices)
        layout.addWidget(refresh)
        grid = self.layout()
        grid.addWidget(panel, grid.rowCount(), 0, 1, grid.columnCount())
        self.refresh_devices()
        self.resize(1040, 650)

    def refresh_devices(self):
        rows = storage_destinations()
        self.devices.clear()
        self.devices.addItem('Choose a connected USB device or mounted volume…', None)
        for row in rows:
            self.devices.addItem(row['text'], row['path'])
            index = self.devices.count() - 1
            self.devices.setItemData(index, row['text'], Qt.ItemDataRole.ToolTipRole)
            if not row['writable'] or not row['path']:
                self.devices.model().item(index).setEnabled(False)
        urls = [QUrl.fromLocalFile(str(Path.home())), QUrl.fromLocalFile('/')]
        urls.extend(QUrl.fromLocalFile(row['path']) for row in rows if row['path'])
        self.setSidebarUrls([QUrl(value) for value in dict.fromkeys(url.toString() for url in urls)])

    def select_device(self, index):
        path = self.devices.itemData(index)
        if not path:
            return
        selected = self.selectedFiles()
        filename = Path(selected[0]).name if selected else self.initial_name
        self.setDirectory(path)
        self.selectFile(filename)


def choose_save_destination(parent, title, initial, name_filter):
    if native_dialogs_available():
        # A plain QFileDialog allows the GTK/portal chooser to show desktop devices.
        # Do not subclass it or add Qt widgets: that forces Qt's filesystem browser.
        filename, _ = QFileDialog.getSaveFileName(
            parent, title, initial, name_filter,
            options=QFileDialog.Option.DontConfirmOverwrite)
        return filename
    dialog = DestinationDialog(parent, title, initial, name_filter)
    try:
        if dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected = dialog.selectedFiles()
            return selected[0] if selected else ''
        return ''
    finally:
        dialog.deleteLater()
