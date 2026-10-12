import os

from PySide6.QtCore import Qt, Signal, QStorageInfo
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox,
    QListWidget, QListWidgetItem, QFileDialog, QAbstractItemView,
)


class TargetsPage(QWidget):
    back_requested = Signal()
    next_requested = Signal(dict)

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(35, 28, 35, 28)
        layout.setSpacing(12)
        back = QPushButton('← Back')
        back.clicked.connect(self.back_requested.emit)
        layout.addWidget(back, alignment=Qt.AlignmentFlag.AlignLeft)
        heading = QLabel('Select Linux Targets')
        heading.setObjectName('heading')
        layout.addWidget(heading)
        description = QLabel('Select mounted volumes or folders for triage. Unmounted devices are not mounted automatically.')
        description.setObjectName('description')
        description.setWordWrap(True)
        layout.addWidget(description)

        self.entire_system = QCheckBox('Analyze all mounted disk volumes (default)')
        self.entire_system.setChecked(True)
        layout.addWidget(self.entire_system)
        layout.addWidget(QLabel('Mounted disk volumes'))
        self.volumes = QListWidget()
        layout.addWidget(self.volumes, 1)
        self.refresh_button = QPushButton('Refresh volumes')
        self.refresh_button.clicked.connect(self.refresh_volumes)
        layout.addWidget(self.refresh_button, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(QLabel('Additional folders'))
        self.folders = QListWidget()
        self.folders.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        layout.addWidget(self.folders, 1)
        folder_buttons = QHBoxLayout()
        self.add_button = QPushButton('Add folder…')
        self.add_button.clicked.connect(self.add_folder)
        self.remove_button = QPushButton('Remove selected')
        self.remove_button.clicked.connect(self.remove_folders)
        folder_buttons.addWidget(self.add_button)
        folder_buttons.addWidget(self.remove_button)
        folder_buttons.addStretch()
        layout.addLayout(folder_buttons)
        self.entire_system.setToolTip('Also collect live state from this running system. Selecting individual volumes or folders disables live-host collection. RAM acquisition remains separate.')
        self.acquire_ram = QCheckBox('Acquire RAM')
        layout.addWidget(self.acquire_ram)
        note = QLabel('RAM acquisition runs separately before file triage: full physical RAM with root, or accessible process memory without root. Choose the destination in the next acquisition stage.')
        note.setObjectName('description')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.error = QLabel()
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        self.next_button = QPushButton('Next →')
        self.next_button.setObjectName('primary')
        self.next_button.clicked.connect(self.submit)
        layout.addWidget(self.next_button, alignment=Qt.AlignmentFlag.AlignRight)
        self.entire_system.toggled.connect(self.update_mode)
        self.refresh_volumes()
        self.update_mode()

    def refresh_volumes(self):
        checked = {
            self.volumes.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self.volumes.count())
            if self.volumes.item(i).checkState() == Qt.CheckState.Checked
        }
        self.volumes.clear()
        excluded = {'proc', 'sysfs', 'devtmpfs', 'devpts', 'tmpfs', 'cgroup',
                    'cgroup2', 'securityfs', 'debugfs', 'tracefs', 'pstore',
                    'configfs', 'hugetlbfs', 'mqueue', 'fusectl', 'autofs'}
        seen = set()
        for volume in sorted(QStorageInfo.mountedVolumes(), key=lambda v: v.rootPath()):
            path = volume.rootPath()
            filesystem = bytes(volume.fileSystemType()).decode(errors='replace')
            if not volume.isValid() or not volume.isReady() or filesystem in excluded or path in seen:
                continue
            seen.add(path)
            device = bytes(volume.device()).decode(errors='replace')
            item = QListWidgetItem(f'{path} — {device} ({filesystem})')
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if path in checked else Qt.CheckState.Unchecked)
            self.volumes.addItem(item)

    def update_mode(self):
        custom = not self.entire_system.isChecked()
        for widget in (self.volumes, self.folders, self.add_button, self.remove_button):
            widget.setEnabled(custom)
        self.error.clear()

    def add_folder(self):
        path = QFileDialog.getExistingDirectory(self, 'Select triage folder', '/',
                                               QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog)
        if not path:
            return
        path = os.path.realpath(path)
        if not self.folders.findItems(path, Qt.MatchFlag.MatchExactly):
            self.folders.addItem(path)
        self.error.clear()

    def remove_folders(self):
        for item in self.folders.selectedItems():
            self.folders.takeItem(self.folders.row(item))

    def submit(self):
        all_volumes = self.entire_system.isChecked()
        paths = [self.volumes.item(i).data(Qt.ItemDataRole.UserRole)
                 for i in range(self.volumes.count())
                 if all_volumes or self.volumes.item(i).checkState() == Qt.CheckState.Checked]
        if not all_volumes:
            paths.extend(self.folders.item(i).text() for i in range(self.folders.count()))
        paths = list(dict.fromkeys(paths))
        if not paths and (all_volumes or not self.acquire_ram.isChecked()):
            self.error.setText('Select at least one mounted volume or folder, or enable RAM acquisition only.')
            return
        for path in paths:
            if not os.path.isdir(path) or not os.access(path, os.R_OK | os.X_OK):
                self.error.setText(f'Target is unavailable or inaccessible: {path}')
                return
        self.error.clear()
        self.next_requested.emit({'all_volumes': all_volumes, 'paths': paths,
                                  'collect_live': all_volumes,
                                  'acquire_ram': self.acquire_ram.isChecked()})
