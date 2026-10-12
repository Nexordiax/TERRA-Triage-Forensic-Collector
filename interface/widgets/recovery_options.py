"""Opt-in recovery storage with an explicitly selected destination."""
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit, QPushButton, QLabel
from controllers.configuration_controller import ConfigurationError
from controllers.export_controller import destination_is_target
from interface.widgets.destination_dialog import choose_save_destination
from pathlib import Path


class RecoveryOptions(QWidget):
    def __init__(self):
        super().__init__()
        self.targets = {'paths': []}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.enabled = QCheckBox('Save scan progress so this triage can be resumed after closing TERRA')
        layout.addWidget(self.enabled)
        self.controls = QWidget()
        body = QVBoxLayout(self.controls)
        body.setContentsMargins(0, 0, 0, 0)
        note = QLabel('Choose where to save a recovery session containing findings, cached evidence and logs. It is updated during collection. Keep this file to resume later; it is separate from the final export ZIP.')
        note.setWordWrap(True)
        note.setObjectName('description')
        body.addWidget(note)
        row = QHBoxLayout()
        self.path = QLineEdit()
        self.path.setPlaceholderText('Choose a new .terra-session file…')
        row.addWidget(self.path, 1)
        self.choose = QPushButton('Choose progress destination…')
        self.choose.clicked.connect(self.choose_destination)
        row.addWidget(self.choose)
        body.addLayout(row)
        self.acknowledgement = QCheckBox('I understand saving progress here writes to an examined target.')
        self.acknowledgement.hide()
        body.addWidget(self.acknowledgement)
        layout.addWidget(self.controls)
        self.controls.hide()
        self.enabled.toggled.connect(self.controls.setVisible)
        self.path.textChanged.connect(self.changed)

    def choose_destination(self):
        filename = choose_save_destination(self, 'Save TERRA scan progress', self.path.text() or 'TERRA-progress.terra-session', 'TERRA recovery sessions (*.terra-session)')
        if filename:
            if not filename.lower().endswith('.terra-session'): filename += '.terra-session'
            self.path.setText(filename)

    def changed(self):
        self.acknowledgement.setChecked(False)
        path = self.path.text().strip()
        self.acknowledgement.setVisible(bool(path) and destination_is_target(path, self.targets))

    def values(self):
        if not self.enabled.isChecked(): return None
        path = Path(self.path.text().strip()).absolute()
        if not self.path.text().strip() or path.suffix.lower() != '.terra-session':
            raise ConfigurationError('Choose a recovery filename ending in .terra-session.')
        if path.exists() or path.is_symlink():
            raise ConfigurationError('Recovery files are not overwritten. Choose a new filename; use Resume saved triage to reopen an existing session.')
        if not path.parent.is_dir(): raise ConfigurationError('Recovery destination folder does not exist.')
        on_target = destination_is_target(str(path), self.targets)
        if on_target and not self.acknowledgement.isChecked():
            raise ConfigurationError('Choose a progress destination outside the examined targets, or acknowledge the write to this target.')
        return dict(path=str(path), allow_target=on_target and self.acknowledgement.isChecked())
