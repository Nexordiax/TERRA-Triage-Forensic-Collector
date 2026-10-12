"""Local, optional secrets for offline forensic decoding."""
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QCheckBox, QFormLayout, QLineEdit


class DecryptionOptions(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.enabled = QCheckBox('Decode protected artifacts offline')
        self.enabled.setChecked(True)
        layout.addWidget(self.enabled)
        note = QLabel('Uses available keys in the selected evidence or the optional secrets below. '
                      'Blank Firefox password tries profiles without a primary password. '
                      'Secrets stay in this process and are excluded from the report and manifest. '
                      'Decrypted findings and original key-bearing evidence are included in exports.')
        note.setWordWrap(True)
        note.setObjectName('description')
        layout.addWidget(note)
        self.fields = {}
        form = QFormLayout()
        for name, label in (
            ('firefox_password', 'Firefox primary password'),
            ('safe_storage_password', 'Linux Chromium / Electron SafeStorage secret'),
            ('signal_key', 'Signal database key (64 hex characters)'),
            ('telegram_passcode', 'Telegram local passcode (legacy key_data)'),
            ('telegram_key', 'Telegram local key (512 hex characters)'),
        ):
            field = QLineEdit()
            field.setEchoMode(QLineEdit.EchoMode.Password)
            self.fields[name] = field
            form.addRow(label, field)
            self.enabled.toggled.connect(field.setEnabled)
        layout.addLayout(form)

    def values(self):
        return {name: field.text() for name, field in self.fields.items()} if self.enabled.isChecked() else {}

    def clear_secrets(self):
        for field in self.fields.values():
            field.clear()
