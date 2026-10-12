from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QCheckBox, QProgressBar, QPlainTextEdit,
)
from controllers.export_controller import destination_is_target, export_basename
from interface.widgets.destination_dialog import choose_save_destination


class ExportPage(QWidget):
    back_requested = Signal()
    export_requested = Signal(str, bool)
    cancel_requested = Signal()
    finish_requested = Signal()

    def __init__(self):
        super().__init__()
        self.targets = {'paths': []}
        self.default_name = export_basename() + '-TERRA.zip'
        self.busy = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(35, 28, 35, 28)
        layout.setSpacing(16)
        self.back_button = QPushButton('← Back')
        self.back_button.clicked.connect(self.back_requested.emit)
        layout.addWidget(self.back_button, alignment=Qt.AlignmentFlag.AlignLeft)
        heading = QLabel('Export Findings')
        heading.setObjectName('heading')
        layout.addWidget(heading)
        description = QLabel('Save a ZIP containing complete verified files, the original target folder structure, a manifest, SHA-256 checksums, diagnostic logs, and PDF and HTML reports. Extract the evidence folders to import them as logical files in your analysis tool.')
        description.setObjectName('description')
        description.setWordWrap(True)
        layout.addWidget(description)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        layout.addWidget(QLabel('Destination ZIP file'))
        destination = QHBoxLayout()
        self.destination = QLineEdit()
        self.destination.setPlaceholderText('Select a destination and ZIP filename…')
        self.destination.textChanged.connect(self.destination_changed)
        self.browse_button = QPushButton('Choose destination…')
        self.browse_button.clicked.connect(self.choose_destination)
        destination.addWidget(self.destination, 1)
        destination.addWidget(self.browse_button)
        layout.addLayout(destination)
        note = QLabel('Existing files are not overwritten. Export ZIP saves to your selected destination. Finish asks for confirmation if the current triage findings have not been successfully exported.')
        note.setObjectName('description')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.target_acknowledgement = QCheckBox('I understand this destination is within an examined target and exporting here writes to that target.')
        self.target_acknowledgement.hide()
        layout.addWidget(self.target_acknowledgement)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.status)
        self.coverage = QPlainTextEdit()
        self.coverage.setReadOnly(True)
        self.coverage.setMaximumHeight(170)
        self.coverage.hide()
        layout.addWidget(self.coverage)
        self.progress = QProgressBar()
        self.progress.hide()
        layout.addWidget(self.progress)
        layout.addStretch()
        buttons = QHBoxLayout()
        self.cancel_button = QPushButton('Cancel export')
        self.cancel_button.clicked.connect(self.cancel_requested.emit)
        self.cancel_button.hide()
        buttons.addWidget(self.cancel_button)
        buttons.addStretch()
        self.export_button = QPushButton('Export ZIP')
        self.export_button.setObjectName('primary')
        self.export_button.clicked.connect(self.submit)
        self.finish_button = QPushButton('Finish')
        self.finish_button.clicked.connect(self.finish_requested.emit)
        buttons.addWidget(self.export_button)
        buttons.addWidget(self.finish_button)
        layout.addLayout(buttons)

    def prepare(self, targets, case, records):
        self.status.clear()
        self.coverage.clear()
        self.coverage.hide()
        self.targets = targets or {'paths': []}
        self.default_name = export_basename(case) + '-TERRA.zip'
        files = sum(record['kind'] == 'file' for record in records)
        folders = sum(record['kind'] == 'directory' for record in records)
        self.summary.setText(f'{files} files and {folders} folder-name findings are ready to export. Files are packaged once, even if they appear in multiple result categories.')
        self.destination_changed()

    def destination_changed(self):
        self.target_acknowledgement.setChecked(False)
        selected = self.destination.text().strip()
        self.target_acknowledgement.setVisible(bool(selected) and destination_is_target(selected, self.targets))

    def choose_destination(self):
        filename = choose_save_destination(
            self, 'Save TERRA Export', self.destination.text() or self.default_name,
            'ZIP archives (*.zip)')
        if filename:
            if not filename.lower().endswith('.zip'):
                filename += '.zip'
            self.destination.setText(filename)

    def submit(self):
        if self.busy:
            return
        filename = self.destination.text().strip()
        if not filename:
            self.status.setText('Select a destination ZIP filename first.')
            return
        on_target = destination_is_target(filename, self.targets)
        if on_target and not self.target_acknowledgement.isChecked():
            self.status.setText('Choose a destination outside the examined targets, or acknowledge the write to this target.')
            return
        self.export_requested.emit(filename, on_target and self.target_acknowledgement.isChecked())

    def begin(self):
        self.busy = True
        self.coverage.hide()
        for widget in (self.back_button, self.destination, self.browse_button, self.export_button,
                       self.finish_button, self.target_acknowledgement):
            widget.setEnabled(False)
        self.cancel_button.show()
        self.progress.show()
        self.progress.setRange(0, 0)
        self.status.setText('Preparing ZIP export…')

    @Slot(dict)
    def update_progress(self, progress):
        self.progress.setRange(0, max(1, progress['total']))
        self.progress.setValue(progress['done'])
        self.status.setText(f"{progress['phase']} · {progress['done']} / {progress['total']}\n{progress['path']}")

    @Slot(dict)
    def finish(self, result):
        self.busy = False
        for widget in (self.back_button, self.destination, self.browse_button, self.export_button,
                       self.finish_button, self.target_acknowledgement):
            widget.setEnabled(True)
        self.cancel_button.hide()
        self.progress.hide()
        if result['status'] == 'saved':
            if result.get('coverage_summary'):
                from reporting.coverage import summary_text
                self.coverage.setPlainText(summary_text(result['coverage_summary']))
                self.coverage.show()
            self.status.setText(f"Saved and verified {result['file_count']} files:\n{result['path']}\nZIP SHA-256: {result['archive_sha256']}")
        else:
            self.status.setText(result['error'])
