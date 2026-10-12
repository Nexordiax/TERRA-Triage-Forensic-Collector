from PySide6.QtCore import Qt, QFile
from PySide6.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QTabWidget, QWidget
from interface.widgets.preview_dialog import PreviewDialog
from interface.widgets.structured_findings import StructuredFindings
from storage.source_file import open_record_device, validate_source


class FileDetails(PreviewDialog):
    """Show matches and hashes, with paged text viewing of complete target files."""
    page_bytes = 64 * 1024

    def __init__(self, record, parent=None, hash_configuration=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle('Target File Details')
        self.resize(820, 640)
        self.record = record
        self.device = None
        self.offset = 0
        layout = QVBoxLayout(self)
        path = QLabel(record['path'])
        path.setTextFormat(Qt.TextFormat.PlainText)
        path.setWordWrap(True)
        path.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        heading = QHBoxLayout()
        heading.addWidget(path, 1)
        if record['category'] == 'Pictures':
            self.fullscreen_button.hide()
        else:
            heading.addWidget(self.fullscreen_button, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addLayout(heading)
        details = QPlainTextEdit()
        self.details = details
        details.setReadOnly(True)
        details.setMaximumHeight(190)
        lines = [f"Category: {record['category']}", f"Size: {record['size']} bytes"]
        for algorithm, digest in record.get('calculated_hashes', {}).items():
            lines.append(f'{algorithm.upper()}: {digest}')
        if hash_configuration:
            if record.get('generated_snapshot'):
                lines.append('Live host metadata snapshot. SHA256 verifies the saved snapshot; imported file hashes are not compared to generated metadata.')
            elif not hash_configuration['options']['hash_matches']:
                lines.append('Hash comparison was disabled for this scan.')
            elif record.get('kind') == 'file':
                reference_hashes = {value.strip().lower() for value in hash_configuration['hashes']}
                lines.append(f'Hash reference list: {len(reference_hashes)} unique hashes.')
                if record['matches'].get('hashes'):
                    lines.append('Hash comparison: MATCH FOUND against the complete file bytes.')
                else:
                    lines.append('Hash comparison: NO MATCH against the imported reference hashes.')
                    lines.append('Use a hash of the complete file; any byte difference, including a newline or encoding, changes the hash.')
        lines.append('Matches:')
        lines.extend(f'{kind}: {values}' for kind, values in record['matches'].items())
        if not record['matches']:
            lines.append('No hash or keyword matches; included by full artifact collection.')
        details.setPlainText('\n'.join(lines))
        layout.addWidget(details)
        self.message = QLabel()
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        if record['kind'] == 'directory':
            self.message.setText('This is a folder-name finding.')
            return
        if record.get('parsed_artifact'):
            layout.removeWidget(self.message)
            tabs = QTabWidget()
            findings = StructuredFindings(record['parsed_artifact'])
            findings.preview_requested.connect(self.preview_contained)
            tabs.addTab(findings, 'Parsed findings')
            raw = QWidget()
            tabs.addTab(raw, 'Raw source file')
            layout.addWidget(tabs, 1)
            layout = QVBoxLayout(raw)
            layout.addWidget(self.message)
        try:
            self.device, description = open_record_device(record, self)
        except (OSError, ValueError) as error:
            self.message.setText(f'Cannot open the target file: {error}')
            return
        self.message.setText(description + ' Text is shown in 64 KiB pages; use Previous/Next to browse the complete file. This tab displays raw bytes decoded as UTF-8. Parsed findings, when available, are shown separately.')
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        layout.addWidget(self.text, 1)
        buttons = QHBoxLayout()
        self.previous = QPushButton('Previous page')
        self.previous.clicked.connect(lambda: self.show_page(max(0, self.offset - self.page_bytes)))
        self.position = QLabel()
        self.next = QPushButton('Next page')
        self.next.clicked.connect(lambda: self.show_page(self.offset + self.page_bytes))
        buttons.addWidget(self.previous)
        buttons.addWidget(self.position, 1)
        buttons.addWidget(self.next)
        layout.addLayout(buttons)
        self.show_page(0)

    def show_page(self, offset):
        try:
            if isinstance(self.device, QFile):
                validate_source(self.record, self.device.handle())
            if not self.device.seek(offset):
                raise OSError('Cannot seek in the target file.')
            chunk = bytes(self.device.read(self.page_bytes))
            if self.device.errorString() and len(chunk) == 0 and offset < self.record['size']:
                raise OSError(self.device.errorString())
        except (OSError, ValueError) as error:
            self.message.setText(f'Cannot read the target file: {error}')
            self.previous.setEnabled(False)
            self.next.setEnabled(False)
            return
        self.offset = offset
        self.text.setPlainText(chunk.decode('utf-8', errors='replace'))
        self.position.setText(f"Bytes {offset}–{offset + len(chunk)} of {self.record['size']}")
        self.previous.setEnabled(offset > 0)
        self.next.setEnabled(offset + len(chunk) < self.record['size'])

    def preview_contained(self, spec):
        from interface.widgets.embedded_preview import EmbeddedPreview
        from artifacts.archive_credentials import ArchiveCredentials
        credentials = ArchiveCredentials()
        credentials.inspect(self.record, self.record.get('data', b''))
        options = getattr(self.parent(), 'triage_configuration', None) or {}
        engine = getattr(getattr(self.parent(), 'scan_controller', None), 'paused_engine', None)
        values = engine.archive_credentials.values if engine else getattr(self.parent(), 'archive_preview_credentials', [])
        EmbeddedPreview(self.record, spec, {'_archive_passwords': list(values or credentials.values)}, self).show()
