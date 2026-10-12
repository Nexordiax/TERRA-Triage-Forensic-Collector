import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QCheckBox, QProgressBar
from controllers.export_controller import destination_is_target, export_basename
from interface.widgets.destination_dialog import choose_save_destination


class RamPage(QWidget):
    back_requested = Signal()
    capture_requested = Signal(str)
    continue_requested = Signal()
    stop_requested = Signal()
    finish_requested = Signal()

    def __init__(self):
        super().__init__()
        self.targets = {'paths': []}
        self.ram_only = False
        self.busy = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(35, 28, 35, 28)
        self.back_button = QPushButton('← Back')
        self.back_button.clicked.connect(self.back_requested.emit)
        layout.addWidget(self.back_button, alignment=Qt.AlignmentFlag.AlignLeft)
        heading = QLabel('RAM Acquisition')
        heading.setObjectName('heading')
        layout.addWidget(heading)
        description = QLabel('Capture RAM before file triage. With root, capture full physical RAM as a ZIP containing the LiME image and acquisition metadata; without root, capture only accessible process memory as a ZIP of raw regions and metadata. Choose an external destination. Data is streamed there, and privileges are never elevated automatically.')
        description.setWordWrap(True)
        description.setObjectName('description')
        layout.addWidget(description)
        row = QHBoxLayout()
        self.destination = QLineEdit()
        self.destination.setPlaceholderText('Destination RAM acquisition ZIP (.zip)')
        self.destination.textChanged.connect(self.changed)
        self.browse = QPushButton('Choose destination…')
        self.browse.clicked.connect(self.choose)
        row.addWidget(self.destination, 1)
        row.addWidget(self.browse)
        layout.addLayout(row)
        self.ack = QCheckBox('I understand this destination is within an examined target and RAM acquisition writes to that target.')
        self.ack.setVisible(False)
        layout.addWidget(self.ack)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.hide()
        layout.addWidget(self.progress)
        layout.addStretch()
        buttons = QHBoxLayout()
        self.stop = QPushButton('Stop RAM acquisition')
        self.stop.clicked.connect(self.stop_requested.emit)
        self.stop.hide()
        self.capture = QPushButton('Acquire RAM')
        self.capture.setObjectName('primary')
        self.capture.clicked.connect(self.submit)
        self.next = QPushButton('Continue with file triage →')
        self.next.clicked.connect(self.continue_requested.emit)
        self.next.hide()
        self.finish_button = QPushButton('Finish')
        self.finish_button.clicked.connect(self.finish_requested.emit)
        self.finish_button.hide()
        buttons.addWidget(self.stop)
        buttons.addStretch()
        buttons.addWidget(self.capture)
        buttons.addWidget(self.next)
        buttons.addWidget(self.finish_button)
        layout.addLayout(buttons)

    def prepare(self, targets, case):
        self.targets = targets
        self.ram_only = not targets.get('paths') and not targets.get('collect_live') and not targets.get('all_volumes')
        self.partial = os.geteuid() != 0
        self.extension = '.zip'
        self.default_name = export_basename(case) + ('-Process-Memory.zip' if self.partial else '-RAM.zip')
        if self.destination.text() and not self.destination.text().lower().endswith(self.extension):
            self.destination.clear()
        self.destination.setPlaceholderText('Destination partial process-memory ZIP' if self.partial else 'Destination physical RAM ZIP (.zip)')
        mode = 'Partial accessible process memory (no root)' if self.partial else 'Full physical RAM (root)'
        self.status.setText(mode + '. Select a destination, then click Acquire RAM. Existing files will not be overwritten.')
        self.next.hide()
        self.finish_button.hide()
        self.changed()

    def choose(self):
        filename = choose_save_destination(self, 'Save RAM acquisition', self.destination.text() or self.default_name,
                                           'Process memory ZIP (*.zip)' if self.partial else 'Physical RAM ZIP (*.zip)')
        if filename:
            self.destination.setText(filename if filename.lower().endswith(self.extension) else filename + self.extension)

    def changed(self):
        self.ack.setChecked(False)
        self.ack.setVisible(bool(self.destination.text()) and destination_is_target(self.destination.text(), self.targets))

    def submit(self):
        if self.busy:
            return
        filename = self.destination.text().strip()
        if not filename:
            self.status.setText('Choose the RAM image destination first.')
            return
        if not filename.lower().endswith('.zip'):
            self.status.setText('Choose a RAM acquisition filename ending in .zip.')
            return
        if destination_is_target(filename, self.targets) and not self.ack.isChecked():
            self.status.setText('Choose another destination or explicitly acknowledge writing to the examined target.')
            return
        self.capture_requested.emit(filename)

    def begin(self):
        self.busy = True
        self.finish_button.hide()
        for widget in (self.back_button, self.destination, self.browse, self.capture, self.ack, self.next):
            widget.setEnabled(False)
        self.stop.show()
        self.progress.show()
        self.progress.setRange(0, 0)
        self.status.setText('Preparing RAM acquisition…')

    def update_progress(self, value):
        if not value['total']:
            unit = 'MiB of process virtual-memory bytes copied (shared pages may repeat; not physical RAM size)' if self.partial else 'MiB acquired'
            self.status.setText(f"{value['phase']} · {value['bytes'] / 1048576:.1f} {unit}")
            self.progress.setRange(0, 0)
            return
        self.status.setText(f"{value['phase']} · {value['bytes'] / 1048576:.1f} / {value['total'] / 1048576:.1f} MiB")
        self.progress.setRange(0, 1000)
        self.progress.setValue(min(1000, int(1000 * value['bytes'] / max(1, value['total']))))

    def finish(self, result):
        self.busy = False
        for widget in (self.back_button, self.destination, self.browse, self.capture, self.ack, self.next):
            widget.setEnabled(True)
        self.stop.hide()
        self.progress.hide()
        self.next.setVisible(not self.ram_only)
        self.finish_button.setVisible(True)
        if result['status'] == 'saved':
            record = result['record']
            scope = ('Partial process memory' if record.get('memory_scope') == 'accessible_process_memory' else 'Full physical RAM image')
            if record.get('memory_scope') == 'physical_ram' and not record.get('complete_physical_ram'):
                scope = 'Physical RAM image with incomplete coverage'
            if record.get('acquisition_stopped'):
                scope = 'Stopped RAM acquisition (partial data retained)'
            if record.get('acquisition_failed'):
                scope = 'Failed RAM acquisition; captured bytes retained (image not validated)'
            self.status.setText(f"{scope} saved; file integrity verified:\n{record['path']}\n{record['size']} bytes · SHA-256: {record['sha256']}" + ('\n' + '\n'.join(record.get('limitations', [])) if record.get('limitations') else ''))
        else:
            guidance = ('Retry or go Back to change your selection.' if self.ram_only else
                        'Retry, return to privilege selection, or explicitly continue with file triage without a RAM image.')
            self.status.setText(result['error'] + '\n' + guidance)
