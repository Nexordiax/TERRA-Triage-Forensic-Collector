from collections import deque
from interface.widgets.finding_priority import category_rank, finding_rank

from PySide6.QtCore import Qt, Signal, Slot, QTimer, QElapsedTimer
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTreeWidget, QCheckBox,
    QTreeWidgetItem, QPlainTextEdit, QProgressBar, QMessageBox,
)


class AnalysisPage(QWidget):
    back_requested = Signal()
    stop_requested = Signal()
    resume_requested = Signal()
    next_requested = Signal()
    preview_requested = Signal(int)
    preview_embedded_requested = Signal(int, dict)

    def __init__(self):
        super().__init__()
        self.record_items = {}
        self.categories = {}
        self.subcategories = {}
        self.category_counts = {}
        self.hash_notifications = deque()
        self.notification = None
        self.summary = None
        self.stopping = False
        self.last_progress = {}
        self.clock = QElapsedTimer()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(35, 28, 35, 28)
        self.back_button = QPushButton('← Back')
        self.back_button.clicked.connect(self.back_requested.emit)
        layout.addWidget(self.back_button, alignment=Qt.AlignmentFlag.AlignLeft)
        heading = QLabel('Live Triage Collection')
        heading.setObjectName('heading')
        layout.addWidget(heading)
        description = QLabel('Triage examines files on the selected drives and folders. Expand a category and double-click a file to view it in the application. The source files remain on their drive; triage does not perform a RAM dump or execute examined files.')
        description.setObjectName('description')
        description.setWordWrap(True)
        layout.addWidget(description)
        priority_note = QLabel('Review priority: hash matches → content matches → OCR matches → image similarity → picture/video skin review.')
        priority_note.setObjectName('description')
        priority_note.setWordWrap(True)
        layout.addWidget(priority_note)
        self.scope = QLabel()
        self.scope.setTextFormat(Qt.TextFormat.PlainText)
        self.scope.setWordWrap(True)
        layout.addWidget(self.scope)
        self.ram_status = QLabel()
        self.ram_status.setWordWrap(True)
        self.ram_status.setObjectName('description')
        layout.addWidget(self.ram_status)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.current_path = QLabel('Waiting for the first file…')
        self.current_path.setTextFormat(Qt.TextFormat.PlainText)
        self.current_path.setWordWrap(True)
        self.current_path.setObjectName('description')
        layout.addWidget(self.current_path)
        self.progress = QProgressBar()
        layout.addWidget(self.progress)
        self.results = QTreeWidget()
        self.results.setObjectName('triageResults')
        self.results.viewport().setObjectName('triageResultsViewport')
        self.results.setStyleSheet('''
            QTreeWidget#triageResults {
                background: #3b4149;
                border: 1px solid #727b88;
            }
            QWidget#triageResultsViewport { background: #3b4149; }
        ''')
        self.results.setHeaderLabels(['Artifact / source path', 'Matches', 'Size', 'Status'])
        self.results.setColumnWidth(0, 430)
        self.results.setColumnWidth(1, 220)
        self.results.setExpandsOnDoubleClick(False)
        self.results.itemClicked.connect(self.toggle_category)
        self.results.itemDoubleClicked.connect(self.preview)
        layout.addWidget(self.results, 3)
        layout.addWidget(QLabel('Diagnostic log (retained in RAM)'))
        self.diagnostics = QPlainTextEdit()
        self.diagnostics.setObjectName('triageDiagnostics')
        self.diagnostics.viewport().setObjectName('triageDiagnosticsViewport')
        self.diagnostics.setStyleSheet('''
            QPlainTextEdit#triageDiagnostics {
                background: #3b4149;
                border: 1px solid #727b88;
            }
            QWidget#triageDiagnosticsViewport { background: #3b4149; }
        ''')
        self.diagnostics.setReadOnly(True)
        self.diagnostics.setMaximumBlockCount(10000)
        layout.addWidget(self.diagnostics, 1)
        self.recovery_acknowledgement = QCheckBox('I understand resuming writes progress to this recovery file inside an examined target.')
        self.recovery_acknowledgement.hide()
        layout.addWidget(self.recovery_acknowledgement)
        buttons = QHBoxLayout()
        buttons.addStretch()
        self.stop_button = QPushButton('Stop')
        self.stop_button.clicked.connect(self.request_stop)
        self.resume_button = QPushButton('Resume')
        self.resume_button.clicked.connect(self.resume_requested.emit)
        self.resume_button.hide()
        self.next_button = QPushButton('Next →')
        self.next_button.setObjectName('primary')
        self.next_button.clicked.connect(self.next_requested.emit)
        self.next_button.hide()
        buttons.addWidget(self.stop_button)
        buttons.addWidget(self.resume_button)
        buttons.addWidget(self.next_button)
        layout.addLayout(buttons)

    def begin(self, configuration=None, targets=None):
        self.recovery_acknowledgement.hide()
        self.recovery_acknowledgement.setChecked(False)
        self.results.clear()
        self.record_items.clear()
        self.diagnostics.clear()
        self.categories.clear()
        self.subcategories.clear()
        self.category_counts.clear()
        self.hash_notifications.clear()
        if self.notification:
            self.notification.close()
        self.summary = None
        self.stopping = False
        self.last_progress = {}
        if configuration:
            mode = ('All artifacts and files' if configuration['collection_mode'] == 'all_supported'
                    else 'Hash, keyword, OCR-list and image-similarity matches only')
            hash_state = (f"Enabled ({len(configuration['hashes'])} reference hashes)" if configuration['options']['hash_matches'] else 'Disabled')
            self.scope.setText(f"Collection: {mode} · Hash matching: {hash_state}\nTargets: {', '.join((targets or {}).get('paths', []))}")
        else:
            self.scope.clear()
        self.ram_status.setText('Separate RAM dump: requested.'
                                if (targets or {}).get('acquire_ram') else 'Separate RAM dump: not requested.')
        self.clock.start()
        self.timer.start(500)
        self.back_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.next_button.hide()
        self.resume_button.hide()
        self.progress.setRange(0, 0)
        self.current_path.setText('Waiting for the first file…')
        self.update_status()

    @Slot(dict)
    def update_progress(self, progress):
        self.last_progress = progress
        if progress.get('path'):
            self.current_path.setText(progress['path'])
            self.current_path.setToolTip(progress['path'])
            size = progress.get('file_size', 0)
            if size:
                self.current_path.setText(f"{progress['path']}\nRead {progress.get('file_bytes_read', 0) / (1024 * 1024):.1f} / {size / (1024 * 1024):.1f} MiB")
        self.update_status()

    def update_status(self):
        if self.summary:
            return
        if self.stopping:
            self.status.setText('Stopping collection… Findings and diagnostics will be preserved.')
            return
        counts = self.last_progress
        seconds = self.clock.elapsed() // 1000 if self.clock.isValid() else 0
        self.status.setText(f"Scanning · {seconds}s · {counts.get('examined', 0)} files examined · {counts.get('findings', 0)} findings · {counts.get('hash_checked', 0)} files hash-checked · {counts.get('hash_matches', 0)} hash matches · {counts.get('parsed_records', 0)} parsed records · {counts.get('errors', 0)} errors")
        self.status.setToolTip(counts.get('path', ''))

    @Slot(dict)
    def add_finding(self, record):
        for category, item in self.record_items.pop(record['id'], []):
            parent = item.parent()
            if parent:
                parent.takeChild(parent.indexOfChild(item))
                self.category_counts[category] -= 1
                self.categories[category].setText(0, f'{category} ({self.category_counts[category]})')
        categories = [record['category']]
        if record['matches'].get('hashes'):
            categories.append('Hash Matches')
        if record['matches'].get('file_names'):
            categories.append('File Name Matches')
        if record['matches'].get('file_contents'):
            categories.append('File Content Matches')
        if record['matches'].get('ocr'):
            categories.append('OCR Matches')
        if record['matches'].get('image_similarity'):
            categories.append('Image Similarity Matches')
        categories.extend(record.get('additional_categories', []))
        for category in dict.fromkeys(categories):
            if category not in self.categories:
                node = QTreeWidgetItem([category])
                node.setData(0, Qt.ItemDataRole.UserRole + 3, category_rank(category))
                index = 0
                while index < self.results.topLevelItemCount() and self.results.topLevelItem(index).data(0, Qt.ItemDataRole.UserRole + 3) <= category_rank(category):
                    index += 1
                self.results.insertTopLevelItem(index, node)
                self.categories[category] = node
                self.categories[category].setExpanded(False)
            parent = self.categories[category]
            group = record.get('category_subgroups', {}).get(category)
            if group:
                key = (category, group)
                if key not in self.subcategories:
                    self.subcategories[key] = QTreeWidgetItem(parent, [group])
                    self.subcategories[key].setExpanded(False)
                parent = self.subcategories[key]
            matches = '; '.join(f'{key}: {value}' for key, value in record['matches'].items())
            source_status = (('Partial process memory verified' if record.get('memory_scope') == 'accessible_process_memory' else 'Full RAM image verified') if record.get('memory_image') else
                             'Folder-name match' if record.get('kind') == 'directory' else 'Source file verified')
            if record.get('memory_image') and record.get('acquisition_stopped'):
                source_status = 'Stopped RAM acquisition · partial data preserved and hashed'
            parsed = record.get('parsed_artifact')
            if record.get('generated_snapshot'):
                source_status = 'Live host metadata snapshot'
            if parsed:
                source_status += (f" · {parsed['record_count']} parsed records" if parsed['status'] == 'parsed' else
                                  f" · {parsed['record_count']} partial records" if parsed['status'] == 'partial' else
                                  ' · raw only' if parsed['status'] == 'raw_only' else ' · parser failed')
            item = QTreeWidgetItem(parent, [record['path'], matches, str(record['size']), source_status])
            item.setData(0, Qt.ItemDataRole.UserRole, record['id'])
            rank = finding_rank(record)
            item.setData(0, Qt.ItemDataRole.UserRole + 2, rank)
            if not group and rank < 100:
                parent.takeChild(parent.indexOfChild(item))
                index = 0
                while index < parent.childCount() and parent.child(index).data(0, Qt.ItemDataRole.UserRole + 2) <= rank:
                    index += 1
                parent.insertChild(index, item)
            self.record_items.setdefault(record['id'], []).append((category, item))
            if parsed:
                import json
                seen = set()
                for row in parsed.get('entries', []):
                    spec = row.get('preview')
                    if not spec: continue
                    key = json.dumps(spec['steps'], sort_keys=True)
                    if key in seen: continue
                    seen.add(key)
                    child = QTreeWidgetItem(item, [spec.get('label', row.get('locator', 'Contained picture')), 'Contained picture', '', 'Double-click to preview'])
                    child.setData(0, Qt.ItemDataRole.UserRole, record['id'])
                    child.setData(0, Qt.ItemDataRole.UserRole + 4, spec)
                item.setExpanded(False)
            item.setToolTip(0, record['collection'])
            item.setToolTip(3, 'Double-click to view the complete target file in the application.' if record.get('kind') == 'file' else 'Folder-name finding')
            if group:
                parent.setText(0, f'{group} ({parent.childCount()})')
                screen = record.get('encryption_detection', {})
                entropy = screen.get('entropy_bits_per_byte')
                if entropy is not None:
                    item.setText(3, f'{source_status} · entropy {entropy:.3f}/8')
                    item.setData(0, Qt.ItemDataRole.UserRole + 1, entropy)
                    parent.takeChild(parent.indexOfChild(item))
                    index = 0
                    while index < parent.childCount() and (parent.child(index).data(0, Qt.ItemDataRole.UserRole + 1) or 0) >= entropy:
                        index += 1
                    parent.insertChild(index, item)
            self.category_counts[category] = self.category_counts.get(category, 0) + 1
            self.categories[category].setText(0, f'{category} ({self.category_counts[category]})')

    def toggle_category(self, item, column):
        if item.data(0, Qt.ItemDataRole.UserRole) is None or item.childCount():
            item.setExpanded(not item.isExpanded())

    @Slot(dict)
    def add_diagnostic(self, entry):
        self.diagnostics.appendPlainText(f"{entry['time']} [{entry['level']}] {entry['path']}: {entry['message']}")

    def request_stop(self):
        self.stopping = True
        self.stop_button.setEnabled(False)
        self.status.setText('Stopping collection… Findings and diagnostics will be preserved.')
        self.timer.stop()
        self.stop_requested.emit()

    @Slot(dict)
    def finish(self, summary):
        self.summary = summary
        self.timer.stop()
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.back_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.next_button.show()
        self.resume_button.setVisible(summary['status'] == 'stopped')
        self.current_path.setText('Scan finished. Source files can be viewed from the findings below.')
        if summary['status'] == 'stopped':
            self.current_path.setText('Triage stopped. Findings stay in RAM. Resume, go Back, or choose Next to optionally export them.')
        self.status.setText(f"{summary['status'].replace('_', ' ').capitalize()} · {summary['examined']} files examined · {summary.get('findings', summary['collected'])} findings · {summary.get('hash_checked', 0)} files hash-checked · {summary.get('hash_matches', 0)} hash matches · {summary.get('parsed_records', 0)} parsed records · {summary['errors']} errors")
        if summary['diagnostic_count'] > 10000:
            self.diagnostics.appendPlainText('Diagnostic display/storage limit reached; additional diagnostics are counted in the scan summary.')

    def resume(self):
        self.summary = None
        self.stopping = False
        self.back_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.resume_button.hide()
        self.next_button.hide()
        self.progress.setRange(0, 0)
        self.timer.start(500)
        self.current_path.setText('Resuming file triage; existing findings are retained.')

    @Slot(dict)
    def notify_hash_match(self, record):
        self.hash_notifications.append(record)
        self.show_next_notification()

    def show_next_notification(self):
        if self.notification or not self.hash_notifications:
            return
        record = self.hash_notifications.popleft()
        message = QMessageBox(self)
        message.setWindowTitle('Hash match found')
        message.setTextFormat(Qt.TextFormat.PlainText)
        message.setText(record['path'])
        message.setInformativeText('\n'.join(f'{algorithm}: {digest}' for algorithm, digest in record['matches'].get('hashes', {}).items()))
        if record['matches'].get('archive_hashes'):
            for match in record['matches']['archive_hashes']:
                message.setInformativeText(message.informativeText() + '\n' + match['locator'] + '\n' + '\n'.join(f'{algorithm}: {digest}' for algorithm, digest in match['hashes'].items()))
            message.setInformativeText(message.informativeText() + '\n\nMember hashes verified against complete decompressed member bytes; enclosing container retained unchanged.')
        else:
            message.setInformativeText(message.informativeText() + '\n\nHash verified against the complete source file on the selected drive.')
        message.setIcon(QMessageBox.Icon.Warning)
        message.setStandardButtons(QMessageBox.StandardButton.Ok)
        message.setModal(False)
        message.finished.connect(self.notification_closed)
        self.notification = message
        message.show()

    def notification_closed(self):
        message = self.notification
        self.notification = None
        if message:
            message.deleteLater()
        QTimer.singleShot(0, self.show_next_notification)

    def preview(self, item, column):
        record_id = item.data(0, Qt.ItemDataRole.UserRole)
        if record_id is not None:
            spec = item.data(0, Qt.ItemDataRole.UserRole + 4)
            if spec:
                self.preview_embedded_requested.emit(record_id, spec)
            else:
                self.preview_requested.emit(record_id)
