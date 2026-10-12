from PySide6.QtCore import Qt, QByteArray
from PySide6.QtWidgets import QMainWindow, QWidget, QStackedWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QFormLayout, QMessageBox
from interface.pages.welcome import WelcomePage
from interface.pages.targets import TargetsPage
from interface.navigation import NavigationController
from interface.pages.privileges import PrivilegesPage
from interface.pages.configuration import ConfigurationPage
from interface.pages.analysis import AnalysisPage
from interface.pages.export import ExportPage
from controllers.export_controller import ExportController
from controllers.ram_controller import RamController
from interface.pages.ram import RamPage
from interface.widgets.media_preview import MediaPreview
from interface.widgets.file_details import FileDetails
from controllers.scan_controller import ScanController
from controllers.privilege_controller import PrivilegeController
from PySide6.QtWidgets import QApplication
from interface.widgets.branding import application_icon
from controllers.recovery_controller import RecoveryController

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('T3RRA Triage Forensic Collector - 0.9.0-aplha.2')
        self.setWindowIcon(application_icon())
        self.resize(960,640)
        self.setMinimumSize(620,460)
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.welcome = WelcomePage()
        self.case = self.build_case()
        self.privilege_controller = PrivilegeController(self)
        self.privileges = PrivilegesPage(self.privilege_controller)
        self.targets = TargetsPage()
        self.target_selection = None
        self.configuration = ConfigurationPage()
        self.triage_configuration = None
        self.analysis = AnalysisPage()
        self.scan_controller = ScanController(self)
        self.recovery_controller = RecoveryController(self)
        self.recovery_controller.completed.connect(self.recovery_loaded)
        self.close_after_recovery = False
        self.close_after_previews = False
        self.close_after_scan = False
        self.ram = RamPage()
        self.ram_controller = RamController(self)
        self.archive_preview_credentials = []
        self.ram_result = None
        self.ram_history = []
        self.ram_logged_results = 0
        self.ram_destination = None
        self.automatic_partial_export = False
        self.automatic_export_result = None
        self.case_export_default = None
        self.case_export_saved = False
        self.triage_export_saved = False
        self.finish_without_export = False
        self.close_after_ram = False
        self.ram.back_requested.connect(self.go_back)
        self.ram.capture_requested.connect(self.start_ram)
        self.ram.continue_requested.connect(self.start_file_triage)
        self.ram.stop_requested.connect(self.ram_controller.stop)
        self.ram.finish_requested.connect(self.close)
        self.ram_controller.progress.connect(self.ram.update_progress)
        self.ram_controller.completed.connect(self.ram_completed)
        self.export = ExportPage()
        self.export.destination.textChanged.connect(lambda: setattr(self, 'case_export_saved', False))
        self.export_controller = ExportController(self)
        self.close_after_export = False
        for page in (self.welcome,self.case,self.privileges,self.targets,self.configuration,self.ram,self.analysis,self.export):
            self.stack.addWidget(page)
        self.navigation = NavigationController(self.stack)
        self.configuration.back_requested.connect(self.go_back)
        self.configuration.start_requested.connect(self.start_triage)
        self.analysis.back_requested.connect(self.go_back)
        self.analysis.stop_requested.connect(self.scan_controller.stop)
        self.analysis.resume_requested.connect(self.resume_triage)
        self.analysis.next_requested.connect(self.open_export)
        self.export.back_requested.connect(self.go_back)
        self.export.export_requested.connect(self.start_export)
        self.export.cancel_requested.connect(self.export_controller.stop)
        self.export.finish_requested.connect(self.confirm_finish_export)
        self.export_controller.progress.connect(self.export.update_progress)
        self.export_controller.progress.connect(self.automatic_export_progress)
        self.export_controller.completed.connect(self.export_completed)
        self.analysis.preview_requested.connect(self.preview_media)
        self.analysis.preview_embedded_requested.connect(self.preview_embedded)
        self.scan_controller.finding.connect(self.analysis.add_finding)
        self.scan_controller.hash_match.connect(self.analysis.notify_hash_match)
        self.scan_controller.progress.connect(self.analysis.update_progress)
        self.scan_controller.diagnostic.connect(self.analysis.add_diagnostic)
        self.scan_controller.completed.connect(self.scan_completed)
        self.privileges.back_requested.connect(self.go_back)
        self.privileges.next_requested.connect(lambda: self.navigation.open(self.targets))
        self.privileges.elevation_requested.connect(self.request_elevation)
        self.privilege_controller.elevated_started.connect(self.elevated_started)
        self.privilege_controller.elevated_closed.connect(QApplication.instance().quit)
        self.targets.back_requested.connect(self.go_back)
        self.targets.next_requested.connect(self.accept_targets)
        self.welcome.create_case.connect(lambda: self.open(self.case, True))
        self.welcome.resume_triage.connect(self.open_recovery)
        self.welcome.quick_triage.connect(lambda: self.open(self.privileges, False))
        self.from_case = False

    def open(self, page, from_case):
        self.from_case = from_case
        self.navigation.open(page)

    def accept_targets(self, selection):
        self.target_selection = selection
        if selection.get('acquire_ram') and not selection.get('paths') and not selection.get('all_volumes'):
            self.start_triage(None)
            return
        self.configuration.set_targets(selection)
        self.navigation.open(self.configuration)

    def start_triage(self, configuration):
        if self.scan_controller.running or self.ram_controller.running or self.export_controller.running:
            return
        if not self.target_selection:
            self.configuration.error.setText('Select targets before starting collection.')
            return
        self.triage_configuration = configuration
        self.ram_result = None
        self.ram_history = []
        self.ram_logged_results = 0
        self.ram_destination = None
        self.automatic_export_result = None
        self.case_export_default = None
        self.case_export_saved = False
        self.triage_export_saved = False
        self.finish_without_export = False
        if self.target_selection.get('acquire_ram'):
            self.ram.prepare(self.target_selection, self.case_information())
            self.navigation.open(self.ram)
        else:
            self.start_file_triage()

    def start_ram(self, destination):
        if self.ram_controller.running or self.export_controller.running:
            return
        self.ram_result = None
        self.ram.begin()
        self.ram_destination = destination
        self.ram_controller.start(destination)

    def ram_completed(self, result):
        self.ram_result = result
        self.ram_history.append(result)
        self.ram.finish(result)
        if self.close_after_ram:
            self.close()

    def start_file_triage(self):
        if self.ram_controller.running or self.scan_controller.running or self.export_controller.running:
            return
        if not self.target_selection.get('paths') and not self.target_selection.get('collect_live'):
            return
        self.analysis.begin(self.triage_configuration, self.target_selection)
        if self.target_selection.get('acquire_ram'):
            state = (self.ram_result or {}).get('status', 'not acquired')
            scope = ((self.ram_result or {}).get('record') or {}).get('collection', 'RAM acquisition')
            self.analysis.ram_status.setText(scope + ': ' + state)
        self.navigation.open(self.analysis)
        targets = dict(self.target_selection)
        from controllers.case_controller import APPLICATION_DIRECTORY
        targets['excluded_directories'] = targets.get('excluded_directories', []) + [str(APPLICATION_DIRECTORY / 'cases')]
        if self.ram_result and self.ram_result['status'] == 'saved':
            targets['excluded_files'] = [self.ram_result['record']['path']]
            if self.ram_result['record'].get('metadata_path'):
                targets['excluded_files'].append(self.ram_result['record']['metadata_path'])
        if self.triage_configuration.get('recovery'):
            self.scan_controller.start(targets, self.triage_configuration,
                                       {'case': self.case_information(), 'memory_acquisition': self.ram_result})
        else:
            self.scan_controller.start(targets, self.triage_configuration)

    def scan_completed(self, summary):
        engine = self.scan_controller.paused_engine or getattr(self.scan_controller, 'finished_engine', None)
        if engine:
            self.archive_preview_credentials = list(engine.archive_credentials.values)
        if self.triage_configuration and summary['status'] != 'stopped':
            self.triage_configuration.pop('_decryption_secrets', None)
        if self.ram_result and self.ram_result['status'] == 'saved' and not any(
                row.get('memory_image') and row['path'] == self.ram_result['record']['path']
                for row in self.scan_controller.store.records):
            record = self.scan_controller.store.add(self.ram_result['record'])
            self.analysis.add_finding(record)
        if self.ram_history:
            from datetime import datetime, timezone
            for result in self.ram_history[self.ram_logged_results:]:
                message = (result['record']['collection'] + ' saved and verified: ' + result['record']['sha256']
                           if result['status'] == 'saved' else result['error'])
                entry = {'time': datetime.now(timezone.utc).isoformat(), 'path': 'RAM acquisition',
                         'level': 'info' if result['status'] == 'saved' else 'error', 'message': message}
                self.scan_controller.store.log(entry)
                self.analysis.add_diagnostic(entry)
                for diagnostic in result.get('diagnostics', result.get('record', {}).get('acquisition_diagnostics', [])):
                    self.scan_controller.store.log(diagnostic)
                    self.analysis.add_diagnostic(diagnostic)
            self.ram_logged_results = len(self.ram_history)
            summary['diagnostic_count'] = self.scan_controller.store.diagnostic_count
        if engine and engine.recovery:
            engine.checkpoint(summary, force=True)
        self.analysis.finish(summary)
        if self.case_information():
            from controllers.case_controller import case_export_path
            self.export.prepare(self.target_selection, self.case_information(), self.scan_controller.store.records)
            try:
                self.case_export_default = str(case_export_path(self.case_information()))
                self.export.destination.setText(self.case_export_default)
                self.export.target_acknowledgement.setChecked(True)
                self.export.status.setText('Choose another destination or keep the default cases folder. Export ZIP saves now; Finish saves to the selected destination and closes.')
                if summary['status'] == 'stopped':
                    self.export.status.setText('Triage is stopped. Export ZIP saves the collected findings to your selected destination; Finish closes without saving them. Back returns to Resume.')
            except (OSError, ValueError) as error:
                from datetime import datetime, timezone
                self.case_export_default = None
                self.export.destination.clear()
                self.export.status.setText('Default case destination unavailable: ' + str(error) + '. Choose another destination.')
                diagnostic = {'time': datetime.now(timezone.utc).isoformat(), 'level': 'error',
                              'path': 'cases', 'message': 'Default case destination unavailable: ' + str(error)}
                self.scan_controller.store.log(diagnostic)
                self.analysis.add_diagnostic(diagnostic)
            if self.close_after_scan:
                if summary['status'] == 'stopped':
                    self.close()
                else:
                    self.finish_export()
            return
        if self.close_after_scan:
            self.close()

    def preview_media(self, record_id):
        record = self.scan_controller.store.get(record_id)
        if record['category'] in ('Pictures', 'Videos', 'Audio'):
            from analyzers.image_formats import EXTENDED_IMAGES
            from pathlib import Path
            if record['category'] == 'Pictures' and Path(record['path']).suffix.lower() in EXTENDED_IMAGES:
                from interface.widgets.embedded_preview import EmbeddedPreview
                dialog = EmbeddedPreview(record, {'steps': [dict(kind='image_frame', index=0)],
                                                  'label': 'Derived picture preview'}, parent=self)
                dialog.setWindowTitle('Target File Preview')
                dialog.show()
                return
            MediaPreview(record, self).show()
        else:
            FileDetails(record, self, hash_configuration=self.triage_configuration).show()

    def preview_embedded(self, record_id, spec):
        from interface.widgets.embedded_preview import EmbeddedPreview
        engine = self.scan_controller.worker.engine if self.scan_controller.worker else self.scan_controller.paused_engine
        values = engine.archive_credentials.values if engine else self.archive_preview_credentials
        EmbeddedPreview(self.scan_controller.store.get(record_id), spec,
                        {'_archive_passwords': list(values)}, self).show()

    def resume_triage(self):
        if self.scan_controller.running or self.ram_controller.running or self.export_controller.running:
            return
        if self.scan_controller.paused_engine is None:
            return
        if not self.analysis.recovery_acknowledgement.isHidden():
            if not self.analysis.recovery_acknowledgement.isChecked():
                self.analysis.current_path.setText('Acknowledge the progress write to this recovery destination before resuming.')
                return
            self.triage_configuration['recovery']['allow_target'] = True
            self.analysis.recovery_acknowledgement.hide()
        self.case_export_saved = False
        self.triage_export_saved = False
        self.finish_without_export = False
        self.automatic_export_result = None
        self.close_after_scan = False
        self.analysis.resume()
        self.navigation.open(self.analysis)
        self.scan_controller.resume()

    def open_recovery(self):
        if self.scan_controller.running or self.ram_controller.running or self.export_controller.running or self.recovery_controller.running:
            return
        from PySide6.QtWidgets import QFileDialog
        filename, _ = QFileDialog.getOpenFileName(self, 'Resume saved TERRA triage', '', 'TERRA recovery sessions (*.terra-session)')
        if filename:
            self.welcome.recovery_status.setText('Loading and verifying saved findings…')
            self.welcome.resume_button.setEnabled(False)
            self.recovery_controller.load(filename)

    def recovery_loaded(self, result):
        self.welcome.resume_button.setEnabled(True)
        if self.close_after_recovery:
            self.close()
            return
        if result['status'] != 'loaded':
            self.welcome.recovery_status.setText('Cannot load this recovery session: ' + result['error'])
            return
        engine, context = result['engine'], result['context']
        self.target_selection = engine.targets
        self.triage_configuration = engine.configuration
        self.triage_configuration['recovery'] = dict(engine.configuration.get('recovery', {}), path=engine.recovery.path)
        self.target_selection['excluded_files'] = list(dict.fromkeys(self.target_selection.get('excluded_files', []) +
            [engine.recovery.path + suffix for suffix in ('', '-journal', '-wal', '-shm')]))
        self.scan_controller.store = engine.store
        self.scan_controller.paused_engine = engine
        self.scan_controller.finished_engine = engine
        self.from_case = bool(context.get('case'))
        for field, name in zip(self.case.findChildren(QLineEdit), ('id','name','examiner')):
            field.setText(str((context.get('case') or {}).get(name, '')))
        self.configuration.restore_values(self.triage_configuration, self.target_selection)
        self.targets.entire_system.setChecked(bool(engine.targets.get('all_volumes')))
        self.targets.acquire_ram.setChecked(bool(engine.targets.get('acquire_ram')))
        selected = set(engine.targets['paths'])
        available = set()
        for index in range(self.targets.volumes.count()):
            item = self.targets.volumes.item(index)
            path = item.data(Qt.ItemDataRole.UserRole)
            available.add(path)
            item.setCheckState(Qt.CheckState.Checked if path in selected else Qt.CheckState.Unchecked)
        self.targets.folders.clear()
        self.targets.folders.addItems(sorted(selected - available))
        self.ram_result = context.get('memory_acquisition')
        self.ram_history = []
        self.ram_logged_results = 0
        self.archive_preview_credentials = list(engine.archive_credentials.values)
        self.case_export_saved = False
        self.triage_export_saved = False
        self.finish_without_export = False
        self.automatic_export_result = None
        self.close_after_scan = self.close_after_export = False
        self.analysis.begin(engine.configuration, engine.targets)
        self.analysis.results.setUpdatesEnabled(False)
        try:
            for record in engine.store.records:
                self.analysis.add_finding({key:value for key,value in record.items() if key != 'data'})
        finally:
            self.analysis.results.setUpdatesEnabled(True)
        self.analysis.diagnostics.setPlainText('\n'.join(f"{row.get('time','')} [{row.get('level','')}] {row.get('path','')}: {row.get('message','')}" for row in engine.store.diagnostics))
        summary = result.get('summary') or dict(engine.counts, status='stopped', diagnostic_count=engine.store.diagnostic_count,
                                              bytes_used=engine.store.bytes_used, coverage=engine.coverage_summary())
        if summary['status'] not in ('completed', 'completed_with_errors'):
            summary = dict(summary, status='stopped')
        else:
            self.scan_controller.paused_engine = None
        self.analysis.finish(summary)
        from controllers.export_controller import destination_is_target
        needs_ack = destination_is_target(engine.recovery.path, engine.targets) and not engine.configuration['recovery'].get('allow_target')
        self.analysis.recovery_acknowledgement.setVisible(needs_ack)
        self.analysis.current_path.setText('Recovered the last committed progress. Resume retries unfinished files and rechecks sources for changes. Export saves the recovered findings.')
        self.navigation.history = [self.welcome] + ([self.case] if self.from_case else []) + [self.privileges, self.targets, self.configuration]
        self.stack.setCurrentWidget(self.analysis)
        self.export.prepare(self.target_selection, self.case_information(), engine.store.records)
        self.export.destination.clear()
        self.case_export_default = None

    def closeEvent(self, event):
        from interface.widgets.embedded_preview import EmbeddedPreview
        pending = [dialog for dialog in self.findChildren(EmbeddedPreview) if dialog.worker.isRunning()]
        if pending:
            if not self.close_after_previews:
                for dialog in pending:
                    dialog.worker.finished.connect(self.close, Qt.ConnectionType.QueuedConnection)
            self.close_after_previews = True
            for dialog in pending:
                dialog.close()
            event.ignore()
            return
        if self.recovery_controller.running:
            self.close_after_recovery = True
            self.recovery_controller.stop()
            event.ignore()
            return
        if self.ram_controller.running:
            self.close_after_ram = True
            self.ram_controller.stop()
            event.ignore()
            return
        if self.export_controller.running:
            self.close_after_export = True
            if not self.automatic_partial_export:
                self.export_controller.stop()
            event.ignore()
            return
        if self.scan_controller.running:
            self.close_after_scan = True
            self.analysis.request_stop()
            event.ignore()
            return
        if not self.finish_without_export and self.case_information() and self.analysis.summary and self.analysis.summary['status'] != 'stopped' and not self.case_export_saved and not self.automatic_export_result:
            event.ignore()
            self.finish_export()
            return
        if self.triage_configuration:
            self.triage_configuration.pop('_decryption_secrets', None)
        super().closeEvent(event)

    def shell(self, title, description):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(35,28,35,28)
        layout.setSpacing(20)
        back = QPushButton('← Back')
        back.setFixedWidth(110)
        back.clicked.connect(self.go_back)
        layout.addWidget(back, alignment=Qt.AlignmentFlag.AlignLeft)
        heading = QLabel(title)
        heading.setObjectName('heading')
        layout.addWidget(heading)
        label = QLabel(description)
        label.setObjectName('description')
        label.setWordWrap(True)
        layout.addWidget(label)
        return page,layout

    def go_back(self):
        if self.scan_controller.running or self.ram_controller.running or (self.export_controller.running and not self.automatic_partial_export):
            return
        self.navigation.back()

    def case_information(self):
        if not self.from_case:
            return None
        fields = [field.text() for field in self.case.findChildren(QLineEdit)]
        return dict(zip(('id', 'name', 'examiner'), fields))

    def open_export(self):
        if self.scan_controller.running or self.ram_controller.running:
            return
        if self.automatic_partial_export or self.automatic_export_result:
            self.navigation.open(self.export)
            if self.automatic_export_result:
                self.export.finish(self.automatic_export_result)
            return
        if self.export_controller.running:
            return
        if self.case_information() and self.analysis.summary:
            self.navigation.open(self.export)
            return
        self.export.prepare(self.target_selection, self.case_information(), self.scan_controller.store.records)
        self.navigation.open(self.export)

    def start_export(self, filename, allow_target):
        if self.scan_controller.running or self.export_controller.running or self.ram_controller.running:
            return
        self.automatic_export_result = None
        context = {'case': self.case_information(), 'targets': self.target_selection,
                   'configuration': self.triage_configuration, 'scan_summary': self.analysis.summary,
                   'memory_acquisition': self.ram_result,
                   'partial_scan': (self.analysis.summary or {}).get('status') == 'stopped',
                   'exclude_memory_images': True}
        if self.case_information():
            context.update(exclude_memory_images=True, export_layout='source_tree',
                           partial_scan=(self.analysis.summary or {}).get('status') not in ('completed', 'completed_with_errors'))
        self.export.begin()
        self.export_controller.start(filename, self.scan_controller.store, context, allow_target)

    def export_completed(self, result):
        if self.automatic_partial_export:
            self.automatic_partial_export = False
            self.export_completed_automatically(result)
            return
        self.export.finish(result)
        if result['status'] == 'saved':
            self.triage_export_saved = True
        if self.case_information() and result['status'] == 'saved':
            self.case_export_saved = True
        if result['status'] != 'saved':
            from datetime import datetime, timezone
            self.scan_controller.store.log({'time': datetime.now(timezone.utc).isoformat(),
                                            'level': 'error', 'path': self.export.destination.text(),
                                            'message': 'Export: ' + result['error']})
        if self.close_after_export and result['status'] == 'saved':
            self.close()

    def confirm_finish_export(self):
        if self.export_controller.running or self.scan_controller.running or self.ram_controller.running:
            return
        if not self.triage_export_saved:
            answer = QMessageBox.question(
                self, 'Finish without exporting?',
                'The triage findings have not been exported to a ZIP.\n'
                'Are you sure you want to finish without exporting them?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        # Explicit Finish accepts leaving this collection, including cases.
        # Window-close case autosaving remains unchanged for other close paths.
        self.finish_without_export = True
        self.close()

    def finish_export(self):
        if (self.analysis.summary or {}).get('status') == 'stopped':
            self.close()
            return
        if self.case_information() and not self.case_export_saved and not self.automatic_export_result:
            if self.export_controller.running:
                self.close_after_export = True
                return
            filename = self.export.destination.text().strip()
            if not filename:
                self.navigation.open(self.export)
                self.export.status.setText('Choose a destination to save this case before finishing.')
                return
            self.close_after_export = True
            if filename == self.case_export_default:
                self.start_export(filename, True)
            else:
                self.export.submit()
            return
        self.close()

    def export_completed_automatically(self, result):
        from datetime import datetime, timezone
        self.automatic_export_result = result
        self.export.finish(result)
        saved = result['status'] == 'saved'
        if saved:
            self.triage_export_saved = True
        message = ('Triage automatically saved: ' + str(result['path']) if saved
                   else 'Automatic triage save failed: ' + result['error'])
        self.analysis.current_path.setText(message)
        entry = {'time': datetime.now(timezone.utc).isoformat(), 'level': 'info' if saved else 'error',
                 'path': result.get('path', self.ram_destination or 'cases'), 'message': message}
        self.scan_controller.store.log(entry)
        self.analysis.add_diagnostic(entry)
        if self.close_after_export and saved:
            self.close()

    def automatic_export_progress(self, progress):
        if self.automatic_partial_export:
            self.analysis.current_path.setText(f"Saving triage ZIP · {progress['phase']} · {progress['done']} / {progress['total']} · {progress['path']}")

    def build_case(self):
        page,layout = self.shell('Create Case','Enter case information to continue.')
        form = QFormLayout()
        for name in ('Case ID','Case name','Examiner'):
            form.addRow(name,QLineEdit())
        layout.addLayout(form)
        self.case_error = QLabel()
        self.case_error.setWordWrap(True)
        self.case_error.hide()
        layout.addWidget(self.case_error)
        button = QPushButton('Next →')
        button.setObjectName('primary')
        button.clicked.connect(self.create_case)
        layout.addWidget(button,alignment=Qt.AlignmentFlag.AlignRight)
        layout.addStretch()
        return page

    def create_case(self):
        from controllers.case_controller import cases_directory
        try:
            cases_directory()
        except (OSError, ValueError) as error:
            self.case_error.setText('Cannot create cases folder: ' + str(error))
            self.case_error.show()
            return
        self.case_error.hide()
        self.open(self.privileges, True)

    def request_elevation(self):
        session = {
            'from_case': self.from_case,
            'case_fields': [field.text() for field in self.case.findChildren(QLineEdit)],
            'window_geometry': bytes(self.saveGeometry().toBase64()).decode('ascii'),
        }
        self.privilege_controller.request_elevation(session)

    def elevated_started(self):
        # Keep the launcher alive while QProcess owns the elevated application.
        QApplication.instance().setQuitOnLastWindowClosed(False)
        self.hide()

    def restore_elevated_session(self, session):
        for field, value in zip(self.case.findChildren(QLineEdit), session.get('case_fields', [])):
            field.setText(value)
        if session.get('from_case'):
            self.open(self.case, True)
        self.open(self.privileges, bool(session.get('from_case')))
        self.navigation.open(self.targets)
        geometry = session.get('window_geometry')
        if geometry:
            self.restoreGeometry(QByteArray.fromBase64(geometry.encode('ascii')))
