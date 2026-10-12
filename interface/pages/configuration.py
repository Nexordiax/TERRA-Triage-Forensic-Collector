from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QListWidget,
    QFileDialog, QAbstractItemView, QCheckBox, QRadioButton, QScrollArea,
)
from controllers.configuration_controller import ConfigurationController, ConfigurationError
from analyzers.image_formats import PICTURE_FILTER
from interface.widgets.content_options import ContentOptions
from interface.widgets.recovery_options import RecoveryOptions


class ReferenceListWidget(QWidget):
    def __init__(self, title, description, controller, hashes=False, pictures=False):
        super().__init__()
        self.controller = controller
        self.hashes = hashes
        self.pictures = pictures
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.heading = QLabel(title)
        self.heading.setStyleSheet('font-size: 17px; font-weight: 700;')
        layout.addWidget(self.heading)
        note = QLabel(description)
        note.setObjectName('description')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.files = QListWidget()
        self.files.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.files.setMinimumHeight(85)
        self.files.setMaximumHeight(130)
        layout.addWidget(self.files)
        buttons = QHBoxLayout()
        add = QPushButton('Import pictures…' if pictures else 'Import .txt lists…')
        add.clicked.connect(self.import_files)
        remove = QPushButton('Remove selected')
        remove.clicked.connect(self.remove_selected)
        buttons.addWidget(add)
        buttons.addWidget(remove)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.error = QLabel()
        self.error.setWordWrap(True)
        layout.addWidget(self.error)

    def paths(self):
        return [self.files.item(i).text() for i in range(self.files.count())]

    def import_files(self):
        filenames, _ = QFileDialog.getOpenFileNames(self, 'Import reference pictures' if self.pictures else 'Import reference lists', '',
                                                  PICTURE_FILTER + ';;All files (*)' if self.pictures else 'Text lists (*.txt)',
                                                  options=QFileDialog.Option.DontUseNativeDialog)
        self.add_files(filenames)

    def add_files(self, filenames):
        self.error.clear()
        for filename in filenames:
            path = str(Path(filename).resolve())
            if path in self.paths():
                continue
            try:
                if self.pictures:
                    from analyzers.image_similarity import MAX_REFERENCES
                    if self.files.count() >= MAX_REFERENCES:
                        raise ConfigurationError(f'Import at most {MAX_REFERENCES} reference pictures per scan.')
                    self.controller.read_picture(path)
                else:
                    self.controller.read_list(path, hashes=self.hashes)
            except ConfigurationError as error:
                self.error.setText(str(error))
                continue
            self.files.addItem(path)

    def remove_selected(self):
        for item in self.files.selectedItems():
            self.files.takeItem(self.files.row(item))
        self.error.clear()


class ConfigurationPage(QWidget):
    back_requested = Signal()
    start_requested = Signal(dict)

    def __init__(self):
        super().__init__()
        self.controller = ConfigurationController()
        self.setStyleSheet('''
            QCheckBox::indicator, QRadioButton::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #a0aab7;
                background: #26292e;
            }
            QCheckBox::indicator { border-radius: 3px; }
            QRadioButton::indicator { border-radius: 10px; }
            QCheckBox::indicator:checked, QRadioButton::indicator:checked {
                background: #879fbd;
                border-color: #d2deed;
            }
            QCheckBox::indicator:hover, QRadioButton::indicator:hover {
                border-color: #ffffff;
            }
            QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {
                background: #343840;
                border-color: #59616c;
            }
        ''')
        layout = QVBoxLayout(self)
        layout.setContentsMargins(35, 28, 35, 28)
        back = QPushButton('← Back')
        back.clicked.connect(self.back_requested.emit)
        layout.addWidget(back, alignment=Qt.AlignmentFlag.AlignLeft)
        heading = QLabel('Triage Configuration')
        heading.setObjectName('heading')
        layout.addWidget(heading)
        self.target_summary = QLabel()
        self.target_summary.setTextFormat(Qt.TextFormat.PlainText)
        self.target_summary.setObjectName('description')
        self.target_summary.setWordWrap(True)
        layout.addWidget(self.target_summary)
        layout.addWidget(QLabel('Collection scope'))
        self.all_artifacts = QRadioButton('Gather all supported artifacts (default)')
        self.matches_only = QRadioButton('Gather only hash, keyword, OCR-list and image-similarity matches')
        self.all_artifacts.setChecked(True)
        layout.addWidget(self.all_artifacts)
        layout.addWidget(self.matches_only)
        self.hash_heading = QLabel('Analysis and reference lists')
        self.hash_heading.setStyleSheet('font-size: 17px; font-weight: 700;')
        layout.addWidget(self.hash_heading)
        scroll = QScrollArea()
        scroll.setObjectName('analysisReferenceScroll')
        scroll.viewport().setObjectName('analysisReferenceViewport')
        scroll.setStyleSheet('''
            QScrollArea#analysisReferenceScroll,
            QWidget#analysisReferenceViewport,
            QWidget#analysisReferenceContent {
                background: #32373e;
            }
            QWidget#analysisReferenceContent ReferenceListWidget,
            QWidget#analysisReferenceContent ContentOptions,
            QWidget#analysisReferenceContent RecoveryOptions,
            QWidget#analysisReferenceContent QLabel,
            QWidget#analysisReferenceContent QCheckBox {
                background: transparent;
            }
        ''')
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        content = QWidget()
        content.setObjectName('analysisReferenceContent')
        body = QVBoxLayout(content)
        body.setSpacing(12)
        self.hash_lists = ReferenceListWidget('Hash lists', 'MD5, SHA-1, SHA-256, or SHA-512 file hashes. Import bare hashes or standard hash-tool output (for example, sha256sum). Multiple .txt lists are supported.', self.controller, hashes=True)
        self.keyword_lists = ReferenceListWidget('Keyword lists', 'One keyword or phrase per line, in UTF-8 .txt files. Blank lines and lines beginning with # are ignored.', self.controller)
        self.ocr_lists = ReferenceListWidget('OCR match lists', 'Import UTF-8 .txt lists containing words or phrases to find in images and OCR-processed PDF pages. These lists are separate from content keywords.', self.controller)
        self.image_lists = ReferenceListWidget('Reference pictures', 'Import pictures to find visually similar copies during live triage. Matching runs offline automatically when pictures are imported. Findings appear under Image Similarity Matches. The default minimum score is 70%; adjust Minimum image similarity score below. This is a review score, not a probability. Cropped or substantially edited copies may be missed.', self.controller, pictures=True)
        body.addWidget(self.hash_lists)
        body.addWidget(self.keyword_lists)
        self.options = {}
        self.content_analysis = ContentOptions()
        body.insertWidget(0, self.content_analysis)
        body.insertWidget(1, self.ocr_lists)
        body.insertWidget(2, self.image_lists)
        for key, text in (
            ('folder_names', 'Search folder names for keywords'),
            ('file_names', 'Search file names for keywords'),
            ('file_contents', 'Search file contents for keywords'),
            ('hash_matches', 'Search for files matching imported hashes'),
        ):
            checkbox = QCheckBox(text)
            checkbox.setChecked(True)
            self.options[key] = checkbox
            body.addWidget(checkbox)
        self.recovery = RecoveryOptions()
        body.addWidget(self.recovery)
        caution = QLabel('Caution: content searching opens files and may generate new filesystem artifacts, including access-time changes. Hash matching also reads file contents.')
        caution.setObjectName('description')
        caution.setWordWrap(True)
        body.addWidget(caution)
        limits = QLabel('Triage reads files from the selected drives and folders, regardless of file size. Findings refer to the source files, which can be viewed in the application. RAM dumping is a separate acquisition step. Content keywords search raw UTF-8 bytes and text from the document/OCR options enabled below. Analysis limits do not restrict raw acquisition or hashing.')
        limits.setObjectName('description')
        limits.setWordWrap(True)
        body.addWidget(limits)
        self.ocr_lists.files.model().rowsInserted.connect(self.enable_ocr_for_list)
        body.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll, 1)
        self.error = QLabel()
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        self.start_button = QPushButton('Start')
        self.start_button.setObjectName('primary')
        self.start_button.clicked.connect(self.submit)
        layout.addWidget(self.start_button, alignment=Qt.AlignmentFlag.AlignRight)

    def set_targets(self, selection):
        self.target_summary.setText('Targets: ' + ', '.join(selection['paths']) +
                                    (' · RAM acquisition requested' if selection['acquire_ram'] else '') +
                                    (' · Live state from this running host requested' if selection.get('collect_live') else ''))
        self.error.clear()
        self.recovery.targets = selection
        self.recovery.changed()

    def submit(self):
        try:
            configuration = self.controller.prepare(
                self.hash_lists.paths(), self.keyword_lists.paths(),
                {key: checkbox.isChecked() for key, checkbox in self.options.items()},
                'matches_only' if self.matches_only.isChecked() else 'all_supported',
                analysis_options=self.content_analysis.values(), ocr_files=self.ocr_lists.paths(),
                image_files=self.image_lists.paths(),
            )
        except ConfigurationError as error:
            self.error.setText(str(error))
            return
        self.error.clear()
        try:
            recovery = self.recovery.values()
        except ConfigurationError as error:
            self.error.setText(str(error))
            return
        if recovery:
            configuration['recovery'] = recovery
        self.start_requested.emit(configuration)

    def enable_ocr_for_list(self, *args):
        self.content_analysis.ocr.setChecked(True)

    def restore_values(self, configuration, selection):
        """Restore controls for Back navigation; resumed matching uses saved values."""
        self.set_targets(dict(selection, acquire_ram=selection.get('acquire_ram', False)))
        self.all_artifacts.setChecked(configuration['collection_mode'] == 'all_supported')
        self.matches_only.setChecked(configuration['collection_mode'] == 'matches_only')
        for key, widget in self.options.items():
            widget.setChecked(bool(configuration['options'][key]))
        for key, widget in (('hash_files',self.hash_lists),('keyword_files',self.keyword_lists),
                            ('ocr_files',self.ocr_lists),('image_files',self.image_lists)):
            widget.files.clear()
            widget.files.addItems(configuration.get(key, []))
        values = configuration.get('analysis_options') or {}
        controls = self.content_analysis
        for key, name in (('extract_documents','extract'),('ocr','ocr'),('ocr_pdf','ocr_pdf'),
                          ('document_images','document_images'),
                          ('ocr_all_pdf_pages','ocr_all_pages'),('skin_tone','skin'),
                          ('skin_videos','skin_videos'),('ocr_videos','ocr_videos')):
            getattr(controls, name).setChecked(bool(values.get(key)))
        for key, name, default in (('skin_threshold','threshold',30),
                                   ('image_similarity_threshold','similarity_threshold',70),('video_skin_interval','video_interval',5)):
            getattr(controls,name).setValue(values.get(key, default))
        controls.languages.setText(values.get('ocr_languages','eng'))
        controls.skin_method.setCurrentIndex(controls.skin_method.findData(values.get('skin_method','colour')))
        recovery = configuration.get('recovery') or {}
        self.recovery.enabled.setChecked(bool(recovery.get('path')))
        self.recovery.path.setText(recovery.get('path',''))
        self.recovery.acknowledgement.setChecked(bool(recovery.get('allow_target')))
