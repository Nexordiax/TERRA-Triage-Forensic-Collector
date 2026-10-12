"""Optional local document/OCR analysis and visual colour screening."""
from PySide6.QtWidgets import QWidget, QVBoxLayout, QFormLayout, QLabel, QCheckBox, QLineEdit, QSpinBox, QPushButton, QMessageBox, QComboBox


class ContentOptions(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        heading = QLabel('Document and image analysis')
        heading.setStyleSheet('font-size: 17px; font-weight: 700;')
        layout.addWidget(heading)
        self.extract = QCheckBox('Extract document text (PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX, OpenDocument and RTF)')
        self.ocr = QCheckBox('Search pictures for entries in imported OCR match lists (default)')
        self.ocr.setChecked(True)
        self.document_images = QCheckBox('Also search images inside documents (PDF and Office; optional)')
        self.document_images.setToolTip('Enable OCR, skin screening and image similarity inside documents. Off by default to reduce decoding work.')
        self.document_images.toggled.connect(self.update_pdf_controls)
        self.ocr_pdf = QCheckBox('Also run OCR on PDF pages without readable text')
        self.ocr_all_pages = QCheckBox('OCR every PDF page, including pages with a text layer')
        self.ocr.toggled.connect(self.update_pdf_controls)
        self.ocr_pdf.toggled.connect(self.update_pdf_controls)
        self.ocr_all_pages.toggled.connect(self.update_pdf_controls)
        self.skin = QCheckBox('Screen pictures for skin areas (experimental)')
        self.skin.setChecked(True)
        self.skin_videos = QCheckBox('Also screen video frames for skin areas (optional)')
        self.skin_videos.setToolTip('Enable skin screening on sampled video frames; off by default.')
        self.ocr_videos = QCheckBox('Also search video frames for OCR matches (optional)')
        for checkbox in (self.ocr, self.document_images, self.ocr_pdf, self.ocr_all_pages, self.extract, self.skin, self.skin_videos, self.ocr_videos):
            layout.addWidget(checkbox)
        form = QFormLayout()
        self.skin_method = QComboBox()
        self.skin_method.addItem('Semantic skin segmentation (default)', 'semantic')
        self.skin_method.addItem('Skin-like colour heuristic', 'colour')
        form.addRow('Skin screening method', self.skin_method)
        self.video_interval = QSpinBox()
        self.video_interval.setRange(1, 60)
        self.video_interval.setValue(5)
        self.video_interval.setSuffix(' seconds')
        self.video_interval.setEnabled(False)
        for checkbox in (self.skin_videos, self.ocr_videos):
            checkbox.toggled.connect(self.update_video_controls)
        form.addRow('Video frame sampling interval', self.video_interval)
        self.similarity_threshold = QSpinBox()
        self.similarity_threshold.setRange(1, 100)
        self.similarity_threshold.setValue(70)
        self.similarity_threshold.setSuffix('%')
        self.similarity_threshold.setToolTip('Minimum perceptual similarity score against imported reference pictures. Lower scores produce more candidates; this is not a probability of identity.')
        form.addRow('Minimum image similarity score', self.similarity_threshold)
        self.languages = QLineEdit('eng')
        self.languages.setPlaceholderText('eng+deu+fra+rus+ara')
        self.languages.setToolTip('Combine installed Tesseract language codes with +: eng (English), deu (German), fra (French), rus (Russian), ara (Arabic). Select only the languages needed to reduce OCR processing time.')
        form.addRow('OCR languages (combine with +)', self.languages)
        installed = QPushButton('Show installed OCR languages…')
        installed.clicked.connect(self.show_languages)
        form.addRow('', installed)
        self.threshold = QSpinBox()
        self.threshold.setRange(1, 100)
        self.threshold.setValue(30)
        self.threshold.setSuffix('%')
        self.threshold.setToolTip('Minimum percentage of sampled pixels classified as skin by the selected method. A higher value produces fewer review candidates.')
        form.addRow('Minimum skin area for review', self.threshold)
        layout.addLayout(form)
        note = QLabel('Extracted text and OCR use the imported content keywords when content searching is enabled. '
                      'Separate OCR match lists search OCR text and produce an OCR Matches category, even when content searching is disabled. '
                      'OCR and skin screening add processing time and run locally. '
                      'Images inside documents are searched only when the optional document-image box is enabled. This option is off by default. '
                      'Skin-area percentages are experimental review indicators. Backgrounds and lighting affect results. They do not determine '
                      'nudity, age, identity or illegal content. In matches-only mode, skin screening does not replace '
                      'the required hash, keyword or OCR-list match. '
                      'Video skin and OCR searches are off by default and share at most 120 sampled frames. Events between samples can be missed.')
        note.setWordWrap(True)
        note.setObjectName('description')
        layout.addWidget(note)

    def values(self):
        return dict(extract_documents=self.extract.isChecked(), ocr=self.ocr.isChecked(),
                    document_images=self.document_images.isChecked(),
                    ocr_pdf=self.ocr_pdf.isChecked(),
                    ocr_all_pdf_pages=self.ocr_all_pages.isChecked(),
                    skin_tone=self.skin.isChecked(), ocr_languages=self.languages.text().strip(),
                    skin_method=self.skin_method.currentData(), skin_videos=self.skin_videos.isChecked(),
                    ocr_videos=self.ocr_videos.isChecked(),
                    video_skin_interval=self.video_interval.value(),
                    skin_threshold=self.threshold.value(),
                    image_similarity_threshold=self.similarity_threshold.value())

    def update_video_controls(self):
        self.video_interval.setEnabled(any(box.isChecked() for box in (self.skin_videos, self.ocr_videos)))

    def update_pdf_controls(self):
        selected = self.sender()
        if selected in (self.ocr_pdf, self.ocr_all_pages) and selected.isChecked():
            self.ocr.setChecked(True)
            self.document_images.setChecked(True)
            if selected is self.ocr_all_pages:
                self.ocr_pdf.setChecked(True)
        elif selected in (self.ocr, self.document_images) and not selected.isChecked():
            self.ocr_pdf.setChecked(False)
            self.ocr_all_pages.setChecked(False)
        elif selected is self.ocr_pdf and not self.ocr_pdf.isChecked():
            self.ocr_all_pages.setChecked(False)

    def show_languages(self):
        from analyzers.ocr.analyzer import installed_languages
        try:
            languages = installed_languages()
            QMessageBox.information(self, 'Installed OCR languages',
                                    'Use + to combine languages, for example eng+deu+fra.\n'
                                    'Additional language data must be installed on the acquisition tool.\n'
                                    'osd is orientation/script data, not a transcription language.\n\nInstalled language codes:\n' + ', '.join(languages))
        except (OSError, ValueError) as error:
            QMessageBox.warning(self, 'OCR language availability', str(error))
