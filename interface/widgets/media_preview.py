from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QImageReader, QPixmap
from PySide6.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea, QSizePolicy
from interface.widgets.preview_dialog import PreviewDialog
from storage.source_file import open_record_device


class PictureView(QLabel):
    """Fit the original image to the current view without changing evidence."""
    def __init__(self, image):
        super().__init__()
        self.original_pixmap = QPixmap.fromImage(image)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.setPixmap(self.original_pixmap.scaled(
            self.contentsRect().size(), Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation))


class MediaPreview(PreviewDialog):
    """Read media in-app from a cached copy or verified read-only source device."""
    def __init__(self, record, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Target File Preview')
        self.resize(760, 540)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.player = None
        layout = QVBoxLayout(self)
        label = QLabel(record['path'])
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setWordWrap(True)
        heading = QHBoxLayout()
        heading.addWidget(label, 1)
        if record['category'] == 'Pictures':
            self.fullscreen_button.hide()
        else:
            heading.addWidget(self.fullscreen_button, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addLayout(heading)
        if record.get('parsed_artifact'):
            from interface.widgets.file_details import FileDetails
            self.analysis_button = QPushButton('View image / OCR / colour analysis…')
            self.analysis_button.clicked.connect(lambda: FileDetails(record, self).show())
            layout.addWidget(self.analysis_button, alignment=Qt.AlignmentFlag.AlignLeft)
            similarities = [row for row in record['parsed_artifact'].get('entries', [])
                            if row.get('type') == 'image_similarity_match']
            if similarities:
                best = max(similarities, key=lambda row: row['similarity_percent'])
                summary = QLabel(f"Best reference-picture match: {best['reference_path']} · "
                                 f"{best['similarity_percent']:.2f}% visual similarity · Manual review required")
                summary.setTextFormat(Qt.TextFormat.PlainText)
                summary.setWordWrap(True)
                summary.setObjectName('description')
                layout.addWidget(summary)
            screens = [row for row in record['parsed_artifact'].get('entries', []) if row.get('type') in ('skin_colour_screen', 'skin_semantic_screen')]
            if screens:
                summary = QLabel(f"Highest sampled skin area: {max(row['skin_like_percent'] for row in screens):.1f}% · Experimental screening for manual review")
                summary.setWordWrap(True)
                summary.setObjectName('description')
                layout.addWidget(summary)
        self.error = QLabel()
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        try:
            self.buffer, source_description = open_record_device(record, self)
        except (OSError, ValueError) as error:
            self.error.setText(f'Cannot open this target file: {error}')
            return
        description = QLabel(source_description)
        description.setObjectName('description')
        description.setWordWrap(True)
        layout.addWidget(description)
        if record['category'] == 'Pictures':
            reader = QImageReader(self.buffer)
            if reader.size().width() * reader.size().height() > 40000000:
                self.error.setText('Image dimensions exceed the preview limit.')
                return
            image = reader.read()
            if image.isNull():
                self.error.setText('This image format could not be decoded.')
                return
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            self.picture = PictureView(image)
            scroll.setWidget(self.picture)
            layout.addWidget(scroll, 1)
        else:
            try:
                from PySide6.QtMultimedia import QAudioOutput, QMediaPlayer
                from PySide6.QtMultimediaWidgets import QVideoWidget
                self.player = QMediaPlayer(self)
                self.audio = QAudioOutput(self)
                self.player.setAudioOutput(self.audio)
                if record['category'] == 'Videos':
                    video = QVideoWidget()
                    layout.addWidget(video, 1)
                    self.player.setVideoOutput(video)
                self.player.errorOccurred.connect(lambda *_: self.error.setText(self.player.errorString()))
                # Decode the read-only device; never launch an examined file.
                self.player.setSourceDevice(self.buffer, QUrl.fromLocalFile('/acquired-preview' + Path(record['path']).suffix))
                buttons = QHBoxLayout()
                for title, action in (('Play', self.player.play), ('Pause', self.player.pause), ('Stop', self.player.stop)):
                    button = QPushButton(title)
                    button.clicked.connect(action)
                    buttons.addWidget(button)
                layout.addLayout(buttons)
            except (ImportError, RuntimeError) as error:
                self.error.setText(f'Media playback is unavailable: {error}')

    def closeEvent(self, event):
        if self.player:
            self.player.stop()
            self.player.setSource(QUrl())
        super().closeEvent(event)
