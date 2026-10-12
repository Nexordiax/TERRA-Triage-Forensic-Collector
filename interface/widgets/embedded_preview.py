"""Asynchronous, isolated decoding of pictures contained in acquired evidence."""
import base64
import hashlib
from threading import Event
from PySide6.QtCore import QThread, Signal, Slot, Qt
from PySide6.QtGui import QImage
from PySide6.QtWidgets import QVBoxLayout, QLabel, QScrollArea, QPushButton
from interface.widgets.preview_dialog import PreviewDialog
from interface.widgets.media_preview import PictureView
from analyzers.content import analyze


class PreviewWorker(QThread):
    ready = Signal(dict)
    def __init__(self, record, spec, options, parent=None):
        super().__init__(parent)
        self.record, self.spec, self.options = record, spec, options
        self.cancel = Event()
    def run(self):
        try:
            result = analyze(self.record['path'], self.record, self.record.get('data', b''), None,
                             dict(self.options, _preview_spec=self.spec), self.cancel.is_set)
        except Exception as error:
            result = dict(status='failed', limitations=[str(error)])
        self.ready.emit(result)


class EmbeddedPreview(PreviewDialog):
    def __init__(self, record, spec, options=None, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle('Contained Picture Preview')
        self.resize(800, 600)
        self.fullscreen_button.hide()
        layout = QVBoxLayout(self)
        self.label = QLabel(record['path'] + '\n' + spec.get('label', 'Contained picture'))
        self.label.setTextFormat(Qt.TextFormat.PlainText)
        self.label.setWordWrap(True)
        layout.addWidget(self.label)
        if record.get('category') == 'Pictures' and record.get('parsed_artifact') and len(spec.get('steps', [])) == 1:
            from interface.widgets.file_details import FileDetails
            self.analysis_button = QPushButton('View image / OCR / colour analysis…')
            self.analysis_button.clicked.connect(lambda: FileDetails(record, self).show())
            layout.addWidget(self.analysis_button, alignment=Qt.AlignmentFlag.AlignLeft)
        self.message = QLabel('Opening verified evidence in the isolated decoder…')
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        layout.addWidget(self.scroll, 1)
        self.pending_close = False
        self.worker = PreviewWorker(record, spec, options or {}, self)
        self.worker.ready.connect(self.show_result)
        self.worker.finished.connect(self.worker_finished)
        self.worker.start()

    @Slot(dict)
    def show_result(self, result):
        if self.pending_close: return
        if result.get('status') != 'parsed' or not result.get('preview_png'):
            self.message.setText('Cannot preview this contained picture: ' + '; '.join(result.get('limitations', [])))
            return
        payload = base64.b64decode(result['preview_png'], validate=True)
        if hashlib.sha256(payload).hexdigest() != result['preview_sha256']:
            self.message.setText('Derived preview verification failed.')
            return
        image = QImage.fromData(payload, 'PNG')
        if image.isNull():
            self.message.setText('Derived preview could not be decoded.')
            return
        self.picture = PictureView(image)
        self.scroll.setWidget(self.picture)
        self.message.setText(result['preview_note'] + '. Large previews are scaled to fit; no extracted file is written to disk.')

    def worker_finished(self):
        if self.pending_close: self.close()

    def closeEvent(self, event):
        if self.worker.isRunning():
            self.pending_close = True
            self.worker.cancel.set()
            self.hide()
            event.ignore()
            return
        super().closeEvent(event)
