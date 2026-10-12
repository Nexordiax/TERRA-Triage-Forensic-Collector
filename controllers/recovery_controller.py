"""Load persisted evidence on a worker thread; collection still uses ScanController."""
from threading import Event
from PySide6.QtCore import QObject, QThread, Signal
from storage.recovery import load_session


class RecoveryWorker(QThread):
    def __init__(self, filename, parent=None):
        super().__init__(parent)
        self.filename = filename
        self.cancel = Event()
        self.result = None
    def run(self):
        try:
            engine, context, summary = load_session(self.filename, self.cancel.is_set)
            self.result = dict(status='loaded', engine=engine, context=context, summary=summary)
        except Exception as error:
            self.result = dict(status='failed', error=str(error))


class RecoveryController(QObject):
    completed = Signal(object)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
    @property
    def running(self): return self.worker is not None
    def load(self, filename):
        if self.running: raise RuntimeError('A recovery session is already loading')
        self.worker = RecoveryWorker(filename, self)
        self.worker.finished.connect(self.finished)
        self.worker.start()
    def stop(self):
        if self.worker: self.worker.cancel.set()
    def finished(self):
        worker = self.worker
        self.worker = None
        self.completed.emit(worker.result)
        worker.deleteLater()
