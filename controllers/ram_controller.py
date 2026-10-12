from threading import Event
from PySide6.QtCore import QObject, QThread, Signal, Slot
from artifacts.memory.collector import MemoryCollector, MemoryCancelled


class RamWorker(QThread):
    progress = Signal(dict)

    def __init__(self, destination, parent=None):
        super().__init__(parent)
        self.destination = destination
        self.cancel = Event()
        self.result = None

    def run(self):
        try:
            record = MemoryCollector(self.cancel, self.progress.emit).acquire(self.destination)
            self.result = {'status': 'saved', 'record': record}
        except MemoryCancelled:
            self.result = {'status': 'cancelled', 'error': 'RAM acquisition stopped before any memory bytes were captured.'}
        except Exception as error:
            self.result = {'status': 'failed', 'error': str(error),
                           'diagnostics': getattr(error, 'diagnostics', [])}


class RamController(QObject):
    progress = Signal(dict)
    completed = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None

    @property
    def running(self):
        return self.worker is not None

    def start(self, destination):
        if self.running:
            raise RuntimeError('RAM acquisition is already running.')
        self.worker = RamWorker(destination, self)
        self.worker.progress.connect(self.progress)
        self.worker.finished.connect(self._finished)
        self.worker.start()

    def stop(self):
        if self.worker:
            self.worker.cancel.set()

    @Slot()
    def _finished(self):
        worker = self.worker
        self.worker = None
        self.completed.emit(worker.result)
        worker.deleteLater()
