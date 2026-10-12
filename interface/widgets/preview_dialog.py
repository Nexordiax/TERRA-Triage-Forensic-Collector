"""Shared full-screen controls for evidence preview windows."""
from PySide6.QtCore import Qt, QEvent
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QDialog, QPushButton


class PreviewDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._windowed_geometry = None
        self.fullscreen_button = QPushButton('Full screen', self)
        self.fullscreen_button.setAutoDefault(False)
        self.fullscreen_button.setToolTip('Toggle full screen (F11). Press Esc to return to the window.')
        self.fullscreen_button.clicked.connect(self.toggle_fullscreen)
        self.fullscreen_shortcut = QShortcut(QKeySequence('F11'), self)
        self.fullscreen_shortcut.activated.connect(self.toggle_fullscreen)

    def toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
            if self._windowed_geometry is not None:
                self.restoreGeometry(self._windowed_geometry)
        else:
            self._windowed_geometry = self.saveGeometry()
            self.showFullScreen()

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange and hasattr(self, 'fullscreen_button'):
            self.fullscreen_button.setText('Exit full screen' if self.isFullScreen() else 'Full screen')

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape and self.isFullScreen():
            self.toggle_fullscreen()
            event.accept()
            return
        super().keyPressEvent(event)
