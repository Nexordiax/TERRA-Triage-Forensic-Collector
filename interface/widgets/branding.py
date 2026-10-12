"""Shared application icon and a welcome-only illustration with painted edge fades."""
from pathlib import Path
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QPixmap
from PySide6.QtWidgets import QWidget, QSizePolicy

LOGO_PATH = Path(__file__).resolve().parents[2] / 'assets/icons/TERRA Forensic Triage.png'


def application_icon():
    return QIcon(str(LOGO_PATH))


class WelcomeIllustration(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.image = QPixmap(str(LOGO_PATH))
        self.setMaximumWidth(340)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setAccessibleName('TERRA Forensic Triage logo')

    def sizeHint(self):
        return QSize(300, 380)

    def paintEvent(self, event):
        if self.image.isNull():
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        size = min(self.width(), self.height())
        x, y = (self.width() - size) // 2, (self.height() - size) // 2
        painter.drawPixmap(x, y, size, size, self.image)
        # Composite the original image's outer edges into the existing app grey.
        background = QColor('#26292e')
        clear = QColor(background)
        clear.setAlpha(0)
        edge = max(1, size * 0.16)
        for start, end in (((x, y), (x + edge, y)), ((x + size, y), (x + size - edge, y)),
                           ((x, y), (x, y + edge)), ((x, y + size), (x, y + size - edge))):
            gradient = QLinearGradient(*start, *end)
            gradient.setColorAt(0, background)
            gradient.setColorAt(1, clear)
            painter.fillRect(x, y, size, size, gradient)
