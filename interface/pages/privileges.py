from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QRadioButton


class PrivilegesPage(QWidget):
    back_requested = Signal()
    next_requested = Signal()
    elevation_requested = Signal()

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        layout = QVBoxLayout(self)
        layout.setContentsMargins(35, 28, 35, 28)
        layout.setSpacing(20)
        self.back_button = QPushButton('← Back')
        self.back_button.clicked.connect(self.back_requested.emit)
        layout.addWidget(self.back_button, alignment=Qt.AlignmentFlag.AlignLeft)
        heading = QLabel('Privilege Selection')
        heading.setObjectName('heading')
        layout.addWidget(heading)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        description = QLabel('Root rights are required for a more comprehensive acquisition of RAM, including a full physical memory dump. Without root, TERRA acquires only process memory that Linux permits it to read; some or all processes may be inaccessible. Administrator access may also allow protected artifacts. Authentication is required; access is not guaranteed.')
        description.setObjectName('description')
        description.setWordWrap(True)
        layout.addWidget(description)
        self.current = QRadioButton('Continue with current privileges')
        self.current.setChecked(True)
        self.elevate = QRadioButton('Request administrator privileges')
        layout.addWidget(self.current)
        layout.addWidget(self.elevate)
        self.message = QLabel()
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        layout.addStretch()
        self.next_button = QPushButton('Next →')
        self.next_button.setObjectName('primary')
        self.next_button.clicked.connect(self.proceed)
        self.elevate.toggled.connect(lambda checked: self.next_button.setText('Authenticate →' if checked else 'Next →'))
        layout.addWidget(self.next_button, alignment=Qt.AlignmentFlag.AlignRight)
        controller.elevation_failed.connect(self.failed)
        self.refresh()

    def refresh(self):
        admin = self.controller.is_admin()
        self.status.setText('Current access: Administrator (root).' if admin else 'Current access: Standard user.')
        self.elevate.setEnabled(not admin and self.controller.can_request_elevation())
        if not self.elevate.isEnabled():
            self.current.setChecked(True)
        if not admin and not self.controller.can_request_elevation():
            self.message.setText('PolicyKit (pkexec) is unavailable. Continue with current privileges, or launch TERRA as an administrator.')

    def proceed(self):
        if self.elevate.isChecked():
            self.set_busy(True)
            self.message.setText('Waiting for administrator authentication. An elevated TERRA window will replace this window after successful authentication.')
            self.elevation_requested.emit()
        else:
            self.next_requested.emit()

    def set_busy(self, busy):
        for widget in (self.back_button, self.next_button, self.current):
            widget.setEnabled(not busy)
        self.elevate.setEnabled(not busy and not self.controller.is_admin() and self.controller.can_request_elevation())

    def failed(self, message):
        self.set_busy(False)
        self.message.setText(message)
