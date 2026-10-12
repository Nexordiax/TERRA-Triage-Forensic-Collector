import json
import os
import shutil
import sys
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, Signal


class PrivilegeController(QObject):
    elevated_started = Signal()
    elevation_failed = Signal(str)
    elevated_closed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.process = None
        self.output = b''
        self.started = False

    @staticmethod
    def is_admin():
        return hasattr(os, 'geteuid') and os.geteuid() == 0

    @staticmethod
    def can_request_elevation():
        return sys.platform.startswith('linux') and shutil.which('pkexec') is not None

    def request_elevation(self, session):
        """Called only after the user explicitly requests administrator access."""
        if self.process is not None:
            return
        if not self.can_request_elevation():
            self.elevation_failed.emit('Administrator authentication is unavailable: install PolicyKit (pkexec), or launch TERRA as an administrator.')
            return
        self.started = False
        self.output = b''
        process = QProcess(self)
        self.process = process
        process.setProgram(shutil.which('pkexec'))
        arguments = ['/usr/bin/env', 'PYTHONDONTWRITEBYTECODE=1']
        for name in ('DISPLAY', 'XAUTHORITY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR',
                     'DBUS_SESSION_BUS_ADDRESS', 'XDG_CURRENT_DESKTOP', 'DESKTOP_SESSION', 'QT_QPA_PLATFORMTHEME'):
            if os.environ.get(name):
                arguments.append(f'{name}={os.environ[name]}')
        arguments.extend([sys.executable, '-B', str(Path(__file__).resolve().parents[1] / 'main.py'), '--elevated-session'])
        process.setArguments(arguments)
        process.started.connect(lambda: self._send_session(session))
        process.readyReadStandardOutput.connect(self._read_output)
        process.errorOccurred.connect(self._process_error)
        process.finished.connect(self._finished)
        process.start()

    def _send_session(self, session):
        self.process.write(json.dumps(session).encode())
        self.process.closeWriteChannel()

    def _read_output(self):
        self.output += bytes(self.process.readAllStandardOutput())
        if not self.started and b'TERRA_ELEVATED_READY\n' in self.output:
            self.started = True
            self.elevated_started.emit()

    def _process_error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self.elevation_failed.emit('Could not start administrator authentication. You can continue with current privileges.')
            self.process.deleteLater()
            self.process = None

    def _finished(self, code, status):
        self._read_output()
        self.process.deleteLater()
        self.process = None
        if self.started:
            self.elevated_closed.emit()
        else:
            self.elevation_failed.emit('Administrator authentication was cancelled or failed, or the elevated window could not open. You can retry or continue with current privileges.')
