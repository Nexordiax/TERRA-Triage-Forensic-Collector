"""AppImage-only elevation adapter. Application source is not modified."""
from pathlib import Path


def relaunch_arguments(arguments, origin, launcher, extract=False):
    arguments = list(arguments)
    if not arguments or arguments[0] != '/usr/bin/env':
        return arguments
    index = 1
    while index < len(arguments) and '=' in arguments[index]:
        index += 1
    command = arguments[index:]
    if not command or command[0] != launcher or '--elevated-session' not in command:
        return arguments
    environment = [value for value in arguments[1:index]
                   if not value.startswith(('APPIMAGE=', 'TMPDIR='))]
    environment.append('APPIMAGE=' + origin)
    if extract:
        # Keep the privileged extraction separate from the user's RAM-backed /tmp cache.
        environment.append('TMPDIR=/var/tmp')
    return ['/usr/bin/env', *environment, origin,
            *(['--appimage-extract-and-run'] if extract else []), '--elevated-session']


def install(origin, launcher, extract=False):
    import controllers.privilege_controller as module
    original_process = module.QProcess
    original_controller = module.PrivilegeController

    class PackagedPrivilegeProcess(original_process):
        def setArguments(self, arguments):
            super().setArguments(relaunch_arguments(arguments, origin, launcher, extract))

    class PackagedPrivilegeController(original_controller):
        def _finished(self, code, status):
            self._read_output()
            if self.started:
                super()._finished(code, status)
                return
            detail = bytes(self.process.readAllStandardError()).decode('utf-8', errors='replace').strip()[-2000:]
            self.process.deleteLater()
            self.process = None
            message = f'Administrator launch failed (exit {code}). '
            message += detail or 'Authentication was cancelled or the elevated window could not open.'
            self.elevation_failed.emit(message)

    module.QProcess = PackagedPrivilegeProcess
    module.PrivilegeController = PackagedPrivilegeController
