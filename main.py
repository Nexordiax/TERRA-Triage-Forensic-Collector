import sys
import json
from pathlib import Path
from PySide6.QtWidgets import QApplication
from interface.main_window import MainWindow
from interface.widgets.branding import application_icon
from interface.widgets.destination_dialog import configure_native_dialogs

if __name__ == '__main__':
    configure_native_dialogs()
    app = QApplication(sys.argv)
    app.setApplicationName('TERRA')
    app.setApplicationDisplayName('T3RRA Triage Forensic Collector - 0.9.0-aplha.2')
    app.setApplicationVersion('0.9.0-aplha.2')
    app.setDesktopFileName('terra')
    app.setWindowIcon(application_icon())
    app.setStyleSheet((Path(__file__).parent/'assets/themes/dark.qss').read_text())
    window = MainWindow()
    if '--elevated-session' in sys.argv:
        if not window.privilege_controller.is_admin():
            raise SystemExit('Administrator access was not granted.')
        window.restore_elevated_session(json.load(sys.stdin))
    window.show()
    if '--elevated-session' in sys.argv:
        print('TERRA_ELEVATED_READY', flush=True)
    sys.exit(app.exec())
