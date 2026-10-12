import os
import unittest
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ['QT_QPA_PLATFORMTHEME'] = 'generic'

from PySide6.QtCore import QProcess, Qt
from PySide6.QtWidgets import QApplication, QLineEdit
from controllers.privilege_controller import PrivilegeController
from interface.main_window import MainWindow


class PrivilegeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.admin = patch.object(PrivilegeController, 'is_admin', return_value=False)
        self.available = patch.object(PrivilegeController, 'can_request_elevation', return_value=True)
        self.admin.start()
        self.available.start()
        self.addCleanup(self.admin.stop)
        self.addCleanup(self.available.stop)
        self.window = MainWindow()
        self.addCleanup(self.window.deleteLater)

    def test_standard_user_and_back_navigation(self):
        self.window.welcome.quick_triage.emit()
        self.assertIs(self.window.stack.currentWidget(), self.window.privileges)
        with patch.object(self.window.privilege_controller, 'request_elevation') as request:
            self.window.privileges.next_button.click()
            request.assert_not_called()
        self.assertIs(self.window.stack.currentWidget(), self.window.targets)
        self.window.go_back()
        self.assertIs(self.window.stack.currentWidget(), self.window.privileges)
        self.window.go_back()
        self.assertIs(self.window.stack.currentWidget(), self.window.welcome)

    def test_explicit_authentication_and_failure(self):
        self.window.welcome.create_case.emit()
        self.window.case.findChildren(QLineEdit)[0].setText('CASE-123')
        self.window.open(self.window.privileges, True)
        page = self.window.privileges
        with patch.object(self.window.privilege_controller, 'request_elevation') as request:
            page.elevate.setChecked(True)
            request.assert_not_called()
            page.next_button.click()
            session = request.call_args.args[0]
            self.assertEqual(session['case_fields'][0], 'CASE-123')
            self.assertTrue(session['from_case'])
        self.assertFalse(page.next_button.isEnabled())
        self.assertIs(self.window.stack.currentWidget(), page)
        self.window.privilege_controller.elevation_failed.emit('Authentication cancelled')
        self.assertTrue(page.next_button.isEnabled())
        self.assertEqual(page.message.text(), 'Authentication cancelled')
        page.current.setChecked(True)
        page.next_button.click()
        self.assertIs(self.window.stack.currentWidget(), self.window.targets)

    def test_root_and_unavailable_authentication(self):
        with patch.object(PrivilegeController, 'is_admin', return_value=True):
            self.window.privileges.refresh()
            self.assertFalse(self.window.privileges.elevate.isEnabled())
            self.assertIn('root', self.window.privileges.status.text())
        with patch.object(PrivilegeController, 'can_request_elevation', return_value=False):
            self.window.privileges.refresh()
            self.assertFalse(self.window.privileges.elevate.isEnabled())
            self.assertIn('unavailable', self.window.privileges.message.text())

    def test_restore_case_navigation(self):
        self.window.restore_elevated_session({'from_case': True, 'case_fields': ['123', 'Example', 'Examiner']})
        self.assertIs(self.window.stack.currentWidget(), self.window.targets)
        self.assertTrue(self.window.from_case)
        self.window.go_back()
        self.assertIs(self.window.stack.currentWidget(), self.window.privileges)
        self.window.go_back()
        self.assertIs(self.window.stack.currentWidget(), self.window.case)
        self.assertEqual(self.window.case.findChildren(QLineEdit)[1].text(), 'Example')

    def test_restore_quick_triage_opens_targets(self):
        self.window.restore_elevated_session({'from_case': False})
        self.assertIs(self.window.stack.currentWidget(), self.window.targets)
        self.assertFalse(self.window.from_case)
        self.window.go_back()
        self.assertIs(self.window.stack.currentWidget(), self.window.privileges)
        self.window.go_back()
        self.assertIs(self.window.stack.currentWidget(), self.window.welcome)

    def test_elevation_preserves_window_size_and_position(self):
        self.window.welcome.quick_triage.emit()
        self.window.resize(720, 520)
        self.window.move(35, 45)
        self.window.show()
        self.app.processEvents()
        original_geometry = self.window.geometry()
        with patch.object(self.window.privilege_controller, 'request_elevation') as request:
            self.window.request_elevation()
            session = request.call_args.args[0]
        restored = MainWindow()
        self.addCleanup(restored.deleteLater)
        restored.restore_elevated_session(session)
        restored.show()
        self.app.processEvents()
        self.assertIs(restored.stack.currentWidget(), restored.targets)
        self.assertEqual(restored.geometry(), original_geometry)
        restored.hide()
        self.window.hide()

    def test_elevation_preserves_maximized_window(self):
        self.window.showMaximized()
        self.app.processEvents()
        with patch.object(self.window.privilege_controller, 'request_elevation') as request:
            self.window.request_elevation()
            session = request.call_args.args[0]
        restored = MainWindow()
        self.addCleanup(restored.deleteLater)
        restored.restore_elevated_session(session)
        self.assertTrue(restored.windowState() & Qt.WindowState.WindowMaximized)
        restored.hide()
        self.window.hide()

    def test_controller_start_failure(self):
        controller = self.window.privilege_controller
        messages = []
        controller.elevation_failed.connect(messages.append)
        with patch('controllers.privilege_controller.QProcess') as process_type:
            process_type.ProcessError = QProcess.ProcessError
            controller.request_elevation({'from_case': False})
            process_type.return_value.start.assert_called_once()
            self.assertEqual(process_type.return_value.setProgram.call_args.args[0], '/usr/bin/pkexec')
            controller._process_error(QProcess.ProcessError.FailedToStart)
        self.assertIsNone(controller.process)
        self.assertTrue(messages)

    def test_elevation_preserves_desktop_file_chooser_integration(self):
        controller = self.window.privilege_controller
        environment = dict(QT_QPA_PLATFORMTHEME='gtk3', XDG_CURRENT_DESKTOP='XFCE',
                           DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/1000/bus')
        with patch.dict(os.environ, environment), patch('controllers.privilege_controller.QProcess') as process_type:
            controller.request_elevation({'from_case': False})
            arguments = process_type.return_value.setArguments.call_args.args[0]
            for key, value in environment.items():
                self.assertIn(f'{key}={value}', arguments)
            self.assertNotIn('QT_QPA_PLATFORMTHEME=generic', arguments)
        controller.process = None
