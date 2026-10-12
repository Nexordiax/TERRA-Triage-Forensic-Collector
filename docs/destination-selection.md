# Desktop destination selection

RAM and file-triage export use the same destination-selection helper. On Linux,
startup enables installed Qt desktop integration before QApplication is created:
GTK on XFCE/GNOME-style desktops and the desktop portal on KDE when available.
An explicitly configured non-generic platform theme is preserved. Headless tests
use the existing Qt storage browser.

The native save dialog uses desktop places and device integration. On XFCE this
is the GTK save chooser, rather than a separate Thunar file-manager window.
Thunar is not launched to select a filename. Native chooser appearance and device
visibility depend on the desktop session and its storage services.

Administrator relaunch preserves the platform theme, desktop identity and session
bus address instead of forcing the generic Qt theme. TERRA's main GUI stylesheet,
window geometry, navigation, ZIP names, target-write acknowledgement and exclusive
no-overwrite acquisition/export remain unchanged.

Restart TERRA after this update so Qt can load the native integration. When native
integration is unavailable, the existing storage-aware Qt dialog remains the
fallback. Cancelling a native chooser ends selection; it does not open a second
dialog. TERRA does not automatically mount devices or write evidence when browsing.

Changed: `interface/widgets/destination_dialog.py`, `main.py`,
`controllers/privilege_controller.py`, `tests/test_destination_dialog.py`,
`tests/test_privileges.py`, this document.

- [Qt native file-dialog behavior](https://doc.qt.io/qt-6/qfiledialog.html#platform-notes)
- [Desktop portal save-file interface](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.FileChooser.html)
