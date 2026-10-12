"""Packaging-only initialization for the unchanged Python application."""
import os
from pathlib import Path
import sys
import site

launcher = os.environ.get('TERRA_BUNDLED_PYTHON')
if launcher:
    site.addsitedir(str(Path(launcher).resolve().parents[1] / 'lib/python3.13/site-packages'))
    sys.executable = launcher
    appdir = Path(launcher).resolve().parents[3]
    source = appdir / 'usr/share/terra'
    sys.path.insert(0, str(source))
    # The mounted AppDir is read-only. Keep the existing cases default beside the AppImage.
    import controllers.case_controller as case_controller
    origin = os.environ.get('APPIMAGE')
    case_controller.APPLICATION_DIRECTORY = Path(origin).resolve().parent if origin else appdir.parent

    # Root must start the original image, not enter the user's FUSE mount.
    if origin:
        from terra_packaging_elevation import install
        extract = not Path('/dev/fuse').exists() or bool(os.environ.get('APPIMAGE_EXTRACT_AND_RUN'))
        install(origin, launcher, extract=extract)
