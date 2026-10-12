"""Offline tests of the packaged runtime. No examined device is scanned."""
import hashlib
import importlib
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
from threading import Event

from PySide6.QtWidgets import QApplication
from interface.main_window import MainWindow
from analyzers.content import analyze
from PIL import Image

app = QApplication([])
source = Path(__import__('interface').__file__).resolve().parent.parent
app.setStyleSheet((source / 'assets/themes/dark.qss').read_text())
window = MainWindow()
assert window.windowTitle() == 'T3RRA Triage Forensic Collector - 0.9.0-aplha.2'
assert window.configuration.content_analysis.ocr.isChecked()
assert 'weapon_detection' not in window.configuration.content_analysis.values()
assert not (source / 'analyzers/weapons.py').exists()
assert not (source / 'assets/models/weapon-reference.onnx').exists()
assert not (source / 'assets/models/weapon-reference.json').exists()
assert (source / 'COPYING').is_file()
assert (source / 'licenses/TERRA-UnRAR-exception.txt').is_file()
assert not window.configuration.content_analysis.document_images.isChecked()
print('GUI pages, theme and default options: PASS')
if os.environ.get('APPIMAGE'):
    from controllers.case_controller import APPLICATION_DIRECTORY
    assert APPLICATION_DIRECTORY == Path(os.environ['APPIMAGE']).resolve().parent
    from controllers.privilege_controller import QProcess
    process = QProcess()
    process.setArguments(['/usr/bin/env','PYTHONDONTWRITEBYTECODE=1',sys.executable,'-B','main.py','--elevated-session'])
    assert 'APPIMAGE=' + os.environ['APPIMAGE'] in process.arguments()
    assert os.environ['APPIMAGE'] in process.arguments()
    assert sys.executable not in process.arguments()
    assert process.arguments()[-1] == '--elevated-session'
    print('Case default and elevation environment adapter: PASS')
for name in ('pypff','cryptography','pyasn1','dissect.database','dfindexeddb','PIL','pillow_heif','rawpy','olefile','xlrd','pypdfium2','onnxruntime','numpy','av','libarchive','py7zr','pyzipper'):
    importlib.import_module(name)
from analyzers.rar_native import library
assert library().RARGetDllVersion() == 10
print('All runtime dependency imports and native RAR backend: PASS')
from analyzers.ocr.analyzer import installed_languages, recognize
assert {'eng','deu','fra','rus','ara'} <= set(installed_languages())
image = Image.new('RGB', (640,640), 'white')
recognize(image, 'eng')
print('Bundled Tesseract and all five language packs: PASS')
import io
buffer = io.BytesIO(); image.save(buffer,format='PNG'); data = buffer.getvalue()
metadata = {'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'content_retained':True}
result = analyze('reference.png', metadata, data, None,
                 {'ocr':True,'ocr_languages':'eng','skin_tone':True,'skin_method':'semantic','skin_threshold':30}, Event().is_set)
assert result['status'] != 'failed', result
assert not result.get('worker_exit_code'),result
print('Isolated analysis worker with OCR and semantic skin model: PASS')
with tempfile.TemporaryDirectory(prefix='terra-appimage-smoke-', dir='/tmp') as tmp:
    target = Path(tmp)/'target'; target.mkdir()
    p=target/'input.txt'; p.write_text('Known synthetic hash match.\n')
    from controllers.configuration_controller import ConfigurationController
    from controllers.scan_controller import ScanEngine
    from storage.memory_store import MemoryStore
    from controllers.export_controller import ZipExporter
    config = dict(collection_mode="all_supported", hashes=[], keywords=[], options=dict(file_names=False, folder_names=False, file_contents=False, hash_matches=False))
    store = MemoryStore()
    summary = ScanEngine(dict(paths=[str(target)]), config, store).run()
    assert summary["status"] == "completed", summary
    records, diagnostics, count = store.snapshot()
    output = Path(tmp)/"export.zip"
    ZipExporter(records, diagnostics, count, dict(targets=dict(paths=[str(target)]), scan_summary=summary)).save(output)
    with zipfile.ZipFile(output) as archive:
        assert any(name.endswith("-Report.pdf") for name in archive.namelist())
        assert any(name.endswith("-Report.html") for name in archive.namelist())
        manifest = json.loads(archive.read("terra/manifest.json"))
        assert any(archive.read(row["archive_path"]) == p.read_bytes() for row in manifest["entries"])
    print('Core collection modules: PASS')
window.close()
print('PACKAGED SMOKE TEST PASSED')
