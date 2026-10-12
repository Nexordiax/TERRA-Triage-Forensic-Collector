"""Build a local test AppImage without modifying the TERRA source tree."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
APPDIR = HERE / 'TERRA.AppDir'
PYTHON = APPDIR / 'usr/python'
SOURCE = APPDIR / 'usr/share/terra'
VERSION = '0.9.0-aplha.2'
EXCLUDE = shutil.ignore_patterns('__pycache__', '*.pyc', '.git', 'cases')

def copy_tree(src, dst):
    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=EXCLUDE)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def dependencies(path):
    result = subprocess.run(['ldd', str(path)], capture_output=True, text=True)
    return re.findall(r'=> (/[^\s]+)', result.stdout)

def main():
    APPDIR.mkdir(exist_ok=True)
    PYTHON.mkdir(parents=True, exist_ok=True)
    # Replace only generated application staging to avoid shipping retired files.
    if SOURCE.exists():
        shutil.rmtree(SOURCE)
    SOURCE.mkdir(parents=True, exist_ok=True)
    source_hashes = {}
    for name in ('analyzers', 'artifacts', 'controllers', 'interface', 'reporting', 'storage', 'assets', 'plugins', 'licenses'):
        copy_tree(PROJECT / name, SOURCE / name)
    for name in ('main.py', 'requirements.txt', 'requirements-forensics.txt', 'LICENSE', 'COPYING', 'THIRD_PARTY_NOTICES.md'):
        shutil.copyfile(PROJECT / name, SOURCE / name)
    for name in ('analyzers','artifacts','controllers','interface','reporting','storage'):
        for path in (PROJECT / name).rglob('*.py'):
            source_hashes[str(path.relative_to(PROJECT))] = digest(path)
    source_hashes['main.py'] = digest(PROJECT / 'main.py')
    (PYTHON / 'bin').mkdir(exist_ok=True)
    shutil.copy2('/usr/bin/python3.13', PYTHON / 'bin/python3.13')
    copy_tree(Path('/usr/lib/python3.13'), PYTHON / 'lib/python3.13')
    copy_tree(PROJECT / '.venv/lib/python3.13/site-packages', PYTHON / 'lib/python3.13/site-packages')
    copy_tree(PROJECT / '.venv/ocr', PYTHON / 'ocr')
    native = APPDIR / 'usr/lib'
    native.mkdir(exist_ok=True)
    shutil.copyfile(HERE / 'python-launcher.sh', PYTHON / 'bin/python')
    (PYTHON / 'bin/python').chmod(0o755)
    shutil.copyfile(HERE / 'sitecustomize.py', PYTHON / 'lib/python3.13/sitecustomize.py')
    shutil.copyfile(HERE / 'elevation.py', PYTHON / 'lib/python3.13/terra_packaging_elevation.py')
    shutil.copyfile(HERE / 'AppRun', APPDIR / 'AppRun')
    (APPDIR / 'AppRun').chmod(0o755)
    shutil.copyfile(HERE / 'terra.desktop', APPDIR / 'terra.desktop')
    shutil.copyfile(PROJECT / 'assets/icons/TERRA Forensic Triage.png', APPDIR / 'terra.png')
    shutil.copyfile(APPDIR / 'terra.png', APPDIR / '.DirIcon')
    elf = []
    for path in APPDIR.rglob('*'):
        if path.is_file() and not path.is_symlink():
            with path.open('rb') as handle:
                if handle.read(4) == b'\x7fELF': elf.append(path)
    # Keep glibc and the loader on the host. This test build is tied to the build host's ABI.
    excluded = re.compile(r'^(?:(?:libc|libm|libpthread|libdl|librt|libresolv)\.so|libnss_.*\.so|ld-linux.*\.so)')
    copied = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        for libraries in pool.map(dependencies, elf):
            for name in libraries:
                path = Path(name)
                if str(path).startswith(str(APPDIR)) or excluded.match(path.name): continue
                if path.name not in copied:
                    shutil.copy2(path, native / path.name)
                    copied[path.name] = str(path)
    # libarchive is loaded through ctypes rather than an ELF DT_NEEDED entry.
    archive = Path('/usr/lib/x86_64-linux-gnu/libarchive.so.13')
    shutil.copy2(archive, native / archive.name)
    for name in dependencies(archive):
        p = Path(name)
        if not excluded.match(p.name): shutil.copy2(p, native / p.name)
    # Prefer the wheel's Qt libraries over any host Qt discovered by ldd.
    for path in (PYTHON / 'lib/python3.13/site-packages/PySide6/Qt/lib').glob('libQt6*.so.6'):
        shutil.copy2(path, native / path.name)
    # Tesseract's subprocess receives its own library directory from unchanged OCR code.
    for path in native.iterdir():
        shutil.copy2(path, PYTHON / 'ocr/usr/lib/x86_64-linux-gnu' / path.name)
    manifest = dict(version=VERSION, architecture='x86_64', python=sys.version,
                    source_hashes=source_hashes, copied_host_libraries=copied,
                    host_glibc=subprocess.check_output(['getconf','GNU_LIBC_VERSION'],text=True).strip(),
                    status='local test build, not cleared for public redistribution')
    (HERE / 'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    for name, value in source_hashes.items():
        assert digest(PROJECT / name) == value, f'Source changed during build: {name}'
        assert digest(SOURCE / name) == value, f'Packaged source differs: {name}'
    print(f'AppDir ready. {len(elf)} ELF files inspected. Application source copied unchanged.', flush=True)

if __name__ == '__main__': main()
