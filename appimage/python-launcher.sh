#!/bin/sh
set -eu
python_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
appdir=$(CDPATH= cd -- "$python_root/../.." && pwd)
export QT_PLUGIN_PATH="$python_root/lib/python3.13/site-packages/PySide6/Qt/plugins"
export QT_QPA_PLATFORM_PLUGIN_PATH="$QT_PLUGIN_PATH/platforms"
export PYTHONHOME="$python_root"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1
export TERRA_BUNDLED_PYTHON="$python_root/bin/python"
export LIBARCHIVE="$appdir/usr/lib/libarchive.so.13"
unset PYTHONPATH
exec /lib64/ld-linux-x86-64.so.2 --library-path "$appdir/usr/lib:$python_root/ocr/usr/lib/x86_64-linux-gnu" "$python_root/bin/python3.13" "$@"
