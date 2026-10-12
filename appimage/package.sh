#!/bin/sh
set -eu
build_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$build_dir"
"$build_dir/../.venv/bin/python" "$build_dir/build.py"
ARCH=x86_64 "$build_dir/tools/squashfs-root/AppRun" --no-appstream \
  --runtime-file "$build_dir/tools/runtime-x86_64" \
  --mksquashfs-opt -processors --mksquashfs-opt 2 \
  "$build_dir/TERRA.AppDir" "$build_dir/output/TERRA-0.9.0-aplha.2-linux-x86_64.pending.AppImage"

if [ -f "$build_dir/output/TERRA-0.9.0-aplha.2-linux-x86_64.pending.AppImage" ]; then
    mv -f -- "$build_dir/output/TERRA-0.9.0-aplha.2-linux-x86_64.pending.AppImage" "$build_dir/output/TERRA-0.9.0-aplha.2-linux-x86_64.AppImage"
fi
