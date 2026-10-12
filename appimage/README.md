# TERRA test AppImage

This folder contains a first Linux x86-64 test package and its build scripts. The existing TERRA source outside this folder is read and copied without modification. Packaging adapters live here and inside the generated AppDir.

## Run

```bash
chmod +x appimage/output/TERRA-0.9.0-aplha.2-linux-x86_64.AppImage
./appimage/output/TERRA-0.9.0-aplha.2-linux-x86_64.AppImage
```

On a host without usable FUSE, run:

```bash
./appimage/output/TERRA-0.9.0-aplha.2-linux-x86_64.AppImage --appimage-extract-and-run
```

Extraction uses temporary storage and needs room for the uncompressed runtime. It writes application runtime files, not acquired evidence. The current runtime is about 2.2 GiB before compression. Normal FUSE execution avoids extracting that whole payload. Do not put an extraction directory inside a target you intend to examine.

The package contains Python 3.13, the installed Python modules, Qt/PySide6, the original application sources and assets, AVML, the current models, archive libraries and a local Tesseract installation. It includes English, German, French, Russian and Arabic OCR data. Runtime pip installation and virtual-environment activation are unnecessary.

The original GUI and navigation remain in place. The packaging bootstrap uses the bundled Python launcher for subprocess workers. It points the case default at the folder containing the AppImage because the mounted application filesystem is read-only. The packaging-only PolicyKit adapter preserves the AppImage location during an explicitly requested elevation. It does not request elevation by itself. The user can still choose another export destination.

## Checks

The smoke test uses synthetic input in temporary folders. It does not acquire physical RAM or scan a real target.

```bash
QT_QPA_PLATFORM=offscreen ./appimage/TERRA.AppDir/AppRun \
  --terra-python ./appimage/smoke_test.py
```

It checks the GUI, module imports, all five OCR languages, an isolated image-analysis worker with both models, a synthetic file scan and ZIP export with PDF and HTML reports. `--terra-python` is a packaging diagnostic argument, not a new GUI option.

`build-manifest.json` records source hashes, runtime details and copied host libraries. The packaged source hashes are checked against the original project. `output/` contains the image and its checksum after validation.

## Rebuild after Python changes

```bash
./appimage/package.sh
```

The build reads the current project and `.venv`, refreshes the AppDir and creates a new image. It never installs modules into the original environment. If Python dependencies change, first install the updated requirements in the development environment and rebuild. Re-run the smoke tests after every build. The release label currently follows the exact GUI spelling `0.9.0-aplha.2`.

The tool downloads are recorded in `tools/appimagetool-release.json` and `tools/runtime-release.json`. Their SHA-256 digests were verified against the official GitHub release metadata. `package.sh` uses the local runtime file so image generation does not fetch a runtime at build time.

## Limits of this first build

This build uses the current Kali workstation's Python and native libraries. The workstation reports glibc 2.43. It is not a validated portable build for older Ubuntu, Debian or other distributions. A broadly compatible release should be built on a deliberately chosen older baseline and tested on the supported distributions. Host glibc, its loader, the kernel, graphics drivers, display server and PolicyKit remain host responsibilities.

GUI checks here use Qt's offscreen platform. Real XFCE/Wayland desktop integration, file dialogs, FUSE execution, administrator authentication, USB destinations and real RAM acquisition still need interactive testing. Kernel restrictions still apply to AVML. Packaging cannot remove them.

This is a local test package. Weapon detection and its model are excluded from this build. The TERRA-owned code carries an UnRAR linking exception, included in the package. A complete standalone dependency/source-delivery inventory remains to be verified. The bundled licensing documents are retained. Do not describe this package as cleared for public redistribution.

## References

- [AppImage manual packaging](https://docs.appimage.org/packaging-guide/manual.html)
- [AppDir specification](https://docs.appimage.org/reference/appdir.html)
- [Official appimagetool repository](https://github.com/AppImage/appimagetool)
- [Official type-2 runtime](https://github.com/AppImage/type2-runtime)

## Administrator relaunch correction

The packaging adapter now asks PolicyKit to execute the original AppImage with
`--elevated-session`. It does not try to start Python inside the standard user's
FUSE mount. The elevated instance gets its own mount and retains the existing
stdin session transfer, window geometry and navigation to Linux targets.

When `/dev/fuse` is unavailable, the elevated relaunch uses extraction mode with
`TMPDIR=/var/tmp`. This separates it from the user's temporary extraction cache
and avoids placing a second large runtime in RAM-backed `/tmp`. This fallback
writes temporary application runtime files to disk and requires about 2.2 GiB of
free space. It does not change the RAM evidence destination.

Failed launches now display the recorded PolicyKit/runtime stderr and exit code.
Command construction is tested without requesting privileges. Real desktop
PolicyKit authentication and acquisition still require testing on the workstation.
