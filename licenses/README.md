# TERRA licence records

TERRA-owned source code and original documentation are licensed under GPL-3.0-only with the additional permission in [TERRA-UnRAR-exception.txt](TERRA-UnRAR-exception.txt). See [../COPYING](../COPYING) for scope. Copyright (c) 2026 Gersi Hajrullahi. See the unmodified GNU licence text in [../LICENSE](../LICENSE).

Third-party files retain their own licences. Copies below do not relicense them. Existing notices alongside assets and test fixtures must remain in place.

## Contents

- `AVML-MIT.txt` preserves the Microsoft AVML notice already bundled with the executable.
- `UnRAR.txt` preserves Alexander Roshal's restricted freeware terms for the bundled source archive and shared library.
- `skin-segmentation-Apache-2.0.txt` and `skin-segmentation-NOTICE.txt` cover the bundled skin model and its ONNX conversion attribution.
- `AGPL-3.0.txt` is a retained reference text. No weapon weights are included in the current Python release.
- `LGPL-3.0.txt` and `LGPL-2.1.txt` are official reference texts for dependencies.
- `libarchive-COPYING.txt` and `rarfile-ISC.txt` preserve upstream test-fixture notices.
- `python/` contains licence and bundled-library notice texts supplied by the installed direct runtime distributions. PySide6's LGPL text was obtained from its official tagged source.

## Python runtime snapshot

These are installed versions on the development workstation, not a new lockfile. The requirement ranges remain unchanged. See `python-dependencies.json` for upstream URLs and copied file paths.

| Distribution | Inspected version | Declared licence | Records |
| --- | --- | --- | --- |
| PySide6 | 6.12.0 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only | [Texts](python/PySide6-6.12.0/) |
| libpff-python | 20260926 | LGPL-3.0-or-later | [Texts](python/libpff-python-20260926/) |
| cryptography | 46.0.7 | Apache-2.0 OR BSD-3-Clause | [Texts](python/cryptography-46.0.7/) |
| pyasn1 | 0.6.4 | BSD-2-Clause | [Texts](python/pyasn1-0.6.4/) |
| dissect.database | 1.1 | Apache-2.0 | [Texts](python/dissect.database-1.1/) |
| dfindexeddb | 20260210 | Apache-2.0 | [Texts](python/dfindexeddb-20260210/) |
| pillow | 12.3.0 | MIT-CMU | [Texts](python/pillow-12.3.0/) |
| pillow_heif | 1.8.0 | BSD-3-Clause | [Texts](python/pillow_heif-1.8.0/) |
| rawpy | 0.27.1 | MIT | [Texts](python/rawpy-0.27.1/) |
| olefile | 0.47 | BSD | [Texts](python/olefile-0.47/) |
| xlrd | 2.0.2 | BSD | [Texts](python/xlrd-2.0.2/) |
| pypdfium2 | 5.14.0 | BSD-3-Clause, Apache-2.0, dependency licenses | [Texts](python/pypdfium2-5.14.0/) |
| onnxruntime | 1.31.0 | MIT License | [Texts](python/onnxruntime-1.31.0/) |
| numpy | 2.5.3 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | [Texts](python/numpy-2.5.3/) |
| av | 16.1.0 | BSD-3-Clause | [Texts](python/av-16.1.0/) |
| libarchive-c | 5.3 | CC0 | [Texts](python/libarchive-c-5.3/) |
| py7zr | 1.1.3 | LGPL-2.1-or-later | [Texts](python/py7zr-1.1.3/) |
| pyzipper | 0.4.0 | MIT | [Texts](python/pyzipper-0.4.0/) |

The table describes Python package declarations. Native libraries inside wheels can have additional terms. Keep the copied nested notices, including PDFium, LibRaw, libheif and NumPy notices. The wrapper licence alone does not cover every native dependency.

This is not a complete licence inventory for a future AppImage, Windows executable or macOS bundle. Those builds must inventory their actual transitive dependencies, Qt modules/plugins, FFmpeg, codecs, Python runtime, OCR language data and system libraries. Licence texts do not replace corresponding-source, relinking or other distribution requirements.

## Publication issues

See [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). The TERRA-owned code now carries an UnRAR linking permission. The disputed weapon model and detection feature are excluded. Complete standalone dependency compliance still requires checking each release bundle.

Official reference texts were retrieved on 2026-10-11 from GNU's licence pages. The fixture notices were retrieved from their upstream repositories. Existing bundled asset notices were copied without modification.
