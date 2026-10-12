# TERRA licensing and third-party notices

## TERRA-owned material

Copyright (c) 2026 Gersi Hajrullahi.

TERRA-owned source code, original documentation and the independent TERRA Volatility plugins are licensed under the GNU General Public License, version 3 only (`GPL-3.0-only`), with the additional UnRAR linking permission in [licenses/TERRA-UnRAR-exception.txt](licenses/TERRA-UnRAR-exception.txt). See [COPYING](COPYING) for scope. See [LICENSE](LICENSE) for the complete terms. Third-party tools, model weights, dependencies, fixtures and reproduced notices retain their original terms. This notice does not claim ownership of third-party material or collected evidence.

The TERRA licence applies only to material the project copyright holders have the right to license. The user-provided logo is not assigned an external licence by this notice. Confirm its artwork rights before redistributing it if it contains third-party material.

## UnRAR linking permission

The TERRA copyright holder grants the additional permission in
[licenses/TERRA-UnRAR-exception.txt](licenses/TERRA-UnRAR-exception.txt).
It permits combining TERRA-owned GPL-3.0-only material with UnRAR. It does
not relicense UnRAR or grant exceptions for third-party GPL-covered code.

The current UnRAR shared library and source archive are version 7.3.1.
Retain [licenses/UnRAR.txt](licenses/UnRAR.txt), upstream copyright
notices and the applicable UnRAR source archive when preparing releases.
Keep the license in distributions and the UnRAR source documentation/comments
as required by the upstream license. See `assets/tools/unrar/manifest.json`.

The project owner supplied a reply from win.rar GmbH confirming that
read/extract use and redistribution are permitted under UnRAR's existing
terms across platforms. The reply did not remove UnRAR's restrictions.
This permission addresses only the TERRA-owned GPL side of that combination.

## Weapon detection excluded

Weapon recognition is not supported. The former ECE weapon model, its
manifest and detector are excluded from the intended release. Before publishing
source or binaries, verify the actual tree and packaged assets contain no
weapon-detection weights, inference hooks or obsolete controls. Previously
built packages must be rebuilt and inspected; documentation changes do not
remove assets from existing executables.

## Bundled runtime assets

### Microsoft AVML minimal

- Version: 0.20.0, Linux x86-64.
- File: `assets/tools/avml-minimal`.
- Copyright: Microsoft Corporation.
- Declared project licence: MIT.
- Source and release: [Microsoft AVML v0.20.0](https://github.com/microsoft/avml/releases/tag/v0.20.0).
- Licence: [licenses/AVML-MIT.txt](licenses/AVML-MIT.txt).
- Recorded binary SHA-256: `79094391156f778db695cde0f84c36c3ad16987b51d80ea02f4a2ffe703b9f47`.

Retain the MIT notice and [existing backend attribution](assets/tools/README.md). The executable may contain linked dependencies with their own notices. The AVML project licence alone is not a complete inventory of every component in the prebuilt binary. Verify that binary's dependency notices for the actual release package.

### MediaPipe skin segmentation model

- File: `assets/models/skin-segmentation.onnx`.
- Original model: Google MediaPipe Selfie Multiclass 256.
- Attribution: Google LLC. ONNX conversion distributed by senty-au.
- Declared licence: Apache-2.0.
- Conversion source: [pinned senty-au model repository](https://huggingface.co/senty-au/selfie_multiclass_256x256-ONNX/tree/6db8421a7150ac20558f2c24675078eb3a1a04d0).
- Model revision: `6db8421a7150ac20558f2c24675078eb3a1a04d0`.
- Recorded SHA-256: `35ec1ecd9ee7f85073c99c00020b7f6751b69506eeacf683bc8665f6117f85b0`.
- Licence and attribution: [Apache text](licenses/skin-segmentation-Apache-2.0.txt) and [model notice](licenses/skin-segmentation-NOTICE.txt).

The downloaded ONNX weights are unchanged by TERRA. Keep the original model URL, model card, conversion revision and checksum recorded in `assets/models/skin-segmentation.json`.

## Python dependencies

The direct runtime dependencies are listed in `requirements.txt`. Their declared licences, inspected versions and copied notices are recorded in [licenses/README.md](licenses/README.md) and [licenses/python-dependencies.json](licenses/python-dependencies.json).

This source repository instructs users to install those packages through pip. It does not turn an installed virtual environment into TERRA-owned code. A packaged release that redistributes the packages must also preserve the notices for the actual dependency versions and their bundled native libraries.

Important examples include Qt/PySide6, libpff, LibRaw, libheif, PDFium and FFmpeg. Their wrapper licences do not replace the terms of underlying libraries or codecs. LGPL and GPL components can require corresponding source and other distribution provisions. Follow the actual licences for the chosen builds rather than assuming that a licence folder is sufficient.

The independent Volatility plugins run with a separately installed Volatility 3. TERRA does not bundle Volatility's framework in this source tree. The plugin guide records the tested framework version and usage.

## Third-party test fixtures

These are development fixtures, not investigative evidence.

| Files | Origin and terms | Retained notice |
| --- | --- | --- |
| `tests/fixtures/libarchive-reference.rar` | Decoded upstream libarchive RAR fixture. See upstream COPYING and any file-specific terms. | [Fixture provenance](tests/fixtures/libarchive-reference.md) and [COPYING](licenses/libarchive-COPYING.txt) |
| `tests/fixtures/rar5-encrypted-reference.rar` | rarfile upstream fixture. Copyright Marko Kreen and contributors. ISC. | [Fixture provenance](tests/fixtures/rar5-encrypted-reference.md) and [ISC text](licenses/rarfile-ISC.txt) |
| `tests/fixtures/weapon-reference-public-domain.jpg` | Glock 17 photograph by Sprenger, uploaded to Wikimedia Commons by Sanandros. Source page records its public-domain dedication. | [Photo attribution](tests/fixtures/weapon-reference-public-domain.md) |
| `tests/fixtures/skin-reference-public-domain.png` | NASA portrait of Eileen Collins distributed through scikit-image as a public-domain reference image. | [Photo attribution](tests/fixtures/skin-reference-public-domain.md) |

Other fixture generators use independent synthetic data. Their external generation tools and libraries retain their own licences when installed or distributed. The KWallet fixture notes identify the native KDE code used to generate test data. They do not imply that KDE's implementation is relicensed as TERRA code.

## Research references

Artifact catalogs contain links to upstream tools and format documentation. A citation is not a claim that TERRA owns or relicenses that source. Any copied source, data or documentation must retain its own terms. The current notice collection does not certify the provenance of every research-derived path or parser.

## Future standalone releases

A Linux AppImage or Windows executable needs an inventory of what the build actually contains. Keep upstream notices for all included packages, native libraries, models, runtimes and OCR language data. Include required corresponding source or a valid source-delivery mechanism where applicable. Check changes whenever dependencies or bundled assets are updated.

These records document the Python release without weapon detection and the UnRAR additional permission. They do not certify complete standalone redistribution compliance. Existing binaries are not verified by this documentation update.
