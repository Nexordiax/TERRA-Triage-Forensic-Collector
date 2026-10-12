# T3RRA Triage Forensic Collector

TERRA is a Linux forensic triage application for investigators who need to identify relevant files and preserve them for further analysis. It brings file matching, Linux artifact collection, media screening and RAM acquisition into one graphical workflow.

The aim is to give law enforcement and other authorized examiners a free tool for an initial assessment of a device. An examiner can look for known files, search investigation keywords, review pictures and collect supporting system activity without first processing a full disk image. The collected evidence can then be examined in a dedicated forensic analysis tool.

TERRA is currently an alpha release intended for testing. Linux is the documented and tested source-code platform, and a Windows build has been produced. Linux and Windows standalone packages are intended to be distributed through GitHub Releases after platform-specific testing. Features and acquisition backends may differ between platforms; do not assume Linux-specific artifact collection or RAM acquisition works on Windows. Coverage across distributions, Windows versions and configurations still requires validation.

## What TERRA collects

You can scan all mounted disk volumes or choose individual mounts and folders. File triage searches the selected filesystem targets. RAM acquisition is a separate operation and can be used on its own.

Supported artifact categories include:

- Device information, installed applications and user accounts.
- Browser history, sessions, bookmarks and supported credential stores.
- OS activity, shell history, service configuration and persistence traces.
- Connected devices, network configuration and remote-access activity.
- Pictures, videos, audio, documents and email.
- Communication applications and supported chat stores.
- Encrypted containers and known encryption headers.
- Cryptocurrency wallets, cloud storage, dark-web applications and anti-forensics tools.
- Virtual machines and container-related artifacts.

The combined Linux catalog currently contains **218 named artifact definition groups**. There are **128 definitions with parser adapters** and **90 collected as raw files**. These numbers describe catalog entries, not individual files or a guarantee that every field can be decoded. Some parsers provide partial metadata. Access restrictions, missing keys and unsupported versions can limit collection or interpretation.

The catalog includes paths for Debian and Ubuntu, Kali, Fedora and RHEL, Arch, openSUSE, Alpine, Gentoo, Slackware, Void and Nix-based systems. It also covers selected GNOME, KDE and XFCE activity and supported Snap and Flatpak application paths.

See [Linux artifact coverage](docs/linux-artifacts.md) and [cross-distribution coverage](docs/linux-distribution-coverage.md) for the maintained paths, categories, sources and known limits.

## Finding relevant files

Import one or more hash lists and keyword lists as text files. TERRA can search file and folder names, search file contents and calculate file hashes against the imported values. Hash matches appear in their own category and trigger a notification during collection.

A separate OCR list searches text recognized in pictures. Reference pictures can also be imported for offline visual similarity matching. The default minimum similarity score is **70%** and can be adjusted in the configuration page. This is a perceptual similarity score, not a probability that two pictures are identical.

Collection can gather all supported artifacts or focus on matches. Findings appear in categories as the scan progresses. Categories stay collapsed until you open them. You can inspect file details, parsed records and supported media while collection continues.

Supported archives are searched automatically within the collector's safety and resource limits. Contained files retain a link to their source archive. Unsupported or inaccessible members are recorded as limitations rather than presented as successfully collected files.

## OCR and media review

Picture OCR and skin-area screening are selected by default. OCR matching uses the imported OCR entries. Languages can be combined in the configuration page, for example `eng+deu` for English and German.

Images inside PDF and Office documents are searched only when you enable the document-image option. Document text extraction is also optional.

Video-frame searching has separate options for OCR and skin areas. Both are off by default. When enabled, they share sampled frames rather than analyzing every frame. The sampling interval is adjustable and events between samples can be missed.

Skin results are review candidates. Skin screening does not determine nudity, age or illegal content. An examiner needs to review the original image or video before drawing conclusions.

All of these searches run locally. TERRA does not upload evidence to an external analysis service.

## Downloads and source code

The GitHub repository contains TERRA Python source code and documentation. Standalone **Linux** and **Windows** packages will be attached to versioned entries under [GitHub Releases](https://github.com/Nexordiax/TERRA-Triage-Forensic-Collector/releases) once each build is verified. The presence of a release asset, rather than this README, determines whether a download is available.

Weapon recognition is **not supported** in this release. The former weapon-detection model and inference feature are excluded. Picture OCR, reference-image similarity and skin-area screening are separate functions and are not weapon detectors.

## Linux source installation

The following commands are for Linux; Windows standalone builds have their own runtime and installation requirements.

## Install and run

The current Python dependencies were validated with **Python 3.13 on Linux x86-64**. Use a virtual environment to keep TERRA's modules separate from the system Python installation.

On Kali, Debian or Ubuntu, install the native prerequisites on the workstation that runs TERRA:

```bash
sudo apt install python3-venv python3-dev build-essential libsnappy-dev libarchive13 tesseract-ocr tesseract-ocr-eng tesseract-ocr-deu tesseract-ocr-fra tesseract-ocr-rus tesseract-ocr-ara
```

Package names can differ between distributions and releases. Other Linux distributions need their equivalent packages. Tesseract and its language data are system packages and are not installed by pip.

From the TERRA project folder, create the environment, install the Python modules and start the application:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

`requirements.txt` includes the application runtime dependencies for the GUI, forensic readers, archive handling and media analysis. `requirements-forensics.txt` remains an alias for older installation instructions. `requirements-forensics-test.txt` contains additional fixture generators needed for development tests.

For later runs, activate the existing environment and start TERRA:

```bash
cd /path/to/TERRA
source .venv/bin/activate
python main.py
```

The OCR packages above provide English (`eng`), German (`deu`), French (`fra`), Russian (`rus`) and Arabic (`ara`). Use **Show installed OCR languages** in the configuration page to check what is available on your workstation.

Installing dependencies needs access to the relevant package repositories. Once the dependencies and included local models are available, collection and analysis work offline.

## Typical workflow

1. Choose **Quick Triage** or create a case with the examiner and case details.
2. Continue with standard privileges or explicitly request administrator privileges.
3. Select mounted volumes or folders. Enable RAM acquisition if needed.
4. Import reference lists and pictures, then choose the collection and analysis options.
5. Review the live findings. Open a category to see its collected files.
6. Export the results to the chosen destination and check the collection summary.

Back and Next controls let you move between stages. A stopped file scan keeps its findings available for review, resuming or manual export. Stopping file triage does not automatically save those findings to a ZIP.

Optional persistent recovery can retain a checkpoint for a later session. A scan held only in RAM cannot be recovered after an application crash. See [recovery and archive review](docs/archive-preview-recovery.md) for the checkpoint workflow.

## RAM acquisition with administrator rights

On Linux x86-64, TERRA uses the bundled Microsoft AVML backend to acquire physical memory in LiME format. Select administrator privileges through the privilege page, enable **Acquire RAM** and choose a destination on the acquisition page.

You can acquire RAM without selecting any filesystem targets. In that case, TERRA goes directly to the RAM acquisition page and offers **Finish** when the operation is done.

The saved RAM ZIP contains the `.lime` image and acquisition metadata and logs. Completed and stopped acquisitions retain the bytes that were acquired when there is evidence to save. TERRA checks the image structure, records coverage limitations and calculates hashes. A partial capture is not labelled as complete physical RAM.

Root access does not guarantee that acquisition will succeed. Kernel lockdown and memory-source restrictions can still prevent it. TERRA does not disable those protections or load an acquisition kernel module. Allow sufficient destination space for the image and its packaging.

Extract the `.lime` image before analyzing it with a compatible memory-analysis tool. Standard Volatility 3 Linux analysis needs suitable symbols for the captured kernel. The separate TERRA process-memory plugins described below are for non-root captures, not LiME images.

AVML attribution and licensing are available in [assets/tools/README.md](assets/tools/README.md).

## RAM acquisition without root

Choose standard privileges and enable the same **Acquire RAM** option. TERRA collects accessible process memory through `/proc/<pid>/mem` and saves a process-memory ZIP. Linux ownership, ptrace restrictions and other security controls determine which processes can be read. TERRA does not change those controls or pause the processes.

For example, an examiner could save a capture as:

```text
/media/examiner/USB/2026-10-11_17-00-05-RAM.zip
```

This is an example destination, not a required filename. The archive contains:

```text
manifest.json
processes/
  <pid>/
    regions/
      <captured-region>.bin
logs/
  diagnostics.jsonl
  acquisition.log
README.txt
```

Where accessible, the manifest records executable identity, command-line arguments, process start time, mapping permissions and acquisition times. It maps the compact region files back to their original virtual addresses. Denied access, unreadable ranges, unattempted ranges and observed changes are recorded explicitly. Missing memory is not filled with invented bytes.

This capture is **process virtual memory, not a full physical RAM image**. Shared mappings can appear in several processes, so the total copied bytes can exceed the machine's installed RAM. TERRA excludes its own process from this acquisition. If no other process memory is readable, it reports that no capture was saved.

If you stop an acquisition after readable memory has been captured, TERRA saves the partial results to the selected destination. Check the manifest and acquisition logs to understand what was collected and what is missing.

See [process-memory context](docs/process-memory-context.md) for the recorded fields and collection limits.

## Analyze a non-root capture with Volatility 3

TERRA includes six independent plugins in [plugins/volatility3](plugins/volatility3). They read the capture ZIP directly or an extracted capture directory. They do not require kernel symbols and do not import the TERRA application.

Use the environment where you already run Volatility 3. Volatility is a separate analysis tool and is not installed by TERRA's `requirements.txt`. The plugins were tested with Volatility 3 **2.28.2**.

The examples below assume that the `vol` command is available, TERRA is in `/opt/TERRA` and the capture is on a USB device. Replace those paths with your own.

First verify the captured region hashes:

```bash
vol --offline -p /opt/TERRA/plugins/volatility3 \
  terramemory.Verify --capture "/media/examiner/USB/2026-10-11_17-00-05-RAM.zip"
```

List recorded process identities and acquisition context:

```bash
vol --offline -p /opt/TERRA/plugins/volatility3 \
  terramemory.Processes --capture "/media/examiner/USB/2026-10-11_17-00-05-RAM.zip"
```

Search readable process memory for a literal value:

```bash
vol --offline -p /opt/TERRA/plugins/volatility3 \
  terramemory.Search --capture "/media/examiner/USB/2026-10-11_17-00-05-RAM.zip" \
  --needle "example.com" --ignore-case
```

Extract printable strings from one recorded PID:

```bash
vol --offline -p /opt/TERRA/plugins/volatility3 \
  terramemory.Strings --capture "/media/examiner/USB/2026-10-11_17-00-05-RAM.zip" \
  --minimum 6 --pid 1234
```

The complete plugin set is:

| Plugin | Purpose |
| --- | --- |
| `terramemory.Processes` | Show captured, unavailable and excluded processes with recorded context. |
| `terramemory.Maps` | Show mappings, captured segments, virtual addresses and gaps. |
| `terramemory.Strings` | Find printable strings with their source PID and virtual address. |
| `terramemory.Search` | Search literal UTF-8, UTF-16 or hexadecimal values. |
| `terramemory.Verify` | Compare each captured region with its recorded SHA-256 hash. |
| `terramemory.Dump` | Export verified region bytes with JSON context and address-map files. |

If you use a Volatility source checkout, replace `vol` with `python3 /path/to/volatility3/vol.py`. The `-p` path must contain `terramemory.py` and the `terra_support` directory. Use `--capture` for these plugins rather than the global `-f` argument.

The input ZIP must contain `manifest.json` and `processes/` at its root. If the capture is inside a larger TERRA export, extract the inner process-memory ZIP first. Do not pass the outer triage ZIP or a `.lime` file.

These plugins use TERRA's captured bytes and recorded context. They cannot recover absent kernel memory or provide the kernel structures required by standard plugins such as `linux.pslist`. A hash match confirms agreement with the manifest, not completeness or independent authenticity of the acquisition.

See the [plugin guide](plugins/volatility3/README.md) for UTF-16 and hexadecimal searches, JSON output, region export and result limits.

## Export and further analysis

Triage findings are copied into a ZIP at the destination you choose. For a created case, the default destination is the `cases/` folder beside TERRA. You can select another folder or external device instead. RAM acquisition uses its own chosen destination.

A triage export separates original logical files from generated analysis:

```text
evidence/
  volume-001/<original-filesystem-path>/...
  volume-002/<original-filesystem-path>/...
terra/
  live/
  analysis/
  reports/
  logs/
  evidence-versions/
  manifest.json
  checksums.sha256
  IMPORT.txt
  README.txt
```

The export contains PDF and HTML reports, a collection summary, diagnostic logs and source-linked JSONL/CSV records. The manifest records original paths, hashes, timestamps and collection status. ZIP entries also carry timestamp metadata where supported. The way an extraction tool restores timestamps can differ, so keep the manifest with the evidence.

RAM archives are saved separately by the RAM acquisition workflow. The triage export records their metadata and references without duplicating the image. Where RAM evidence is included in an export, it is placed under `terra/memory/`.

To process the logical evidence in Magnet AXIOM or another analysis tool, extract the ZIP and add the `evidence/volume-NNN` folders as file and folder evidence. This preserves directory relationships for original files and collected companions. The export is not a disk image and does not include deleted or unallocated data. AXIOM does not automatically interpret TERRA's custom manifest. Proprietary AXIOM import still needs testing with the installed product version.

Read the summary and logs after exporting. They describe recorded access failures, decoding problems and collection limits. Finish asks for confirmation if the current triage findings have not been successfully exported.

See [export layout and import guidance](docs/case-export-import.md) for the folder structure, timestamp handling and case naming.

## Evidence handling and limitations

TERRA uses RAM-first storage for file triage and opens examined files for reading. It does not execute discovered files, silently elevate privileges or upload evidence. Collection errors are recorded in diagnostic logs. Inaccessible artifacts are not presented as collected.

A live examination still changes the running system. Reading files can affect access times depending on filesystem settings. Starting the application and acquiring RAM also changes memory. RAM-first collection reduces evidence writes but does not make a live examination write-free.

File export validates source identity and hashes. If a source changes or becomes unavailable, the export records the failure rather than silently treating different bytes as the collected evidence. Browser databases and other live files can change during collection. Decryption depends on supported formats and accessible keys.

TERRA provides triage findings for examiner review. Automated matches, parsed timestamps and experimental media results need to be interpreted with the original evidence and recorded limitations. Broader forensic validation and distribution testing remain part of the work toward a stable release.

Developed by Gersi Hajrullahi.
