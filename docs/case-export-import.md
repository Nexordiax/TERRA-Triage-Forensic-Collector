# Automatic case exports and analysis-tool import

Creating a case (Next on the case form) creates `cases/` beside the application if needed. When file triage ends, including a stopped or incomplete run, the export page uses that folder as the default destination. The examiner can select any other destination before saving. Export ZIP saves immediately. Finish asks for confirmation when the current triage collection has not been successfully exported; No returns to the export page, and Yes closes without exporting. After a successful export, Finish closes without a prompt, even if the destination field is subsequently edited. Starting or resuming collection resets this saved state. Closing a completed unsaved case through the window-close control retains the existing automatic save behavior. Failures during a requested save keep the application open. RAM acquisition is independent: its selected destination is unchanged and RAM image bytes are not copied into the automatic triage ZIP. RAM acquisition metadata/path/hash are recorded as a reference when available.

Filename: `<case-id>-<case-name>-<UTC-date_hour-minute-second-microsecond>-.zip`. Spaces and unsafe filename characters in the ID/name are replaced with underscores; the original case fields are retained in the manifest and PDF. Subsecond precision reduces collisions. Existing files are never overwritten. A missing/unwritable directory produces a visible diagnostic and leaves findings available for manual export. A symlink at the cases directory is rejected. `cases/` is excluded from source scanning and version control to prevent collecting previous exports or committing evidence.

## Layout

```
<case-id>-<case-name>-<timestamp>-.zip
  evidence/volume-001/<original-filesystem-path>/...
  evidence/volume-002/<original-filesystem-path>/...
  terra/
    live/                 generated live-state snapshots
    memory/               RAM evidence, when included in a manual export
    analysis/             derived JSONL/CSV and parser metadata
    reports/<case-name>-<date>-Report.pdf
    reports/<case-name>-<date>-Report.html
    reports/collection-summary.txt and .json
    logs/diagnostics.log and .jsonl
    evidence-versions/    earlier recovered source versions, when present
    manifest.json
    checksums.sha256
    IMPORT.txt
    README.txt
```

This source-tree layout preserves directory relationships even when a selected target is a subfolder. Folders from the same mounted filesystem share a volume directory; distinct mount identities remain separate. The acquisition-time mount snapshot is retained through recovery. The manifest maps each volume directory to its device identity, original mount point, filesystem type, filesystem root and selected folders. If original mount metadata is unavailable, the device is marked unknown and full absolute source paths are retained; a replacement mount is not substituted. Normal Unicode and space-containing filenames are preserved with standard ZIP UTF-8 filename encoding; Windows-unsafe characters/reserved names, trailing dots and case-insensitive collisions are escaped or renamed. The manifest maps every exported path back to its exact original source path and records timestamps, hashes and collection status. Browser databases and acquired companions such as WALs remain beside one another. This is a logical subset, not a full disk image, reconstructed AXIOM case or collection of deleted/unallocated data.

## Documented import workflows

The [Magnet AXIOM Cyber user guide](https://www.magnetforensics.com/docs/axiom-cyber/html/Content/Resources/PDFs/Magnet%20AXIOM%20Cyber%20User%20Guide.pdf), sections **Files and folders**, **Load an image**, and **Supported images and file types**, documents Linux logical file/folder evidence and ZIP archive input. Its logical-acquisition description also preserves original folder structure in a compressed ZIP.

- AXIOM Process portable workflow: extract the ZIP, select **Evidence sources > Computer > Linux > Load evidence > Files and folders**, then add the `evidence/volume-NNN` directories. Select relevant artifact processing options.
- AXIOM archive workflow: the guide lists `.zip` as a supported archive image. Use **Load evidence > Image** and select original evidence directories for processing, avoiding treating reports/derived analysis as additional original evidence.
- [Autopsy logical-file workflow](https://sleuthkit.org/autopsy/docs/user-docs/4.22.0/ds_page.html): extract the ZIP, choose **Add Data Source > Logical Files > Local files and folders**, and add the evidence directories. Autopsy notes that extracted-file timestamps can reflect copying; TERRA's manifest records the original timestamps for reference.

Import instructions are embedded in every ZIP as `terra/IMPORT.txt`. Compatibility here means a standard ZIP with intact original logical files and a documented import route. Native ingestion was not exercised in proprietary AXIOM in this development environment. Artifact decoding still depends on the installed analysis-tool version, enabled parsers, Linux artifact coverage, selected files and available decryption keys. TERRA metadata/CSV are supplemental; neither AXIOM nor Autopsy is assumed to understand TERRA's custom manifest automatically.

## Stop/navigation correction

Previously an automatic stopped-scan export made Back/Next handlers return while an export worker was running. That save could also re-copy a large, already acquired RAM image, giving the appearance of a freeze. File triage Stop now retains findings in RAM and offers Resume, Back and Next, without any automatic export. File triage exports exclude memory images, show streaming export/verification/hash progress, and use the examiner-selected destination. Next opens the existing export page for optional saving of stopped results, or for saving completed case results with the cases-folder default. Back returns to the previous stage; new acquisition is held until the save finishes to preserve session state. Normal manual-export protections remain unchanged. Closing during automatic saving waits for completion. The Finish button has its own explicit discard confirmation and does not trigger case autosaving after the examiner confirms finishing without export.

Validation covers complete/stopped cases, separate RAM references, filename handling, original paths and companion bytes, UTF-8 filenames, reports/checksums, active-save Back/Next navigation, destination failure and output-directory exclusion. Existing export, RAM and navigation suites also pass.

Changed files: `controllers/case_controller.py` (new), `export_controller.py`, `scan_controller.py`, `interface/main_window.py`, `interface/pages/export.py`, `reporting/pdf_report.py`, `.gitignore`, and `tests/test_case_exports.py` (new). RAM collectors are unchanged for this update.

## Export format version 2: timestamps and layout

ZIP original-file entries now include UTC Extended Timestamp (0x5455) modification time (whole seconds where representable) and NTFS (0x000A) modification/access/birth times at 100-nanosecond precision. Unknown NTFS times use the zero/unset sentinel. POSIX ctime is metadata-change time, not creation time: it remains exclusively in the manifest and is never placed in a ZIP creation-time field. Exact acquired nanoseconds remain in the manifest. Legacy DOS dates use UTC and have two-second precision and a 1980–2107 range; out-of-range times remain in extra fields/the manifest. Regular-file collection and verified parser companion acquisition now retain access time before reading. Extraction tools and AXIOM may interpret timestamp extensions differently; actual AXIOM ingestion still requires testing.

SQLite sidecar basenames share portable collision renames with their parent database, regardless of collection order. Only already collected, verified originals are exported; export does not collect new files or claim missing companions. Generated material is consolidated under `terra/`, including historical recovered versions. Existing session files remain loadable; sessions without mount provenance use explicitly unknown volume mappings.

Timestamp references: [PKWARE APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), [Info-ZIP extra-field specification](https://github.com/madler/unzip/blob/master/proginfo/extra.fld).

Files changed for format version 2: `controllers/export_controller.py`, `controllers/scan_controller.py`, `artifacts/file_collector.py`, `artifacts/parser_support.py`, new `artifacts/volume_metadata.py`, new `reporting/zip_metadata.py`, `reporting/structured_export.py`, `reporting/pdf_report.py`, `storage/recovery.py`, this documentation, and affected export/recovery/parallel comparison tests (including new `tests/test_volume_export_layout.py`). No GUI workflow changes.

Both report formats share the same case information, findings, hashes, parser summary, collection coverage and limitations. The HTML report is self-contained UTF-8 with embedded styles, no scripts or external resources, and escaped evidence strings. Its ZIP path is recorded as `html_report_path` in `terra/manifest.json`; the existing `report_path` continues to identify the PDF. Both reports are covered by `terra/checksums.sha256`.
