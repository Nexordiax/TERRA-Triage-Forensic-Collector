# Archive searching, contained-picture review, recovery and export coverage

## Automatic archive support

TERRA searches ZIP (including supported ZipCrypto and AES encryption), TAR/TGZ/TBZ/TXZ, GZIP/BZIP2/XZ, Office ZIP containers, supported RAR4/RAR5 and 7z archives automatically. pyzipper handles encrypted ZIP members. libarchive streams supported RAR/7z members without invoking external filter programs; encrypted 7z falls back to py7zr with a custom RAM-only writer. Encrypted RAR falls back to the bundled, checksum-pinned official UnRAR 7.3.1 library, using test-mode callbacks to collect bytes in RAM. Passwords do not appear in process arguments. Archive members are never extracted into filesystem paths, executed, or uploaded. Links, duplicate member names, corrupt data and unsupported codecs/encryption produce diagnostics.

Outer archives above 64 MiB use a verified inherited read-only descriptor. Member hashes and raw content keywords cover complete member bytes, including members above the previous 32 MiB limit. Bounds remain necessary: at most 2 GiB of expanded work, 10,000 entries and five nested archive levels per container, plus the existing isolated worker's wall-time, CPU and output budgets. Nested/media decoding and preview inputs remain bounded to 32 MiB per member. The encrypted 7z and RAR RAM fallbacks have a 64 MiB total expansion bound. These bounds do not restrict acquiring/exporting the original container or hashing its complete source bytes. The native libarchive library will need to be bundled alongside the pinned Python packages when building a standalone release.

Multipart archives requiring additional volumes and unsupported codecs are not promised to decrypt; the original is retained in full-collection mode and limitations are reported. This is not arbitrary password cracking.

## Automatic credentials

artifacts/archive_credential_index.json lists known plaintext credential carriers and labelled archive-password keys. Verified selected-target carriers (at most 1 MiB) and already decoded browser saved logins supply up to 32 bounded candidates. Values are sent to the worker through standard input, never command-line arguments or diagnostics. Successful member findings include the credential source path, source hash and field/line locator without copying its password into the derived member row. Earlier locked containers get another attempt after the scan discovers credentials. Updates replace an existing finding instead of creating duplicate rows. Existing decryption of other artifacts remains unchanged.

## Picture preview

Contained pictures have child entries below their container in live results. Expand the container and double-click a picture. Alternatively, double-click a preview-enabled row in the container's parsed findings table. A separate worker reopens the cached or verified source, follows an explicit member/page/frame locator, verifies member SHA-256 values and produces a derived PNG in RAM. Pictures in nested archives, Office containers and PDF image objects are supported. Ordinary archive inventory is automatic. Document-image analysis and PDF picture inventory require the unchecked-by-default **Also search images inside documents** option. Office member hashes and their on-demand preview locators remain available without automatically decoding their pictures. Containers with discovered pictures also appear in Pictures, with the pictures listed as child findings. The preview fits the window; a large image may be scaled to a 2400-pixel edge. The original evidence is unchanged and is what the export saves. Closing a preview or TERRA cancels pending decoding before destroying its worker.

## Persistent triage recovery

Before Start, enable **Save scan progress so this triage can be resumed after closing TERRA** and choose a new `.terra-session` destination. The option is off by default, preserving RAM-first operation. Existing files are not overwritten. A destination inside an examined target requires explicit acknowledgement. Session files and SQLite journal companions are excluded from collection.

Progress and retained evidence are committed incrementally to a private SQLite session every 20 completed files or approximately five seconds at a completed-file boundary, and when collection stops/finishes. Long interrupted files are retried; recovery represents the last committed checkpoint, not every in-flight byte. SQLite transactions preserve the last committed state after interruption. Session loading uses a worker, bounded JSON and byte records, an application-format marker, and checksum verification; it does not deserialize executable Python objects. A hot journal may be rolled back inside the explicitly reopened recovery destination after a crash.

On the welcome screen choose **Resume saved triage…**, open the session and click Resume. The prior case context, configuration, findings, cached evidence and diagnostics return. Original targets must be available with the recorded device/root identity. Changed completed files are searched again. Earlier cached bytes remain available as a distinct acquisition; their exports use `evidence-versions/`. If earlier bytes were not cached and the source changed/disappeared, the manifest identifies `original_bytes_unavailable`, preserves the earlier metadata/derived findings, and does not pretend the old file was exported. A session moved into an examined target requires acknowledgement before progress writes resume. No automatic privilege elevation occurs.

Reference hash/keyword/OCR values and image descriptors are saved in the session, so resuming does not depend on reopening the reference-list files. Discovered archive passwords are rebuilt from cached evidence or unchanged verified original credential carriers. RAM image acquisition itself is not resumed by this feature; its existing saved partial/full ZIP behavior remains separate. To retain whole source files that exceed the RAM cache or after reaching its limit, original unchanged sources must remain available for export. The recovery file can contain sensitive evidence and decoded credentials; it remains at the user-selected destination until the user removes it.

## Coverage after export

After successful export the Export page displays a readable collection coverage summary. The same information appears in the PDF, manifest and `reports/collection-summary.txt` / `.json`. It describes targets, scan status, partial collection, examined/completed/hash-checked files, archive coverage, parser states, missing historical bytes, excluded nonregular entries and diagnostic event groups, with example issues and log truncation counts. These are recorded operational facts, not a claim that every possible artifact was searched. Detailed diagnostic logs remain under `logs/`. Counts of warnings/errors describe diagnostic events, not unique inaccessible files; previously resolved warnings remain in the audit trail.

## Files changed

- Archive backend: analyzers/archive_readers.py, analyzers/containers.py, analyzers/content.py, analyzers/content_worker.py, analyzers/embedded.py and analyzers/rar_native.py, with the attributed source, binary, checksum manifest and licence in assets/tools/unrar/.
- Credential discovery: artifacts/archive_credentials.py and artifacts/archive_credential_index.json.
- Collection/recovery: controllers/scan_controller.py, controllers/recovery_controller.py, storage/recovery.py and storage/memory_store.py.
- Existing GUI connections: interface/main_window.py, interface/pages/configuration.py, interface/pages/welcome.py, interface/pages/analysis.py, interface/widgets/recovery_options.py, interface/widgets/embedded_preview.py, interface/widgets/file_details.py and interface/widgets/structured_findings.py.
- Coverage/export: reporting/coverage.py, reporting/pdf_report.py, controllers/export_controller.py and interface/pages/export.py.
- Dependencies/tests: requirements-forensics.txt, tests/test_archive_features.py, tests/test_persistent_recovery.py and attributed upstream RAR fixtures in tests/fixtures/. Related notes in docs/container-search.md and docs/document-image-analysis.md were updated.

## Primary API references

- https://github.com/Changaco/python-libarchive-c — memory/stream readers; no filesystem extractor is used.
- https://py7zr.readthedocs.io/en/latest/advanced.html — WriterFactory/Py7zIO RAM-only output API.
- https://github.com/danifus/pyzipper — AES ZIP support.
- https://pypdfium2-team.github.io/pypdfium2/python_api.html — page-object image decoding and bitmap ownership.
- https://www.sqlite.org/atomiccommit.html — transactional commit and crash recovery.

The bundled UnRAR binary is a Linux x86-64 development build. Its official freeware distribution licence is retained; it is not an OSI open-source licence. The source archive and build command are preserved so it can be rebuilt on the minimum supported Linux release and for each target architecture during packaging. Other architectures retain libarchive RAR reading and report unavailable encrypted-RAR fallback explicitly.
