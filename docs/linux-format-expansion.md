# Additional Linux artifact interpretation

Research and implementation: 2026-10-10. Follow-up protected-format coverage,
validation and exact limits are documented in [offline protected decoding](protected-artifacts.md). This extends point 2 (artifact
interpretation). It does not change RAM acquisition, the GUI theme, privilege
selection, or live-host scope. Windows/macOS collectors remain separate work.

## Implemented coverage

| Format | Findings | Exact limits |
| --- | --- | --- |
| RPM SQLite `rpmdb.sqlite` | Package names, versions/releases, architecture, build/install times, selected header fields, package IDs | Reads the `Packages` table from the existing verified RAM/WAL snapshot; no librpm invocation. BDB hash/B-tree inventories now have a separate offline reader. |
| RPM NDB `Packages.db` | Indexed package inventory, database/blob generations, RPM header fields | Version 0 only. Checks slot bounds/overlap, blob identity/length, zero padding and Adler32. Unreferenced/deleted blobs are not carved. |
| Traditional lastlog | Latest recorded login, UID, terminal, host, UTC time, original offset | Linux little-endian 292-byte layout only. UID is the sparse-record index; never resolve it against examiner-host accounts. Other ABIs are not guessed. Not complete login history. |
| lastlog2 | Username, latest login time, terminal, remote host, PAM service | util-linux `Lastlog2` SQLite schema, with verified committed WAL replay in RAM. |
| Chromium/Electron LevelDB logs and SSTs | Physical keys/values, sequence numbers, puts/deletes, original binary hex, decoded strings; Chromium Local Storage origins, metadata times and script keys/values; Session Storage map fields | CRC32C checked; fragmented logs, write batches, prefix/restart blocks, uncompressed and Snappy SST blocks supported. Session map IDs are not joined to a presumed current origin. No CURRENT/MANIFEST reconciliation: records may be old, superseded or no longer active. IndexedDB/V8/Blink/Gecko objects now have offline decoding; supported chat formats are documented in the follow-up. Unknown compression and damaged/truncated sources fail explicitly and retain raw evidence. |
| Firefox session JSON/Mozilla LZ4 | Open and closed tab history entries, URLs/titles, selected entry, tab last-access time | Last access belongs to the tab, not a proven visit time for each history entry. No automatic browser launch or session restoration. |
| Firefox bookmark backups | URLs/titles, GUIDs, creation/modification times | JSON and Mozilla LZ4 snapshots; bookmarks do not prove visits. |
| Firefox permissions | Origins, permission types/values, modification/expiry metadata | Configuration only; no inference that permission was exercised. |
| Snap state | Package names, active/current revision flags, revision sequence, channel | Persisted inventory, not proof of execution. Assertions remain raw. |
| Flatpak metadata | Application/runtime identifiers, deployment metadata and permission sections | Presence of a deployment is not proof it is the current active revision or running. |
| PST/OST | Folder hierarchy, MAPI item properties, message class, email subject/sender/headers/plain and HTML bodies, available times and attachment counts | Optional `pypff/libpff` reader opens only `BytesIO` snapshots. Other MAPI items are not labelled email. Without the library, status is **partial**, with header metadata only. Attachments can be extracted within a 32 MiB aggregate derived-byte budget and exported separately; raw stores remain intact. Nested embedded messages and deleted items are not recovered. HTML remains text and is never executed/rendered as active content. |
| Telegram Desktop | TDF$ wrapper/version, local AES-IGE blocks and recognized local drafts | Key_data or supplied local key; exact limits in the follow-up. Arbitrary inner schemas remain partial, and drafts are not sent messages. |
| Signal configuration | Presence of plaintext/protected key fields, available safeStorage backend metadata | **Partial**, key values are not exposed in parsed records and supported wrapped keys can be decoded by the Signal collector with a locally supplied secret. |
| Signal messages | Message JSON/body/conversation/source fields | Plaintext or authenticated SQLCipher v3/v4 RAM snapshots with available selected-evidence/supplied keys; unavailable keys remain locked. No host keyring access. |

The catalog has 113 definitions, 75 with parser adapters and 38 raw-only. Adapter
count does not mean 75 complete application decoders: optional/partial support is
explicit in the catalog and results.

## Evidence handling and export

All new adapters use acquired bytes or the existing verified SQLite RAM snapshot.
They do not open a live LevelDB environment, create database locks, invoke package
managers, run examined applications, unlock host keyrings, log into accounts, or
send evidence over the network. Offline credentials/chat decoding uses available
selected-evidence keys or locally supplied secrets; missing keys remain explicit.

Cancelled parsing propagates cancellation. Parsing failure discards derived
records for that source, retains the acquired original and logs a diagnostic.
Successful partial records are labelled **partial** in the preview and metadata,
counted separately in the scan summary, and exported as JSONL/CSV with
`parser_status` provenance. The PDF and manifest retain the status/limitations.
Original raw bytes and source SHA-256 remain available in the ZIP.

There is a **64 MiB decoded-block/snapshot safety limit** for LevelDB Snappy blocks,
fragmented log records and Mozilla LZ4 snapshots to reject implausibly large
compressed expansions. This is not the file acquisition/cache limit: larger raw
source files are still collected and exported by the existing workflow. The total
parsed-record memory footprint is not capped by this block limit.

Install `requirements-forensics.txt` in the application environment for PST/OST
message parsing. The core requirements and application remain usable without it;
TERRA does not install anything automatically. `libpff-python==20260926` was
validated with Python 3.13 on Linux x86-64 using an isolated directory under `/tmp`,
without changing the system installation.

## Research references

Primary implementations determine field meanings and byte layouts. Additional
forensic projects and papers were used to cross-check interpretation, not to
execute their collectors or copy source code into TERRA.

- [RPM SQLite backend](https://github.com/rpm-software-management/rpm/blob/master/lib/backend/sqlite.cc), [NDB database implementation](https://github.com/rpm-software-management/rpm/blob/master/lib/backend/ndb/rpmpkg.c), [header encoding](https://github.com/rpm-software-management/rpm/blob/master/lib/header.cc), [tag IDs](https://github.com/rpm-software-management/rpm/blob/master/include/rpm/rpmtag.h).
- [Linux PAM lastlog](https://github.com/linux-pam/linux-pam/blob/master/modules/pam_lastlog/pam_lastlog.c), [util-linux lastlog2 schema](https://github.com/util-linux/util-linux/blob/master/liblastlog2/src/lastlog2.c), [Dissect lastlog adapters](https://github.com/fox-it/dissect.target/blob/main/dissect/target/plugins/os/unix/log/lastlog.py).
- [LevelDB logs](https://github.com/google/leveldb/blob/main/doc/log_format.md), [tables](https://github.com/google/leveldb/blob/main/doc/table_format.md), [write batches](https://github.com/google/leveldb/blob/main/db/write_batch.cc), [restart-block reader](https://github.com/google/leveldb/blob/main/table/block.cc), [CRC masking](https://github.com/google/leveldb/blob/main/util/crc32c.h), [Snappy specification](https://github.com/google/snappy/blob/main/format_description.txt).
- [Chromium Local Storage implementation](https://github.com/chromium/chromium/blob/main/components/services/storage/dom_storage/local_storage_impl.cc), [CCL forensic reader](https://github.com/cclgroupltd/ccl_chromium_reader), [CCL Chromium storage technical paper](https://assets-global.website-files.com/5f02f2ca454c471870e42fe3/60ed4b9585dae9c79fbe331d_CCL_Tech_paper_Chromium_Storage.pdf).
- [Mozilla session store](https://github.com/mozilla/gecko-dev/blob/master/browser/components/sessionstore/SessionStore.sys.mjs), [bookmark JSON snapshots](https://github.com/mozilla/gecko-dev/blob/master/toolkit/components/places/BookmarkJSONUtils.sys.mjs), [LZ4 block format](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md). Foxton's [session-restore research](https://www.foxtonforensics.com/blog/post/analysing-firefox-session-restore-data-mozlz4-jsonlz4) was cross-checked against the native implementation.
- [Snap state](https://github.com/snapcore/snapd/blob/master/overlord/snapstate/snapstate.go), [Snap revision serialization](https://github.com/snapcore/snapd/blob/master/overlord/snapstate/sequence/sequence.go), [Flatpak metadata](https://github.com/flatpak/flatpak/blob/main/doc/flatpak-metadata.xml).
- [libpff format specification](https://github.com/libyal/libpff/blob/main/documentation/Personal%20Folder%20File%20(PFF)%20format.asciidoc), [Python API](https://github.com/libyal/libpff/wiki/Python-development), native [file](https://github.com/libyal/libpff/blob/main/pypff/pypff_file.c), [folder](https://github.com/libyal/libpff/blob/main/pypff/pypff_folder.c), [message](https://github.com/libyal/libpff/blob/main/pypff/pypff_message.c) and [item](https://github.com/libyal/libpff/blob/main/pypff/pypff_item.c) bindings.
- [Telegram storage wrapper](https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/storage/details/storage_file_utilities.cpp), [Signal database schema](https://github.com/signalapp/Signal-Desktop/blob/main/DATABASE_SCHEMA.md). Telegram encryption research and [OpenTele's storage handling](https://github.com/thedemons/opentele/blob/main/src/td/tdesktop.py) were reviewed; no account/session conversion or cloud access is used.
- Browser credential research: [NSS password handling](https://github.com/nss-dev/nss/blob/master/lib/softoken/sftkpwd.c), [Firefox Decrypt](https://github.com/unode/firefox_decrypt), [firepwd](https://github.com/lclevy/firepwd). Those tools are not invoked. The follow-up implements verified offline key4 snapshots and primary-password inputs; host keyrings are not unlocked.

## Verification

`tests/test_extended_formats.py` covers valid and malformed layouts, sparse UID
indexing, RPM blob bounds/checksums/overlap, LevelDB CRC32C known vectors,
fragmentation, tombstones, SST/Snappy blocks, Firefox LZ4 and schema interpretation,
partial statuses, cancellation, offline path priority, retained raw evidence and
source-linked JSONL/CSV export. The full existing test suite is also run.

Independent installed Snappy and LZ4 implementations verified five varied payloads,
including repeated and binary data. Real public [freepst fixtures](https://github.com/hrbrmstr/freepst/tree/master/inst/extdata)
were downloaded only into `/tmp`: the PST yielded 24 folders and four non-email
MAPI items with retained properties; the OST yielded 46 folders and three emails.
Fixture messages/properties were not printed, uploaded or added to the repository.
These checks do not establish support for every PST/OST variant or damaged store.

## Remaining work within point 2

- Legacy Firefox key3 databases and unsupported OS/keyring protection; supported offline credential paths are implemented.
- Other encrypted chat schemas, unsupported Signal attachment layers, newer protected Telegram passcode-wrap KDFs and complete cloud history; supported local message/draft paths are implemented.
- Encrypted/checksummed RPM BDB variants and non-Linux-LE-292 lastlog layouts.
- Unsupported IndexedDB tags/versions and verified CURRENT/MANIFEST live-state reconstruction; supported V8/Blink/Gecko objects now decode offline.
- PST/OST nested embedded-message interpretation and deleted-item recovery; more version/corruption fixtures.
- Other raw-only application caches and formats listed in the catalog.

## Files changed

New parsers: `artifacts/os_activity/lastlog.py`, `artifacts/installed_apps/rpm.py`,
`artifacts/installed_apps/app_state.py`, `artifacts/leveldb.py`,
`artifacts/browsers/sessions.py`, `artifacts/email/pff.py`,
`artifacts/communication/native_metadata.py`.

Integration: `artifacts/parsing.py`, `artifacts/linux_catalog.json`,
`controllers/scan_controller.py`, `reporting/structured_export.py`.

Validation/dependencies/documentation: `tests/test_extended_formats.py`,
`tests/test_structured_artifacts.py` (raw-only fixture now uses an unparsed Signal
attachment), `requirements-forensics.txt`, README and Linux artifact/research docs.
