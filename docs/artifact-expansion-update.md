# Additional offline artifact decoding

Protected artifacts are still analyzed automatically without GUI password fields.
Private integration/test key inputs remain supported. Empty passwords can be tried;
unknown passwords are never guessed. Original evidence remains intact when a
format is locked or partially interpreted.

## Added coverage

- **Firefox key3.db:** bounded Berkeley DB 1.85 records, password verification and
  NSS key decoding for logins.json when key4.db is absent. A corrupt/present key4
  is not bypassed. Native NSS DBM fixtures verify empty/known passwords. Unsupported
  overflow layouts and obsolete signons.sqlite schemas remain explicit limitations.
- **GNOME keyrings:** AES128-CBC/iterated-SHA256 binary format with MD5 consistency
  checks, item secrets/attributes/times; textual format preserves secret spaces.
  The upstream native encrypted test fixture was independently checked.
- **Classic KWallet:** iterated-SHA1 or PBKDF2-SHA512, Blowfish ECB/CBC, SHA1 consistency
  checks and QDataStream password/stream/map entries. Modern selected .salt companions
  are required. Three synthetic native KDE interoperability fixtures are bundled.
  GPG wallets remain locked.
- **SafeStorage discovery:** exact same-user/application GNOME items and classic
  Chrome/Chromium KWallet folder/key associations. Conflicts remain locked. Discovery
  rejects directory symlinks/out-of-target companions; provenance records hashes and
  locators. No host keyring service is contacted.
- **Signal local attachments:** documented version-2 IV/AES256-CBC/HMAC-SHA256 format,
  authenticated padding and declared-size trimming; legacy plaintext local files.
  Only known message fields and selected attachments.noindex paths are read. Unknown
  layers, missing files, traversal paths and failed integrity remain unavailable.
- **PST/OST attachments:** bounded libpff reads, filename/MIME/properties and SHA256.
  Signal/PFF extraction each uses a 32 MiB aggregate derived-payload budget per
  database/store. Unavailable/oversized attachments remain in original raw evidence.
  Nested embedded messages and deleted-item recovery remain unsupported.
- **IndexedDB manifest observations:** CRC32C-verified VersionEdit replay, table
  membership and recovery logs. Findings identify latest acquired puts/deletes,
  superseded records and inactive files. Companion records retain their actual source
  paths; raw files are acquired once. Inputs are checked for changes before publishing.
  Missing, unknown, oversized or changing sets stay unverified physical evidence.
  This is not an atomic running-browser/memtable view. External blob candidates still
  do not prove historical version correspondence. Unknown serialized types stay partial.

GNOME MD5 and KWallet SHA1 are format consistency checks, not modern cryptographic
authentication. Signal's HMAC is verified before accepting attachment plaintext.
No examined executable, browser, cloud service or host keyring API is invoked.

## Export and checks

Derived attachments export to
`analysis/artifact-NNNNNN/attachments/NNNNNN-name`, with checksums and JSONL/CSV
archive-path references. Original names cannot escape their ZIP folder. Original
RAM finding rows and raw sources remain unchanged. No evidence write occurs until
the examiner chooses export.

Tests cover native NSS/KDE formats, GNOME corruption, scoped discovery, authenticated
Signal fixtures/parser integration, bounded PFF reads, portable ZIP/checksum export,
manifest history/tombstones, unknown tags, missing files and scan integration.
A public OST sample still parses 50 records through the installed native library;
that sample has no attachments, so attachment extraction also uses controlled API
fixtures. Additional real PST/OST attachment/version fixtures remain useful.

## Changed files

- GUI: `interface/widgets/file_details.py` hides Full Screen for pictures.
- Scan: `controllers/scan_controller.py`, `scan_scheduler.py`,
  `storage/memory_store.py`, `analyzers/matching/hash_matcher.py`.
- Decoders: `artifacts/browsers/legacy_credentials.py`, `indexeddb.py`,
  `artifacts/keyrings.py`, `leveldb_state.py`, `communication/attachments.py`,
  `email/pff.py`, `parsing.py`, `companions.py`, `protected_keys.py`, `encrypted.py`,
  `linux_catalog.json`, `protected_key_index.json`.
- Export: `reporting/structured_export.py`.
- Validation: `tests/test_parallel_scan.py`, `test_artifact_expansion.py`,
  `test_image_review.py`, `test_extended_formats.py`, `test_triage_enrichment.py`,
  `nss_fixture.py`, `benchmark_scan.py`, and KWallet fixtures/generator/wrapper.
- Documentation: README, this file, protected-artifacts, linux-format-expansion,
  scan-performance-plan.

Primary references:

- [NSS legacy DB](https://github.com/nss-dev/nss/tree/master/lib/softoken/legacydb)
- [GNOME binary format](https://github.com/GNOME/gnome-keyring/blob/main/pkcs11/secret-store/gkm-secret-binary.c)
- [KWallet v6.18 backend](https://github.com/KDE/kwallet/tree/v6.18.0/src/runtime/kwalletbackend)
- [Signal attachment crypto](https://github.com/signalapp/Signal-Desktop/blob/main/ts/AttachmentCrypto.node.ts)
- [libpff Python API](https://github.com/libyal/libpff/wiki/Python-development)
- [LevelDB VersionEdit](https://github.com/google/leveldb/blob/main/db/version_edit.cc)
- [LevelDB recovery](https://github.com/google/leveldb/blob/main/db/db_impl.cc)
