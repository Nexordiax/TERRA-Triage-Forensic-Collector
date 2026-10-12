# Offline protected artifact decoding

Implemented and validated on Linux, 2026-10-10. Select the relevant profile or
application directory as a target so companion key databases and blobs are in
scope. Protected-artifact decoding runs automatically during file triage;
the configuration page has no decryption checkbox or password fields.
The data-only [key support index](../artifacts/protected_key_index.json) records
supported companion paths, fields/offsets and decoder references. Companion
discovery is independent of traversal order and remains within selected targets.

| Artifact | Implemented | Limits |
| --- | --- | --- |
| Firefox `logins.json` / `key4.db` | Primary-password verification, NSS legacy 3DES/PBES2 AES key unwrapping, 3DES/AES login values; SHA-1 and newer SHA-384 global-salt password hashing; verified SQLite/WAL key snapshots | Blank password tries an unprotected profile. Wrong/missing keys produce locked metadata. Legacy key3.db fallback is supported when key4.db is absent. Unsupported BDB overflow layouts, OIDs and OS-bound keys stay locked. CBC login records have no individual authentication; UTF-8 and padding are validated. |
| Linux Chromium-family logins and cookies | `v10` basic-store CBC; `v11` CBC with automatically discovered same-user/application SafeStorage item; cookie schema version 24+ SHA-256 host binding | Supported GNOME textual/binary and classic Chrome/Chromium KWallet items. Binary stores need an empty or usable known password; modern KWallet needs its selected salt companion. GPG/DPAPI/macOS/v20 stay locked. No host keyring calls. CBC alone does not authenticate a password record. |
| Signal Desktop | Plaintext or authenticated SQLCipher 3/4 default raw-key profiles; unchanged database and committed encrypted WAL snapshots; message body/conversation columns plus JSON fields; authenticated local version-2 attachments and legacy plaintext attachments | Selected `config.json` plaintext key or Linux v10/v11 wrapped key. v11 uses a supported same-user Signal SafeStorage item. Custom SQLCipher profiles, other OS protection, unknown attachment encryption layers, deleted-message recovery and messages absent from the local store are unsupported. |
| Telegram Desktop | TDF$ checksum validation, old-MTProto local AES-IGE block integrity checks and selected `key_data` empty-passcode wraps; recognized tagged local draft schemas | Drafts are labelled `chat_draft`, never sent/received messages. Unknown decrypted containers export plaintext hex as partial records. Protected passcode wraps stay locked without usable keys. Legacy account map key derivation and complete cloud chat history are unsupported. No Telegram connection or session conversion occurs. |
| RPM Berkeley DB | Hash/B-tree inventories, overflow pages and existing RPM header interpretation from acquired bytes | No BDB environment, locks or package manager. Cyclic/out-of-range pointers fail. Encrypted/checksummed, unsupported version/layout and transaction-log reconstruction are unsupported. |
| Chromium/Electron IndexedDB | Physical LevelDB key prefixes, metadata, user keys, Blink/V8 values; objects, arrays, sparse arrays, cycles/references, Map/Set object keys, dates, BigInt, regular expressions, buffers/views and supported Blink host objects; bounded Snappy; verified external blob candidates | Unsupported versions/tags remain explicit partial records. Physical observations can be superseded. External blob candidates identify their metadata source/sequence and blob path; they do not prove historical version correspondence. CURRENT/MANIFEST replay identifies latest acquired puts/deletes and superseded records when companions validate. Missing/changing sets remain unverified; no atomic live-process view or JavaScript/Wasm execution. |
| Firefox IndexedDB | Gecko keys, inline Snappy/framed-Snappy structured clones, external clone file indices/flags from SQLite and selected `.files` companions | Framed CRC32C validated. Unsupported Gecko tags/object forms remain partial. No browser execution or access outside selected targets. |
| PST/OST | Existing libpff folder/MAPI/message parser is installed and available in `.venv` | Bounded attachment extraction and checksummed ZIP files are implemented. Nested embedded messages and deleted-item recovery remain unsupported; optional reader availability is reported explicitly. |

Universal decryption and decoding are not claimed. Missing secrets, inaccessible
companions and unsupported serialization formats remain visible as locked,
partial or failed results, with original evidence retained.

See [decoder expansion details](artifact-expansion-update.md) for new modules, independent validation and precise limits.

## Installation and running

The dependencies are installed in this project's `.venv`. Run:

```bash
.venv/bin/python main.py
```

For a new tool installation:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-forensics.txt
```

Google's pinned `python-snappy==0.6.1` needs a C/C++ compiler, Python development
headers and `libsnappy-dev` when built from source on Linux. Prepare these on the
acquisition tool beforehand. This development environment used headers downloaded
and extracted under `/tmp`; no system packages were installed. TERRA does not
download or install parsers during evidence collection.

## Evidence and secret handling

Companion reads remain within selected targets and reject symlink traversal.
Source/WAL snapshots retain their original SHA-256 and are included as raw evidence.
Decryption uses analysis copies in RAM; SQLite never opens the examined databases.
Page HMACs and encrypted WAL checksums are checked before Signal messages are
interpreted. Unsupported or incorrect keys do not generate decrypted findings.

Automatically discovered secrets stay in parser-local memory; their values are not
added to configuration, diagnostic messages or key-discovery provenance. Key-file
path, SHA-256, rule and section/field locator are recorded instead. The decoder API
retains its private supplied-key compatibility for independent tests/integration;
these fields are excluded recursively from export context and cleared after a scan.
Python does not guarantee secure
erasure of all copies from process memory. Original key-bearing evidence and
decrypted findings are intentionally exported; they are sensitive evidence.
No evidence is uploaded, no privilege is silently elevated, no examined program
is run, and no host keyring or remote account is contacted.

GNOME textual discovery checks `.local/share/keyrings/*.keyring` and legacy
`.gnome2/keyrings/*.keyring` under the same evidence user's home inferred from a
known `.config` application path. Exact Safe Storage label and, when present,
application attribute must agree. Conflicting secrets are not tried. Each file is
bounded to 2 MiB and each directory to 64 keyrings. Firefox primary passwords and
encrypted GNOME/KWallet secrets are not guessed or brute-forced. A password in an
unrelated file is never treated as a valid key for another artifact.

Decompression uses a 64 MiB object/block bound; V8/Gecko decoding also bounds
nesting and node counts. Sparse V8 arrays preserve length and properties without
allocating their entire logical length. These bounds do not restrict raw file
collection. They do not impose a total parsed-record memory budget.

## Validation and references

`tests/test_protected_formats.py` verifies local scope, wrong keys, corruption,
cancellation, source preservation, decoded fields, GUI inputs and ZIP provenance
with secret exclusion. Native NSS generates password-protected/unprotected
profiles; native SQLCipher generates v3/v4 databases and a live WAL; OpenSSL's
native IGE implementation generates Telegram blocks. Independent Berkeley DB
and V8 fixtures and their generators are in `tests/fixtures/`.

Additional development validation recovered Dissect's 239 expected RPM packages
and the three messages/46 folders in the public `freepst` OST sample. Public
mail/RPM fixtures stay in `/tmp`, outside the repository. These observations
do not establish every version or corruption case.

Install `requirements-forensics-test.txt` for native SQLCipher fixture generation.
NSS/OpenSSL fixture tests require their system shared libraries; unavailable
optional generators/decoders are explicitly skipped. Run the complete suite with:

```bash
QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORMTHEME= QT_STYLE_OVERRIDE=Fusion \
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -q
```

Primary implementations consulted:

- [NSS password/key handling](https://github.com/nss-dev/nss/blob/master/lib/softoken/sftkpwd.c), [firepwd's offline NSS formats](https://github.com/lclevy/firepwd), [Firefox Decrypt](https://github.com/unode/firefox_decrypt).
- [Chromium Linux OSCrypt](https://chromium.googlesource.com/chromium/src/+/ff58622d23a1de5/components/os_crypt/os_crypt_linux.cc), [Signal database keying](https://github.com/signalapp/Signal-Desktop/blob/main/ts/sql/Server.node.ts), [SQLCipher design](https://www.zetetic.net/sqlcipher/design/).
- [Telegram local encryption](https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/storage/details/storage_file_utilities.cpp), [local AES key schedule](https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/mtproto/mtproto_auth_key.cpp), [draft schemas](https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/storage/storage_account.cpp).
- [Dissect BDB reader](https://github.com/fox-it/dissect.database/blob/main/dissect/database/bsd/db.py), [RPM inventory tests](https://github.com/fox-it/dissect.database/blob/main/tests/bsd/test_rpm.py).
- [Google forensic IndexedDB decoder](https://github.com/google/dfindexeddb), [CCL Chromium reader](https://github.com/cclgroupltd/ccl_chromium_reader), [Mozilla IndexedDB overflow-clone storage](https://github.com/mozilla/gecko-dev/blob/master/dom/indexedDB/ActorsParent.cpp).
- [libpff Python API](https://github.com/libyal/libpff/wiki/Python-development), [public OST sample expectations](https://github.com/hrbrmstr/freepst).

## Files changed for this update

- GUI: `interface/pages/configuration.py`, `interface/widgets/decryption_options.py`, `interface/main_window.py`.
- Controllers: `controllers/configuration_controller.py`, `controllers/scan_controller.py`, `controllers/export_controller.py`.
- Shared parser support: `artifacts/decryption.py`, `artifacts/companions.py`, `artifacts/parsing.py`, `artifacts/sqlite_snapshot.py`, `artifacts/linux_catalog.json`.
- Browser adapters: `artifacts/browsers/parser.py`, `credentials.py`, `indexeddb.py`, `v8_objects.py`.
- Chat adapters: `artifacts/communication/native_metadata.py`, `protected.py`, `sqlcipher.py`, `telegram_crypto.py`.
- RPM: `artifacts/installed_apps/rpm.py`.
- Dependencies/documentation: `requirements-forensics.txt`, `requirements-forensics-test.txt`, `.gitignore`, `README.md`, `docs/linux-artifacts.md`, `docs/linux-format-expansion.md`, this document.
- Tests: `tests/test_extended_formats.py`, `tests/test_protected_formats.py`, `tests/nss_fixture.py`, synthetic fixtures/generators in `tests/fixtures/`.
