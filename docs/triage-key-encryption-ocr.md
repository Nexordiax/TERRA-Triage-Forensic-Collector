# Automatic key discovery, encrypted containers and OCR lists

## Target and configuration changes

**Analyze all mounted disk volumes** is the single whole-system option. It also
enables existing live-host collection. Choosing individual folders/volumes disables
that live-host collection; RAM acquisition remains independent. There is no second
live-state checkbox.

Protected-artifact decoding runs automatically with supported selected companions.
The GUI no longer prompts for decoding or secrets. See
[protected-artifacts.md](protected-artifacts.md) and the
[key support index](../artifacts/protected_key_index.json) for exact supported paths,
fields/offsets and limitations. Adding an index entry alone does not implement a
new decoder: the corresponding parser/resolver must support and validate its format.
There is no universal password extraction or decryption.

## Encrypted Containers

During file triage, public signatures are recognized regardless of filename and
file-byte cache retention. Results have a collapsed **Encrypted Containers** parent
and collapsed format/cipher subcategories. Files within a subgroup are ordered by
descending sampled entropy. Each file retains its original hashes and bytes/source
reference. The tree status shows entropy, and details/export preserve measurements
and detection limitations.

| Identification | Reported cipher information | Limits |
| --- | --- | --- |
| LUKS1 | Public cipher and mode fields at offsets 8 and 40 | Header signature/version recognition; complete keyslot/header validation and volume unlocking are not performed. |
| LUKS2 | `segments.*.encryption` from JSON starting at offset 4096 when available | Header area bounded to 4 MiB; public metadata only, checksum not validated. Detached headers can be identified. |
| BitLocker | Format identified from `-FVE-FS-` boot signature, sector size and boot marker | Cipher remains unknown: the boot sector alone does not establish CBC/XTS or key size. Distant FVE metadata is not parsed. |
| KeePass KDBX 3/4 | Known AES-256-CBC, ChaCha20 and Twofish outer cipher UUIDs when present | Public fields only; no password database unlock or full header integrity validation. |
| GNOME binary keyring | Binary encrypted keyring format signature | No algorithm guessed from entropy, and no keyring unlock. |
| Encrypted ZIP | First local member encrypted flag | Indicator only; whole-archive validation and cipher identification are not performed. Mixed archives whose first member is unencrypted are outside this probe. |
| High-entropy candidates (unconfirmed) | None | Plausible container/image extensions or extensionless files, at least 32 KiB sampled, entropy at least 7.8 bits/byte. Encryption, cipher and VeraCrypt/TrueCrypt identity are not established. |

Entropy is Shannon entropy of the first and final 32 KiB of the existing acquisition
stream (at most 64 KiB, without overlap). No second file read is needed. Sample ranges
are exported. Headers/padding/compressed data can affect measurements, and sampling
can miss encrypted regions. High entropy is a review cue, not proof of encryption;
ordinary picture/archive extensions are not promoted by entropy alone.

Selected mounted volumes are also checked using kernel mountinfo and sysfs
device-mapper UUIDs, including stacked LVM/dm devices. A readable `CRYPT-LUKS1/2`
UUID identifies the format; generic `CRYPT-` UUIDs are labelled dm-crypt. Mounted
dislocker filesystems are labelled BitLocker. These findings are RAM-resident
metadata snapshots grouped by format. They do not claim to acquire encrypted
volume bytes, and the cipher is unknown when kernel metadata does not expose it.
Folder-only selections do not enumerate their containing host volume. No raw block
devices are read, volumes mounted/unlocked or key-bearing dm tables requested.

Collection mode is respected: mounted-volume snapshots appear in full collection;
file container findings in matches-only collection still require a hash, keyword
or OCR-list match.

## Separate OCR lists

In **Triage Configuration**, import one or more UTF-8 `.txt` files under **OCR match
lists**, with one word/phrase per line. Blank/comment lines and duplicate entries are
handled like keyword lists. Import enables OCR; imported lists also force OCR at
Start, even if its checkbox was subsequently cleared. Language-code validation and
all existing OCR bounds still apply. Lists are reread into RAM at Start and excluded
from filesystem triage.

OCR transcripts from pictures and OCR-processed PDF pages are compared with these
entries using the existing case-insensitive substring matcher. Matches produce a
separate collapsed **OCR Matches** category, retain page/frame locators and matched
entries in structured records, and qualify for matches-only collection even with
ordinary content-keyword searching disabled. OCR lists do not search file names,
raw file bytes or PDF text-layer-only rows. Enable **OCR every PDF page** to search
pages that already contain readable text. Ordinary content keywords can continue
to match extracted/OCR text independently.

No OCR transcriptions or key material are uploaded, and processing preserves source
bytes/hashes. Original key-bearing companion evidence and decrypted findings may
be included in an explicitly requested ZIP export.

## Validation and changed files

Independent fixtures cover native OCR with standard matching disabled, separate
OCR category and reference exclusion, list snapshot/validation, automatic Chromium
v11 and Signal SQLCipher decoding with hashed key provenance, cross-user/application
scope, symlink rejection, conflicting/encrypted keyrings, significant secret spaces,
LUKS2 JSON across acquisition chunks without caching, BitLocker/KDBX signatures,
bounded entropy sampling, stacked mounted-volume metadata, collapsed subcategories
and descending entropy order. Existing decoder, scan, GUI and export regressions
remain included in the full suite.

Changed implementation files:

- `interface/pages/targets.py`, `interface/pages/configuration.py`, `interface/pages/analysis.py`
- `interface/widgets/content_options.py`, `interface/main_window.py`
- `controllers/configuration_controller.py`, `controllers/scan_controller.py`
- `artifacts/parsing.py`, `artifacts/protected_keys.py`, `artifacts/protected_key_index.json`
- `artifacts/encrypted.py`, `artifacts/encrypted_volumes.py`
- `tests/test_triage_enrichment.py`, `tests/test_protected_formats.py`, `tests/test_live_collectors.py`
- `README.md`, this document, `docs/protected-artifacts.md`, `docs/document-image-analysis.md`

## Primary references

- [GNOME textual keyring implementation](https://github.com/GNOME/gnome-keyring/blob/main/pkcs11/secret-store/gkm-secret-textual.c)
- [cryptsetup LUKS formats](https://gitlab.com/cryptsetup/cryptsetup/-/tree/main/docs)
- [libbde BitLocker format specification](https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20%28BDE%29%20format.asciidoc)
- [KeePass KDBX specification](https://keepass.info/help/kb/kdbx.html)
- [KeePassXC cipher identifiers](https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KeePass2.cpp)
- [PKWARE ZIP specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Linux dm-crypt documentation](https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html)
