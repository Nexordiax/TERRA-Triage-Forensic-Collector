# Linux application artifact expansion

Research date: 2026-10-10. These definitions are Linux collection rules, including mounted evidence roots. They extend the existing live categories, RAM-first evidence store, hash/keyword matches, diagnostics and structured ZIP exports without changing the GUI theme or navigation.

| Category | Coverage | Structured interpretation |
| --- | --- | --- |
| Cloud Storage | Dropbox, Nextcloud/ownCloud, abraunegg OneDrive, rclone, Syncthing, MEGAsync, Seafile | Dropbox account/folder metadata; INI settings and remote definitions; OneDrive item inventory; Nextcloud/ownCloud sync journal; Syncthing folders/devices; MEGA settings; Seafile directory pointer |
| Dark Web Apps | Tor/Tor Browser, I2P/i2pd, OnionShare, Hyphanet/Freenet | Tor directives/onion-service references, router/tunnel settings, OnionShare JSON, Hyphanet properties; existing specialized Tor Browser parsers remain active |
| Anti-forensics Apps | BleachBit, KDE Sweeper, shred, wipe, secure-delete utilities | Cleaner preferences, CleanerML XML and installed tool files. Configuration or installed binaries do not prove execution, successful cleaning or intent |
| Virtual Machines | VirtualBox, VMware, libvirt/QEMU, GNOME Boxes | VM registry/configuration, snapshot references, disks, interfaces and memory settings; VM disks, saved states/memory and logs retained raw |

## Boundaries and interpretation

Definitions live in four category-specific `index.json` files, with paths, sources, parser names and limitations. Shared format readers live in `artifacts/applications.py`. XML namespaces are supported; DTD/entity declarations, excessive nesting and configuration inputs over 8 MiB are rejected for structured parsing, with original evidence retained. SQLite parsing uses the existing verified RAM snapshot/WAL handling, rejects views/virtual tables, and reports unsupported schemas through diagnostics.

Secret-named settings are redacted in structured summaries; original evidence is retained. Fully encrypted rclone configurations are explicitly reported locked. Obfuscated rclone passwords, encrypted Dropbox/MEGA state and encrypted Seafile libraries are not decrypted by these new readers. Client caches/state outside supported schemas remain raw-only. The definitions do not contact providers, Tor/I2P nodes or onion services, launch clients, execute cleaners, start guests, mount guest filesystems, or follow configuration references beyond selected targets. Remote-only/cloud-placeholder contents are not acquired. Arbitrary custom XDG/configuration paths require selecting those locations; default path coverage is not exhaustive app discovery.

VM disk extensions identify candidates, not validated disk formats. Existing large-file RAM retention/export rules still apply, so classification does not imply the whole disk was retained in RAM. Syncthing is peer-to-peer synchronization, included alongside cloud client artifacts with that distinction recorded.

Tor Browser profile databases keep their existing browser parser/category and also appear under Dark Web Apps. Other recognized profile files are retained raw in Dark Web Apps. Privacy software presence does not establish illegal activity.

## Image review overlap

Skin-colour Review and Weapon Review are independent. Skin screening measures the proportion of sampled opaque pixels within the documented YCbCr colour ranges, compared to the user's skin percentage threshold (default 30%). It does not recognize anatomy. Wood, sand, leather or beige backgrounds can satisfy those ranges; an image showing a weapon can therefore be listed in both categories. Weapon screening uses separate offline inference and its own threshold. No detector/category wiring fault was found, and neither detector was adjusted for the reported AK-47 example. The user's exact image was not available for pixel-by-pixel validation.

Regression tests cover all four independent skin/weapon outcomes, mounted-root path recognition, preserved Tor Browser parsing, selected-scope collection, matches-only filtering, protected/invalid/raw inputs, SQLite schema checks, XML entity rejection, source byte preservation and structured ZIP export.

## Research sources

Primary app documentation/source code was used for implemented paths and formats. UAC and KAPE definitions were compared as forensic collection references; KAPE Windows roots were not copied as Linux defaults. Velociraptor's repository was searched for these app families; this does not imply borrowing or implementing every tool's collectors. SANS and the Tor audit provide forensic interpretation context rather than Linux schema specifications.

- [UAC artifacts](https://tclahr.github.io/uac-docs/artifacts/)
- [KAPE VirtualBox configuration targets](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/VirtualBoxConfig.tkape)
- [Velociraptor artifact repository](https://github.com/Velocidex/velociraptor/tree/master/artifacts/definitions)
- [SANS: private browsing and anti-forensic tools](https://www.sans.org/white-papers/40005)
- [Tor Browser forensic audit](https://arxiv.org/abs/1907.10279)
- [rclone](https://rclone.org/docs/)
- [dropbox](https://help.dropbox.com/installs/locate-dropbox-folder)
- [uac dropbox](https://github.com/tclahr/uac/blob/main/artifacts/files/applications/dropbox.yaml)
- [nextcloud](https://docs.nextcloud.com/server/latest/user_manual/en/desktop/configfile.html)
- [onedrive config](https://github.com/abraunegg/onedrive/blob/master/docs/USAGE.md)
- [onedrive schema](https://github.com/abraunegg/onedrive/blob/master/src/itemdb.d)
- [nextcloud schema](https://github.com/nextcloud/desktop/blob/master/src/common/syncjournaldb.cpp)
- [syncthing](https://docs.syncthing.net/users/config.html)
- [MEGAsync configuration reader](https://github.com/meganz/MEGAsync/blob/master/src/MEGASync/control/Preferences/Preferences.cpp)
- [Seafile applet configuration](https://github.com/haiwen/seafile-client/blob/master/src/seafile-applet.cpp)
- [Seafile data directory pointer](https://github.com/haiwen/seafile-client/blob/master/src/configurator.cpp)
- [tor](https://manpages.debian.org/bookworm/tor/tor.1.en.html)
- [i2p](https://github.com/i2p/i2p.i2p/blob/master/router/java/src/net/i2p/router/Router.java)
- [i2pd](https://docs.i2pd.website/en/latest/user-guide/configuration/)
- [onionshare](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [hyphanet](https://www.hyphanet.org/pages/help.html)
- [Tor Browser forensic audit](https://arxiv.org/abs/1907.10279)
- [bleachbit](https://github.com/bleachbit/bleachbit/blob/master/bleachbit/Options.py)
- [cleanerml](https://docs.bleachbit.org/doc/cleanerml/)
- [shred](https://www.gnu.org/software/coreutils/manual/html_node/shred-invocation.html)
- [KDE Sweeper cleaning preferences](https://github.com/KDE/sweeper/blob/master/sweeper.cpp)
- [virtualbox](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/TechnicalBackground.html)
- [kape vmware](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/VMwareInventory.tkape)
- [libvirt](https://libvirt.org/formatdomain.html)
- [VMware Workstation Linux inventory](https://knowledge.broadcom.com/external/article?legacyId=57224)
