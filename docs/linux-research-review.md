# Expanded Linux triage source review

Reviewed 2026-10-10. This is a focused comparison, not complete feature parity
with every upstream tool or coverage of every Linux application.

## Projects reviewed

| Source | Material reviewed | TERRA consequence |
| --- | --- | --- |
| [SANS FOR577 Linux poster](https://www.sans.org/posters/linux-incident-response-threat-hunting-poster) | Public description and the SANS-authored PDF available from [UMBC](https://courses.cs.umbc.edu/undergraduate/CMSC491activeCyber/SANS_LINUX_Incident_Response_Threat_Hunting_Poster.pdf). | Added environments/mappings, mounts/partitions and missing persistence/log paths. Checked existing accounts, histories, SSH and scheduling coverage. |
| [SANS SIFT](https://www.sans.org/posters/sift-cheat-sheet) | Public reference description. | Reviewed workflow context; did not add automatic mounting or image conversion. |
| [Velociraptor](https://github.com/Velocidex/velociraptor/tree/master/artifacts/definitions/Linux) | Linux [Maps](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Linux/Sys/Maps.yaml), [Arp](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Linux/Proc/Arp.yaml), [Modules](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Linux/Proc/Modules.yaml), [Mounts](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Linux/Mounts.yaml) and [UAC rules](https://triage.velocidex.com/docs/linux.triage.uac/rules/). | Added kernel table/mapping collectors and checked Linux paths. Remote collection/upload was not imported. |
| [KapeFiles](https://github.com/EricZimmerman/KapeFiles) | Current [KapeTriage](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Compound/KapeTriage.tkape), [WebBrowsers](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Compound/WebBrowsers.tkape), [Firefox](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Browsers/Firefox.tkape), [AnyDesk](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/AnyDesk.tkape), target/module organization. | Cross-checked browser-extension and remote-access evidence. Windows paths were not inserted into the Linux catalog; AnyDesk Linux locations were verified with its vendor. The queried legacy SANS_Triage URL was unavailable, so its source content is not claimed as reviewed. |
| [WithSecure Linux CatScale](https://github.com/WithSecureLabs/LinuxCatScale/blob/master/Cat-Scale.sh) | Process/network, logs, configuration, startup, scheduling and loader collection routines. | Expanded live metadata and persistence interpretation. Its shell script and Docker/package commands are not invoked. |
| [CyLR](https://github.com/orlikoski/CyLR#linux) | Linux system/user collection inventory. | Added repository, log configuration, scheduler-state and startup variants. Narrow extension parsers precede broad raw rules. Inventory typos were not blindly copied. |
| [Sekoia FastIR Linux](https://github.com/SekoiaLab/Fastir_Collector_Linux/blob/master/fastIR_collector_linux.py) | Process/module/network and startup/configuration sources. | Cross-checked coverage. Subprocess execution and log-size cutoff were not adopted. |
| [DFIR ORC](https://dfir-orc.github.io/) | Platform scope and collection architecture. | It targets Windows; Windows-specific collectors were not added to this Linux implementation. |

## Implemented changes

The catalog grew from 79 definitions / 44 parser-backed definitions to **93
definitions / 58 parser-backed definitions**, with 35 raw-only definitions.
Generic full collection already acquires other readable regular files; a new
definition improves classification/interpretation rather than necessarily
increasing the number of acquired files.

- Live process environments/root links and mapped-file metadata; kernel modules;
  ARP cache; IPv4/IPv6 routes; mount/partition information. All remain scoped to
  the running host. Mappings are not dumped RAM.
- SSH authorization and known-host records with public-key SHA256 fingerprints.
  Invalid keys remain explicit unparsed records. Stored trust is not labelled as
  proof of a connection or authentication.
- APT list/deb822 records and other repository configuration; loader/module
  configuration; sudoers physical lines; shell startup definitions; autostart
  launchers; timer/service drop-ins; anacron dates; logging configuration.
- Chromium extension manifests and Firefox addon state. Extension code is never
  executed; unresolved localized names remain unchanged.
- AnyDesk Linux trace/configuration sources with original log messages retained.
  Undocumented session success/timestamp semantics are not inferred.
- Journal decoding through the host systemd read API, preserving source hashes,
  microsecond timestamps and repeated/binary fields. USB messages appear under
  Connected Devices too. If an original-source fallback is needed, the complete
  source is reverified; changes invalidate all derived records.
- Additional logs classified as raw OS Activity; recognized compressed text logs
  support gzip, bzip2 and xz.

## Format references and verification

Inventories suggest where to look; native documentation determines interpretation:
Linux [maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html),
[mountinfo](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html),
[loader configuration](https://man7.org/linux/man-pages/man5/ld.so.conf.5.html),
[Debian repositories](https://www.debian.org/doc/manuals/debian-reference/ch02.en.html),
[Chromium manifests](https://developer.chrome.com/docs/extensions/reference/manifest),
[AnyDesk traces](https://support.anydesk.com/what-are-trace-files), systemd's
[read API](https://github.com/systemd/systemd/blob/main/man/sd_journal_open.xml) and
[field enumeration](https://github.com/systemd/systemd/blob/main/man/sd_journal_get_data.xml).

Tests exercise rule priority, offline roots, valid/malformed input, disabled
repositories, repeated/binary journal fields, cancellation, namespace-safe
ownership, process identity changes, source revalidation and raw/derived ZIP
provenance. Read-only smoke checks exercised accessible live sources and decoded
5,339 records from an existing journal without printing/exporting their contents.
This is not validation across all distributions.

## Remaining limits

The subsequent [format expansion](linux-format-expansion.md) adds RPM SQLite/NDB,
lastlog/lastlog2, LevelDB physical records, Firefox snapshots and optional PST/OST
reading. RPM BDB, other lastlog ABIs and encrypted payload decryption remain unsupported;
native Telegram wrapper and Signal key-availability interpretation are partial. Journal decoding requires compatible host
libsystemd; unsupported input retains raw evidence with diagnostics. Host runtime
`/run` journals are excluded from recursive scanning. Accessible process/thread network and mount namespaces now have read-only views and coverage metadata; see [live collectors](linux-live-collectors.md). SUID detection, filesystem-wide metadata
timelines, Docker daemon interrogation, deleted-file recovery, automated malware
verdicts are not implemented here. Recorded USB/login-session temporal correlation is now available, with explicit clock, identity and log-completeness limits in the live-collector documentation.
Evidence stays local; hash/keyword selection, RAM acquisition and export retain
their existing behavior. Original TERRA code was written from format knowledge;
no upstream collector code was copied or installed.

Changed files: `artifacts/live.py`, `live_tables.py`, `devices.py`,
`persistence.py`, `os_activity/parser.py`, `os_activity/journal.py`,
`parser_support.py`, `parsing.py`, `linux_catalog.json`;
`controllers/scan_controller.py`; `interface/pages/targets.py`;
the corresponding collector tests, README and Linux documentation.
