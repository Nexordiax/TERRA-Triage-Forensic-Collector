# Linux live collectors and device/container detection

The target page offers **Collect live state from this running system**. It is
selected for the default all-mounted-volumes workflow and cleared when switching
to custom targets. An examiner can explicitly select it for a custom scan. This
option always refers to the running host, never to the operating system stored
on an offline volume. It does not acquire RAM; the existing RAM checkbox remains
a separate acquisition.

## Collection sources

| Category | Sources | Interpretation |
| --- | --- | --- |
| Running Processes | `/proc/<pid>/stat`, `status`, `cmdline`, `environ`, `exe`, `cwd`, `root` | Observed processes, accessible environments, raw start ticks and clock frequency; PID directory descriptors prevent reuse from silently retargeting reads. |
| Process Mappings | `/proc/<pid>/maps` | Virtual ranges, permissions, offsets, inode/device and mapped paths. Mapped contents are not read. |
| Kernel Modules | `/proc/modules` | Names, sizes, references, dependencies and raw addresses. Addresses may be redacted. |
| Device Information | `/proc/<pid>/mountinfo`, `/proc/partitions` | Current mounts in accessible discovered mount namespaces and exposed partition metadata. Block devices are not opened. |
| Open File Handles | `/proc/<pid>/fd` links | Observed descriptor targets, including deleted paths, pipes, anonymous handles and sockets. Referenced files are never opened. |
| Network Connections | `/proc/<pid>/net/{tcp,tcp6,udp,udp6,unix}` | Endpoints, raw states, TCP state labels, UID and socket inode. Includes listening sockets; endpoints alone do not prove remote access or application identity. |
| Network Connections | `/proc/<pid>/net/{arp,route,ipv6_route,dev,if_inet6}` | ARP cache, routes, interface counters and IPv6 interface addresses in discovered network namespaces, not connection history. |
| Connected Devices | `/sys/bus/usb/devices` public text attributes | USB devices present at snapshot, with vendor/product IDs, descriptors and available serial numbers. Includes hubs; no device node is opened. |
| Login Sessions | `/run/systemd/sessions`, accessible utmp, boot-scoped logind journal events | Observed login boundaries; private state layout is validated, never shell-sourced. |
| Connected Devices timeline | Boot-scoped local kernel journal; read-only nonblocking `/dev/kmsg` fallback | Recognized USB connection/disconnection/descriptor events correlated with recorded login sessions. |
| Connected Devices history | Selected syslog/kernel logs; BlueZ `/var/lib/bluetooth/<adapter>/<device>/info` | USB event messages retain source timestamps; Bluetooth records describe stored associations/configuration, not current connections. |
| Encrypted Containers | First 4 KiB of each scanned regular file | LUKS1/LUKS2 and KeePass KDBX public signatures and versions, independent of filename. Detection works even when file bytes exceed cache limits. |

Only processes whose metadata can be read and whose identity remains stable are
shown. Access failures, exits, malformed records and unavailable sources are
logged. Optional USB descriptors may be absent. Root may improve visibility, but
these collectors never elevate privileges.

Each discovered network/mount namespace is read once per table through a pinned
process or thread directory. Representatives are retried after access failures;
process start ticks and namespace membership are checked before/after each read.
Threads with independent namespaces are included. Socket owners are joined using
namespace plus inode. Unavailable tables and malformed rows have explicit coverage
statuses; an empty readable table is distinct from an unavailable table. No
`setns`, namespace creation, container daemon requests, or traversal of process
roots occurs. Namespaces without a visible accessible representative, other PID
namespaces and permission-hidden processes remain outside coverage. Snapshot
collection is non-atomic; owner links are observations, not guaranteed current
ownership or proof of application identity.

USB events are correlated with **recorded login sessions**, including overlapping
users and each user's latest observed login. Same-boot monotonic ordering takes
priority over UTC wall time. Different known boot or machine IDs cannot match.
Yearless or timezone-free syslog dates remain uncorrelated. Unknown logout times
are labelled `after_login_end_unknown`; logind removal is distinguished from
actual user logout. A relation does not attribute a physical action to a user.
Journal receipt timestamps are labelled: delivery delay can affect ordering near
a login boundary. A supported kernel source monotonic timestamp takes priority
when available. Device presence alone never proves a connection since login.
A present USB device is associated with an observed connection generation only
when vendor/product IDs, serial and available device number agree, with no later
observed disconnect. Missing serials retain presence and history separately.

The existing **Collect live state** selection authorizes this running host's
local journal metadata observations. Journals are filtered to the current boot,
kernel transport and trusted logind unit/session message IDs. No daemon or
`journalctl` is invoked. Session state snapshots retain parsed fields and source
SHA256. Journal observations retain identifying source fields, both clocks and
boot ID, not a claim of a complete immutable raw journal acquisition. The kernel
ring fallback opens only `/dev/kmsg` read-only/nonblocking, validates device 1:11,
ignores user-injected messages, records sequence gaps, and never clears the ring
or reads consuming `/proc/kmsg`. Journal reading has a combined 30-second/250,000
entry budget; ring reading has a 10-second/250,000 entry budget. Limits and access
failures are diagnostic/coverage findings, never evidence of no prior connections.

For offline targets, the scan's final analysis pass correlates already acquired
wtmp/utmp and timestamped syslog/journal entries within their filesystem log root.
It makes no additional host/source reads and leaves raw bytes and hashes intact.
Known mixed machine identities are separated; ambiguous wtmp identity cannot be
borrowed for a journal from a mixed-machine root. Only already collected records
participate, including in matches-only mode. Stop/cancellation preserves existing
findings; completed scans receive cross-file correlation. Bluetooth configuration
is still stored association metadata, not proof of a connection. Other device
families and logs with unsupported messages retain their existing interpretation.

VeraCrypt/TrueCrypt filenames remain
candidates: there is no public identifying header signature. Container header
recognition does not validate all metadata, establish integrity, or decrypt
content; LUKS headers can also be detached backups.

## Storage, matching and export

Live snapshots are generated JSON retained in RAM. They record host, boot ID when
available, collection start/end times, network and mount namespaces, sources and limitations.
They cannot silently fall back to source files when the RAM byte cache is full:
collection stops with a logged memory-limit status instead. No evidence is
written until the examiner explicitly exports.

Full collection includes nonempty live categories. Matches-only collection
filters live entries using enabled filename checks against executable/handle/mapped-file
names and content keyword checks against the generated metadata. Such matches
describe metadata, not bytes of the executable or open file. Imported file hashes
are never compared to generated snapshots; ordinary target-file hash matching is
unchanged. Snapshot SHA256 values verify the generated JSON.

ZIP exports place snapshots under `live/`, raw target files under `evidence/`,
and derived JSONL/CSV under `analysis/`. Manifest and derived metadata identify
live-host scope and provenance. A file containing USB history can appear in both
OS Activity and Connected Devices in the GUI; its bytes are exported once.

Accessible process environments may contain sensitive values; these remain local
with the evidence. Process mappings describe addresses, not a RAM dump.

Journal decoding prefers a sealed RAM file. Some libsystemd versions reject such
unlinked files; the fallback opens the anchored original source read-only and
reverifies its complete SHA256 and identity after parsing. If the source changed,
all derived records are discarded and acquired raw bytes are preserved. No
journal daemon is contacted, no `journalctl` is executed and filesystem parsing does not search host journal
directories. Opt-in live journal observations use the separate boot-scoped reader
described above. Field truncation is disabled; repeated
and binary fields are preserved. Journal sealing and completeness are not
verified. Unsupported libraries/formats produce diagnostics.

## Primary research sources

This implementation uses original Python collectors informed by public format
documentation and collector inventories; it does not run downloaded tools or
copy external command execution logic.

- [UAC live-response definitions](https://github.com/tclahr/uac/tree/main/artifacts/live_response)
- [psutil Linux implementation](https://github.com/giampaolo/psutil/blob/master/psutil/_pslinux.py)
- [Linux proc filesystem documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
- [Process stat format](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html)
- [Process descriptor links and access restrictions](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [Network namespace scope](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html)
- [Kernel TCP socket table documentation](https://docs.kernel.org/networking/proc_net_tcp.html)
- [BlueZ storage specification](https://github.com/bluez/bluez/blob/master/doc/settings-storage.txt)
- [LUKS1 format](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf)
- [LUKS2 format](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/docs/on-disk-format-luks2.pdf)
- [KeePass KDBX format](https://keepass.info/help/kb/kdbx.html)

## Validation and implementation files (2026-10-10)

`tests/test_device_namespaces.py` covers distinct/shared/thread namespaces,
representative retries and namespace changes, unavailable versus empty tables,
clock changes, overlapping sessions, boot boundaries, serial/port reuse, source
symlinks, journal filters/budgets, kernel ring semantics, and cross-file ZIP
provenance. A read-only smoke check exercised this development host's accessible
proc views, session files and retained journals. Multiple namespace cases use
controlled fixtures; this is not a claim of validation on every distribution or
container runtime.

Changed implementation: `artifacts/live.py`, `namespaces.py`, `live_tables.py`,
`devices.py`, `login_devices.py`, `device_history.py`, `os_activity/journal.py`,
`analyzers/device_timeline.py`, `controllers/scan_controller.py`,
`storage/memory_store.py`; new tests in `tests/test_device_namespaces.py`.

Additional primary sources:

- [Namespace membership](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Mount namespace views](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [Logind session state and events](https://github.com/systemd/systemd/blob/main/src/login/logind-session.c)
- [Session message IDs](https://github.com/systemd/systemd/blob/v255/src/systemd/sd-messages.h)
- [Journal clocks and boot IDs](https://www.freedesktop.org/software/systemd/man/latest/sd_journal_get_realtime_usec.html)
- [Kernel ring read semantics](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/dev-kmsg)
