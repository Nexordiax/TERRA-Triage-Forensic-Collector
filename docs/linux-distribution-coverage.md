# Linux collection coverage expansion

Research date: 2026-10-11.

This update adds 57 named artifact definitions and expands paths for 19 existing definitions. The combined catalog now has 218 definitions: 128 with parser adapters and 90 collected raw. These are definition groups, not counts of file formats, individual paths or guaranteed findings.

The update is data-driven in `artifacts/linux_distribution_index.json`, loaded by `artifacts/catalog.py`. Original definition IDs and parser dispatch remain in use for expanded paths. New package/account format adapters are isolated in `artifacts/distribution_metadata.py` and connected through `artifacts/parsing.py`. No GUI, RAM acquisition, search settings or export layout changes are required.

## Distribution families

| Family | Coverage added or extended |
| --- | --- |
| Debian, Ubuntu, Kali | APT extended state, dpkg file lists/checksums, diversions and package overrides; Upstart legacy jobs; modern systemd and sandboxed applications. Existing dpkg parsing remains. |
| Fedora, RHEL, Rocky, AlmaLinux | DNF4/DNF5 transaction databases and system state; legacy ifcfg network configuration; broader systemd units. Existing RPM parsing remains. |
| openSUSE/SUSE | Parsed Zypp transaction history, including rotated compressed logs; wicked/ifcfg network settings. Existing RPM parsing remains. |
| Arch/Manjaro | Broader systemd services and network profiles, iwd, application state and Flatpak paths. Existing pacman inventory remains. |
| Alpine | APK world/repository policy and stored package scripts; ash history and OpenRC service configuration. Existing APK inventory remains. |
| Gentoo | Portage VDB scalar metadata, recorded build times, package file/environment metadata, world selection and OpenRC configuration. |
| Slackware | Current and historical removed package registrations, stored package scripts and policy. |
| Void | XBPS package database and file metadata, repository policy, runit scripts and disabled-service markers. |
| Nix/NixOS | Profile manifests v1/v2/v3, package database/logs and declarative configuration. Stored generations are not assumed to be the active generation. |

These locations also apply where those components are installed on other distributions. Distribution names do not imply that every artifact exists or that a complete disk image for each distribution has been tested.

## Categories

| Existing category | New definitions |
| --- | ---: |
| Installed Applications | 14 |
| Device Information | 4 |
| OS Activity | 20 |
| Network Connections | 9 |
| Communication | 1 |
| User Accounts | 3 |
| Connected Devices | 3 |
| Virtual Machines | 3 |

Browser and communication coverage additionally gains Flatpak XDG path variants for Chromium, Chrome, Brave, Edge, Vivaldi, Opera, Discord, Slack and Element wherever an existing native definition applies. These reuse the existing database/LevelDB parsers and companion definitions. Conventional Firefox/Thunderbird paths already match many Snap/Flatpak layouts. Custom XDG overrides or nonstandard profile locations are not automatically discovered by this update.

Containers are grouped under the existing Virtual Machines category; this is a collection grouping, not a claim that containers are full virtual machines. Quadlet startup files are parsed as configuration without running generators or pulling images.

## New definitions and interpretation

| Definition | Category | Support | Example paths |
| --- | --- | --- | --- |
| `gentoo_package_metadata` | Installed Applications | `distro_gentoo` | `/var/db/pkg/*/*/BUILD_TIME`<br>`/var/db/pkg/*/*/COUNTER`<br>`/var/db/pkg/*/*/CHOST`<br>+6 additional patterns in index |
| `gentoo_package_payload_metadata` | Installed Applications | Raw collection | `/var/db/pkg/*/*/CONTENTS`<br>`/var/db/pkg/*/*/environment.bz2`<br>`/var/db/pkg/*/*/NEEDED`<br>+3 additional patterns in index |
| `gentoo_package_policy` | Installed Applications | Raw collection | `/etc/portage/**`<br>`/var/lib/portage/world`<br>`/var/lib/portage/world_sets` |
| `gentoo_transaction_logs` | Installed Applications | `package_log` | `/var/log/emerge.log*`<br>`/var/log/portage/**` |
| `slackware_package_inventory` | Installed Applications | `distro_slackware` | `/var/log/packages/*`<br>`/var/lib/pkgtools/packages/*`<br>`/var/log/removed-packages/*`<br>+1 additional patterns in index |
| `slackware_package_scripts` | Installed Applications | Raw collection | `/var/lib/pkgtools/scripts/*`<br>`/var/lib/pkgtools/removed_scripts/*`<br>`/var/log/scripts/*`<br>+2 additional patterns in index |
| `void_xbps_inventory` | Installed Applications | `distro_xbps` | `/var/db/xbps/pkgdb-*.plist` |
| `void_xbps_files` | Installed Applications | Raw collection | `/var/db/xbps/.*-files.plist`<br>`/var/db/xbps/keys/*.plist`<br>`/etc/xbps.d/*.conf`<br>+1 additional patterns in index |
| `nix_profile_inventory` | Installed Applications | `distro_nix` | `/nix/store/*-profile/manifest.json`<br>`/nix/store/*-user-environment/manifest.json`<br>`/nix/var/nix/profiles/**/manifest.json`<br>+1 additional patterns in index |
| `nix_package_state` | Installed Applications | Raw collection | `/nix/store/*-user-environment/manifest.nix`<br>`/nix/store/*-profile/manifest.nix`<br>`/nix/var/nix/db/db.sqlite*`<br>+3 additional patterns in index |
| `nixos_configuration` | Device Information | Raw collection | `/etc/nixos/**/*.nix`<br>`/etc/nixos/flake.lock`<br>`/nix/store/*-nixos-system-*/nixos-version` |
| `suse_zypp_history` | Installed Applications | `distro_zypp` | `/var/log/zypp/history*` |
| `dnf_transaction_state` | Installed Applications | Raw collection | `/var/lib/dnf/history.sqlite*`<br>`/var/lib/yum/history/history-*.sqlite*`<br>`/usr/lib/sysimage/libdnf5/transaction_history.sqlite*`<br>+3 additional patterns in index |
| `debian_package_extended_state` | Installed Applications | Raw collection | `/var/lib/apt/extended_states`<br>`/var/lib/dpkg/updates/*`<br>`/var/lib/dpkg/diversions*`<br>+4 additional patterns in index |
| `alpine_package_policy` | Installed Applications | Raw collection | `/etc/apk/world`<br>`/etc/apk/repositories`<br>`/lib/apk/db/scripts.tar`<br>+1 additional patterns in index |
| `openrc_configuration` | OS Activity | `startup_script` | `/etc/rc.conf`<br>`/etc/conf.d/**`<br>`/etc/local.d/*.start`<br>+4 additional patterns in index |
| `runit_service_scripts` | OS Activity | `startup_script` | `/etc/sv/*/run`<br>`/etc/sv/*/finish`<br>`/etc/sv/*/log/run`<br>+8 additional patterns in index |
| `runit_disabled_markers` | OS Activity | Raw collection | `/etc/sv/*/down`<br>`/**/.config/service/*/down` |
| `upstart_jobs` | OS Activity | `startup_script` | `/etc/init/*.conf`<br>`/etc/init/*.override`<br>`/etc/xdg/upstart/*.conf`<br>+3 additional patterns in index |
| `systemd_lingering` | OS Activity | Raw collection | `/var/lib/systemd/linger/*` |
| `systemd_persistent_failures` | OS Activity | Raw collection | `/var/lib/systemd/coredump/**`<br>`/var/lib/systemd/pstore/**`<br>`/etc/systemd/coredump.conf`<br>+1 additional patterns in index |
| `additional_shell_history` | OS Activity | `line_history` | `/**/.ash_history*`<br>`/**/.sh_history*`<br>`/**/.ksh_history*`<br>+1 additional patterns in index |
| `tcsh_history` | OS Activity | Raw collection | `/**/.history`<br>`/**/.history.*` |
| `xonsh_history` | OS Activity | Raw collection | `/**/.local/share/xonsh/xonsh_history.sqlite*`<br>`/**/.local/share/xonsh/xonsh-*.json` |
| `shell_additional_startup` | OS Activity | `startup_script` | `/**/.cshrc`<br>`/**/.tcshrc`<br>`/**/.login`<br>+9 additional patterns in index |
| `gnome_gvfs_activity` | OS Activity | Raw collection | `/**/.local/share/gvfs-metadata/**`<br>`/**/.local/share/gnome-shell/application_state`<br>`/**/.config/dconf/user` |
| `gnome_tracker_indexes` | OS Activity | Raw collection | `/**/.cache/tracker3/files/*.db*`<br>`/**/.cache/tracker/*.db*`<br>`/**/.local/share/tracker/data/*.db*` |
| `kde_activity_database` | OS Activity | Raw collection | `/**/.local/share/kactivitymanagerd/resources/database*` |
| `desktop_session_configuration` | OS Activity | Raw collection | `/**/.config/xfce4/xfconf/xfce-perchannel-xml/*.xml`<br>`/**/.cache/sessions/xfce4-session-*`<br>`/**/.config/ksmserverrc`<br>+1 additional patterns in index |
| `office_recent_configuration` | OS Activity | Raw collection | `/**/.config/libreoffice/**/registrymodifications.xcu`<br>`/**/.var/app/org.libreoffice.LibreOffice/**/registrymodifications.xcu`<br>`/**/snap/libreoffice/**/registrymodifications.xcu` |
| `office_recent_xbel` | OS Activity | `recent` | `/**/.config/libreoffice/**/recently-used.xbel`<br>`/**/.var/app/org.libreoffice.LibreOffice/**/recently-used.xbel`<br>`/**/snap/libreoffice/**/recently-used.xbel` |
| `locate_file_indexes` | OS Activity | Raw collection | `/var/lib/mlocate/mlocate.db`<br>`/var/lib/plocate/plocate.db`<br>`/var/cache/locate/locatedb`<br>+1 additional patterns in index |
| `process_accounting_files` | OS Activity | Raw collection | `/var/account/pacct*`<br>`/var/log/account/pacct*`<br>`/var/log/pacct*` |
| `cloud_init_provisioning` | OS Activity | Raw collection | `/etc/cloud/cloud.cfg`<br>`/etc/cloud/cloud.cfg.d/**`<br>`/var/lib/cloud/instances/**`<br>+2 additional patterns in index |
| `cups_print_jobs` | OS Activity | Raw collection | `/var/spool/cups/c*`<br>`/var/spool/cups/d*`<br>`/var/cache/cups/job.cache*` |
| `networkd_profiles` | Network Connections | `network_profile` | `/etc/systemd/network/*.network`<br>`/etc/systemd/network/*.netdev`<br>`/etc/systemd/network/*.link`<br>+6 additional patterns in index |
| `legacy_distribution_network` | Network Connections | `network_profile` | `/etc/sysconfig/network-scripts/ifcfg-*`<br>`/etc/sysconfig/network-scripts/route-*`<br>`/etc/sysconfig/network/ifcfg-*`<br>+9 additional patterns in index |
| `iwd_networks` | Network Connections | `network_profile` | `/var/lib/iwd/*.psk`<br>`/var/lib/iwd/*.8021x`<br>`/var/lib/iwd/*.open`<br>+1 additional patterns in index |
| `connman_networks` | Network Connections | `network_profile` | `/var/lib/connman/**/settings`<br>`/var/lib/connman/settings`<br>`/var/lib/connman/*.config`<br>+2 additional patterns in index |
| `wireless_profiles` | Network Connections | `network_profile` | `/etc/wpa_supplicant/*.conf`<br>`/etc/wpa_supplicant.conf`<br>`/etc/network/if-pre-up.d/wpasupplicant` |
| `firewall_configuration` | Network Connections | `network_text` | `/etc/nftables.conf`<br>`/etc/nftables.d/**`<br>`/etc/iptables/*.rules`<br>+5 additional patterns in index |
| `filezilla_state` | Network Connections | Raw collection | `/**/.config/filezilla/*.xml*`<br>`/**/.config/filezilla/*.sqlite3*`<br>`/**/.var/app/org.filezillaproject.Filezilla/**/*.xml*`<br>+1 additional patterns in index |
| `rustdesk_access_logs` | Network Connections | `remote_trace` | `/**/.local/share/logs/RustDesk/**` |
| `teamviewer_access_logs` | Network Connections | `remote_trace` | `/var/log/teamviewer*/**/*.log`<br>`/var/log/teamviewer*/**/Connections_incoming.txt`<br>`/**/.local/share/teamviewer*/logfiles/*.log` |
| `teamviewer_chat_cache` | Communication | Raw collection | `/**/.local/share/teamviewer*/**/tvchatfilecache.db*` |
| `polkit_authorization` | User Accounts | Raw collection | `/etc/polkit-1/rules.d/*.rules`<br>`/usr/share/polkit-1/rules.d/*.rules`<br>`/usr/share/polkit-1/actions/*.policy`<br>+2 additional patterns in index |
| `accountsservice_user_state` | User Accounts | `distro_accountsservice` | `/var/lib/AccountsService/users/*` |
| `kerberos_account_configuration` | User Accounts | Raw collection | `/etc/krb5.conf`<br>`/etc/krb5.conf.d/**`<br>`/etc/krb5.keytab`<br>+3 additional patterns in index |
| `boot_loader_entries` | Device Information | Raw collection | `/boot/loader/loader.conf`<br>`/boot/loader/entries/*.conf`<br>`/boot/efi/loader/loader.conf`<br>+3 additional patterns in index |
| `system_policy_configuration` | Device Information | Raw collection | `/etc/sysctl.conf`<br>`/etc/sysctl.d/*.conf`<br>`/usr/lib/sysctl.d/*.conf`<br>+6 additional patterns in index |
| `lvm_volume_metadata` | Device Information | Raw collection | `/etc/lvm/backup/*`<br>`/etc/lvm/archive/*`<br>`/etc/lvm/lvm.conf` |
| `cups_printer_configuration` | Connected Devices | Raw collection | `/etc/cups/printers.conf*`<br>`/etc/cups/classes.conf*`<br>`/**/.cups/lpoptions` |
| `usbguard_device_policy` | Connected Devices | Raw collection | `/etc/usbguard/rules.conf`<br>`/etc/usbguard/rules.d/**`<br>`/etc/usbguard/usbguard-daemon.conf` |
| `fwupd_device_history` | Connected Devices | Raw collection | `/var/lib/fwupd/pending.db`<br>`/var/lib/fwupd/pending.db-wal`<br>`/var/lib/fwupd/pending.db-shm`<br>+1 additional patterns in index |
| `podman_container_metadata` | Virtual Machines | Raw collection | `/etc/containers/*.conf`<br>`/etc/containers/*.json`<br>`/**/.config/containers/*.conf`<br>+11 additional patterns in index |
| `libvirt_additional_state` | Virtual Machines | Raw collection | `/etc/libvirt/*.conf`<br>`/var/lib/libvirt/qemu/**/*.xml`<br>`/**/.config/libvirt/*.conf`<br>+1 additional patterns in index |
| `podman_quadlet_units` | Virtual Machines | `systemd` | `/etc/containers/systemd/**/*.container`<br>`/etc/containers/systemd/**/*.volume`<br>`/etc/containers/systemd/**/*.network`<br>+21 additional patterns in index |

## Collection and parsing limits

- Only accessible regular files inside the selected targets are acquired. Symlinks are not followed, and `/proc`, `/sys`, `/dev` and `/run` keep their existing exclusions. No privileged or external reads are added.
- A configured service, printer, firewall rule or network profile is not proof of execution or a current connection. USBGuard policies can contain device identifiers but do not establish when a device was connected.
- Desktop indexes, GVFS metadata, dconf, firmware history, process accounting, complex package databases and most container state are preserved raw. They are not labelled decoded. Standard SQLite sidecar paths are included for the added raw databases.
- Gentoo BUILD_TIME is a build timestamp. Slackware removed package records are marked removed. XBPS unpacked/half-removed states are not marked fully installed. Nix active flags describe a stored profile, which may be historical. Zypp history retains original wall-clock timestamps without inventing timezone information.
- Nix expressions, package install scripts, Polkit rules, cloud-init scripts and container definitions are never evaluated or executed. Referenced paths/URLs do not trigger collection outside the selected targets or any network requests.
- New distribution format parsers cap raw/expanded input at 32 MiB. Nix/XBPS/Zypp record counts are capped at 100,000. Unsupported, malformed or oversized inputs remain raw evidence with parser failure diagnostics, rather than being displayed as successfully decoded.
- Collection and export continue through the existing read-only, hashing, timestamp, logging and ZIP/report mechanisms. More collected artifact files can increase acquisition time and evidence size.

## Research references

Reviewed UAC file definitions and the ForensicArtifacts Linux catalog alongside Velociraptor Linux artifacts, Bruce Nikkel's Linux forensics workshop and upstream distribution/component specifications. Path definitions and format adapters are independent TERRA code; upstream programs are not executed or downloaded during collection.

- [UAC file artifact definitions, reviewed commit db563110](https://github.com/tclahr/uac/tree/db563110cb9d2d3a5ad8aa985c267205d45ce4da/artifacts/files)
- [ForensicArtifacts Linux definitions](https://github.com/ForensicArtifacts/artifacts/blob/main/artifacts/data/linux.yaml)
- [Bruce Nikkel: Forensic Artifacts in Modern Linux Systems](https://digitalforensics.ch/nikkel18.pdf)
- [Velociraptor Linux artifact definitions, reviewed commit bd3cf159](https://github.com/Velocidex/velociraptor/tree/bd3cf159a70dd8f6bff7d3fbaa57927792f0dc3b/artifacts/definitions/Linux)
- [Gentoo Portage file layout](https://dev.gentoo.org/~zmedico/portage/doc/man/portage.5.html)
- [Slackware package management](https://docs.slackware.com/slackware:package_management)
- [Void XBPS database layout](https://man.voidlinux.org/xbps)
- [XBPS package database implementation](https://github.com/void-linux/xbps/blob/master/lib/pkgdb.c)
- [Nix manifest JSON format](https://nix.dev/manual/nix/2.35/command-ref/files/manifest.json.html)
- [Nix profile manifest versions 1/2/3](https://github.com/NixOS/nix/blob/master/src/nix/profile.cc)
- [libzypp transaction history format](https://opensuse.github.io/libzypp/group__g__ZyppHistory.html)
- [DNF5 packaged state and history paths](https://github.com/rpm-software-management/dnf5/blob/main/dnf5.spec)
- [OpenRC user guide](https://github.com/OpenRC/openrc/blob/master/user-guide.md)
- [Void runit services](https://docs.voidlinux.org/config/services/index.html)
- [systemd unit load paths](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [Boot Loader Specification](https://uapi-group.org/specifications/specs/boot_loader_specification/)
- [polkit authorization policy](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [NetworkManager keyfile locations](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-keyfile.html)
- [systemd-networkd configuration locations](https://github.com/systemd/systemd/blob/main/man/systemd.network.xml)
- [ConnMan configuration format](https://github.com/sailfishos/connman/blob/master/connman/doc/config-format.txt)
- [iwd saved network format](https://kernel.googlesource.com/pub/scm/network/wireless/iwd/+/e8e9c68deaecec0aa4d7964661e73c885235284c/src/iwd.network.rst)
- [Flatpak XDG path conventions](https://docs.flatpak.org/en/latest/conventions.html)
- [cloud-init on-disk layout](https://docs.cloud-init.io/en/latest/development/internal_files.html)
- [Rootless Podman storage and configuration](https://github.com/podman-container-tools/podman/blob/main/docs/tutorials/rootless_tutorial.md)
- [libvirt QEMU state directories](https://www.libvirt.org/drvqemu.html)
- [CUPS printer configuration](https://www.cups.org/doc/man-printers.conf.html)
- [USBGuard default rules location](https://github.com/USBGuard/usbguard/blob/main/usbguard-daemon.conf.in)
- [fwupd device history implementation](https://github.com/fwupd/fwupd/blob/main/src/fu-history.c)
- [AccountsService user metadata directory](https://sources.debian.org/patches/accountsservice/0.6.21-8/0005-gdm_config_file_path.patch/)
- [Alpine APK world and package database](https://docs.alpinelinux.org/user-handbook/0.1a/Working/apk.html)
- [openSUSE network configuration](https://doc.opensuse.org/documentation/leap/reference/html/book-reference/cha-network.html)
- [RHEL ifcfg configuration files](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/configuring-ip-networking-with-ifcfg-files_configuring-and-managing-networking)
- [Podman Quadlet unit paths and formats](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)

- [Xfconf per-channel XML specification](https://github.com/xfce-mirror/xfconf/blob/master/docs/spec/perchannel-xml.txt)
- [Xfce session state locations](https://man.archlinux.org/man/extra/xfce4-session/xfce4-session.1.en)
- [KDE session manager configuration](https://github.com/KDE/plasma-desktop/blob/master/kcms/ksmserver/smserversettings.kcfg)

Flatpak application IDs were checked against the corresponding Flathub repositories. The XBPS parser was also exercised against the upstream `tests/xbps/libxbps/pkgdb/pkgdb-0.38.plist` fixture (seven package records); this downloaded research fixture is not required at runtime.

## Validation

The new fixture tests cover indexed path/category matching on mounted roots, Flatpak browser/chat paths, distro-specific record semantics, gzip/bzip2/xz rotations, bounds/cancellation, XML entity rejection, preservation of raw bytes on parsing failure, source hashes/provenance, symlink exclusion and final ZIP exports. Real-device validation across distribution/version combinations is still required; fixture coverage is not a certification of all supported operating systems.
