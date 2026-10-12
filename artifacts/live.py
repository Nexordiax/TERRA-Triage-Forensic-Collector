"""Read-only Linux live snapshots. Never follow or open reported file handles."""
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from artifacts.parser_support import check_cancelled
from artifacts.live_tables import parse_line
from artifacts.namespaces import add_candidate, collect_views, discover_threads
from artifacts.login_devices import LoginDeviceCollector, SOURCES as LOGIN_DEVICE_SOURCES

SOURCES = [
    'https://github.com/tclahr/uac/tree/main/artifacts/live_response',
    'https://github.com/giampaolo/psutil/blob/master/psutil/_pslinux.py',
    'https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html',
    'https://docs.kernel.org/networking/proc_net_tcp.html',
    'https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Linux/Sys/Maps.yaml',
    'https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Linux/Proc/Arp.yaml',
    'https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Linux/Proc/Modules.yaml',
    'https://github.com/WithSecureLabs/LinuxCatScale/blob/master/Cat-Scale.sh',
    'https://www.sans.org/posters/linux-incident-response-threat-hunting-poster',
]
TCP_STATES = dict(zip(range(1, 13), ('ESTABLISHED', 'SYN_SENT', 'SYN_RECV',
    'FIN_WAIT1', 'FIN_WAIT2', 'TIME_WAIT', 'CLOSE', 'CLOSE_WAIT', 'LAST_ACK',
    'LISTEN', 'CLOSING', 'NEW_SYN_RECV')))


def process_stat(text):
    end = text.rfind(')')
    start = text.find('(')
    fields = text[end + 2:].split()
    if start < 0 or end < start or len(fields) < 22:
        raise ValueError('Truncated process stat record')
    return dict(pid=int(text[:start]), name=text[start + 1:end], state=fields[0],
                parent_pid=int(fields[1]), session_id=int(fields[3]),
                start_ticks=int(fields[19]), virtual_bytes=int(fields[20]),
                resident_pages=int(fields[21]))


def endpoint(value, ipv6=False):
    address, port = value.split(':')
    raw = bytes.fromhex(address)
    if sys.byteorder == 'little':
        raw = b''.join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    return {'address': socket.inet_ntop(socket.AF_INET6 if ipv6 else socket.AF_INET, raw),
            'port': int(port, 16)}


class LiveCollector:
    def __init__(self, proc='/proc', sysfs='/sys', cancelled=lambda: False,
                 diagnostic=lambda path, message, level: None, progress=lambda path: None):
        self.proc, self.sysfs = Path(proc), Path(sysfs)
        self.cancelled, self.diagnostic = cancelled, diagnostic
        self.progress = progress

    def read(self, name, directory_fd=None):
        fd = os.open(str(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory_fd)
        with os.fdopen(fd, 'rb') as source:
            # Kernel metadata only; this is not a target-file acquisition limit.
            data = source.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError('Kernel metadata exceeds snapshot field limit')
        return data.decode('utf-8', errors='replace')

    def warn(self, path, error):
        self.diagnostic(str(path), str(error), 'warning')

    def collect(self):
        check_cancelled(self.cancelled)
        started = datetime.now(timezone.utc).isoformat()
        groups = {'Running Processes': [], 'Open File Handles': [],
                  'Network Connections': [], 'Connected Devices': [],
                  'Process Mappings': [], 'Kernel Modules': [], 'Device Information': []}
        owners = {}
        candidates = {"net": {}, "mnt": {}}
        for kind in candidates:
            try:
                add_candidate(candidates, kind, os.readlink(self.proc / ("self/ns/" + kind)), "self")
            except OSError as error:
                self.warn(self.proc / ("self/ns/" + kind), error)
        try:
            namespace = os.readlink(self.proc / 'self/ns/net')
        except OSError as error:
            namespace = None
            self.warn(self.proc / 'self/ns/net', error)
        try:
            names = os.listdir(self.proc)
        except OSError as error:
            self.warn(self.proc, error)
            names = []
        for pid in sorted((name for name in names if name.isdigit()), key=int):
            check_cancelled(self.cancelled)
            folder = self.proc / pid
            self.progress(str(folder))
            descriptor = None
            try:
                descriptor = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                row = process_stat(self.read('stat', descriptor))
                row.update(type='running_process', locator=str(folder),
                           clock_ticks_per_second=os.sysconf('SC_CLK_TCK'))
                for field in ('status', 'cmdline', 'environ'):
                    try:
                        value = self.read(field, descriptor)
                        row[field] = value.split('\0')[:-1] if field in ('cmdline', 'environ') and value.endswith('\0') else value
                    except (OSError, ValueError) as error:
                        self.warn(folder / field, error)
                for field in ('exe', 'cwd', 'root'):
                    try:
                        row[field] = os.readlink(field, dir_fd=descriptor)
                    except OSError as error:
                        self.warn(folder / field, error)
                try:
                    process_namespace = os.readlink('ns/net', dir_fd=descriptor)
                except OSError as error:
                    process_namespace = None
                    self.warn(folder / 'ns/net', error)
                try:
                    mount_namespace = os.readlink('ns/mnt', dir_fd=descriptor)
                except OSError as error:
                    mount_namespace = None
                    self.warn(folder / 'ns/mnt', error)
                row.update(network_namespace=process_namespace, mount_namespace=mount_namespace)
                handles = []
                mappings = []
                try:
                    for number, line in enumerate(self.read('maps', descriptor).splitlines(), 1):
                        check_cancelled(self.cancelled)
                        try:
                            mappings.append(dict(parse_line('maps', line), locator=f'{folder}/maps:{number}',
                                                 pid=row['pid'], process_start_ticks=row['start_ticks']))
                        except (ValueError, IndexError, OSError) as error:
                            self.warn(f'{folder}/maps:{number}', error)
                except (OSError, ValueError) as error:
                    self.warn(folder / 'maps', error)
                try:
                    fd_folder = os.open('fd', os.O_RDONLY | os.O_DIRECTORY, dir_fd=descriptor)
                    try:
                        for number in os.listdir(fd_folder):
                            check_cancelled(self.cancelled)
                            try:
                                target = os.readlink(number, dir_fd=fd_folder)
                                handles.append(dict(type='open_handle', locator=str(folder / 'fd' / number),
                                                    pid=row['pid'], process_start_ticks=row['start_ticks'],
                                                    descriptor=int(number), target=target))
                            except (OSError, ValueError) as error:
                                self.warn(folder / 'fd' / number, error)
                    finally:
                        os.close(fd_folder)
                except OSError as error:
                    self.warn(folder / 'fd', error)
                if process_stat(self.read('stat', descriptor))['start_ticks'] != row['start_ticks']:
                    raise ValueError('Process identity changed during snapshot; discarded')
                for kind, observed in (('net', process_namespace), ('mnt', mount_namespace)):
                    if observed is not None and os.readlink('ns/' + kind, dir_fd=descriptor) != observed:
                        raise ValueError('Process namespace changed during snapshot; discarded')
                groups['Running Processes'].append(row)
                groups['Open File Handles'].extend(handles)
                groups['Process Mappings'].extend(mappings)
                for kind, observed in (('net', process_namespace), ('mnt', mount_namespace)):
                    add_candidate(candidates, kind, observed, pid, pid=row['pid'], start_ticks=row['start_ticks'])
                discover_threads(self, folder, row, candidates)
                if process_namespace is not None:
                    for handle in handles:
                        target = handle['target']
                        if target.startswith('socket:[') and target.endswith(']'):
                            owners.setdefault((process_namespace, target[8:-1]), []).append(
                                dict(pid=row['pid'], descriptor=handle['descriptor'],
                                     process_start_ticks=row['start_ticks']))
            except (OSError, ValueError) as error:
                self.warn(folder, error)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        coverage = collect_views(self, groups, candidates, owners)
        tables = [('modules', 'modules', 'Kernel Modules', 0),
                  ('partitions', 'partitions', 'Device Information', 2)]
        # Preserve readable mounts even when the namespace ID is inaccessible.
        if not candidates['mnt']:
            tables.insert(1, ('self/mountinfo', 'mountinfo', 'Device Information', 0))
        for name, parser, category, skip in tables:
            check_cancelled(self.cancelled)
            path = self.proc / name
            self.progress(str(path))
            try:
                lines = self.read(path).splitlines()
            except (OSError, ValueError) as error:
                self.warn(path, error)
                continue
            for number, line in enumerate(lines[skip:], skip + 1):
                check_cancelled(self.cancelled)
                if not line.strip():
                    continue
                try:
                    row = dict(parse_line(parser, line), locator=f'{path}:{number}')
                    if category == 'Network Connections':
                        row['network_namespace'] = namespace
                    groups[category].append(row)
                except (ValueError, IndexError, OSError) as error:
                    self.warn(f'{path}:{number}', error)
        usb = self.sysfs / 'bus/usb/devices'
        try:
            devices = list(usb.iterdir())
        except OSError as error:
            self.warn(usb, error)
            devices = []
        for device in devices:
            check_cancelled(self.cancelled)
            self.progress(str(device))
            # sysfs exposes device directories as links; only known text attributes
            # are read, never device nodes or files on the connected storage.
            if ':' in device.name:
                continue
            row = dict(type='connected_usb_device', locator=str(device),
                       connection_semantics='Present at snapshot; connection time unknown')
            for field in ('idVendor', 'idProduct', 'busnum', 'devnum', 'manufacturer', 'product', 'serial', 'speed'):
                try:
                    row[field] = self.read(device / field).strip()
                except FileNotFoundError:
                    pass  # Optional USB descriptors.
                except (OSError, ValueError) as error:
                    self.warn(device / field, error)
            if 'idVendor' in row and 'idProduct' in row:
                groups['Connected Devices'].append(row)
        provenance = dict(scope='live_host', hostname=socket.gethostname(),
                          started_at=started, finished_at=datetime.now(timezone.utc).isoformat(),
                          network_namespace=namespace, namespace_coverage=coverage, sources=SOURCES + LOGIN_DEVICE_SOURCES,
                          limitations=['Non-atomic snapshot; exited/inaccessible processes may be missing.',
                                       'Accessible process/thread network namespaces are sampled; socket owner associations are observations.',
                                       'Process environments may contain sensitive values; only accessible values are read.',
                                       'Accessible process/thread mount namespaces are sampled; mount information is not historical.',
                                       'USB presence does not establish when a device was connected.'])
        try:
            provenance['mount_namespace'] = os.readlink(self.proc / 'self/ns/mnt')
        except OSError as error:
            self.warn(self.proc / 'self/ns/mnt', error)
        try:
            provenance['boot_id'] = self.read(self.proc / 'sys/kernel/random/boot_id').strip()
        except (OSError, ValueError) as error:
            self.warn(self.proc / 'sys/kernel/random/boot_id', error)
        sessions, devices, device_coverage = LoginDeviceCollector(self).collect(
            provenance.get('boot_id'), [dict(device, bus_path=Path(device['locator']).name,
                                           boot_id=provenance.get('boot_id')) for device in groups['Connected Devices']])
        groups['Login Sessions'] = sessions
        groups['Connected Devices'] = devices
        provenance['device_timeline_coverage'] = device_coverage
        provenance['limitations'].extend([
            'Device/login relations are temporal observations, not attribution to a user.',
            'Retained accessible logs may omit events; no match does not prove a device was not connected.',
            'Other PID namespaces, invisible processes and namespaces with no visible representative remain outside coverage.',
        ])
        provenance['finished_at'] = datetime.now(timezone.utc).isoformat()
        return groups, provenance


def snapshot_bytes(entries, provenance):
    return json.dumps(dict(provenance=provenance, entries=entries), ensure_ascii=True,
                      sort_keys=True, indent=2).encode('utf-8')
