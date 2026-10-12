"""Parsers for Linux kernel metadata; no commands or examined files are run."""
import re
import socket
import sys


def unescape(value):
    return re.sub(r'\\(040|011|012|134)', lambda match: chr(int(match[1], 8)), value)


def ipv4(value):
    return socket.inet_ntop(socket.AF_INET, int(value, 16).to_bytes(4, sys.byteorder))


def parse_line(parser, line):
    fields = line.split()
    if parser == 'modules':
        if len(fields) < 6:
            raise ValueError('Truncated kernel module record')
        return dict(type='loaded_kernel_module', name=fields[0], size_bytes=int(fields[1]),
                    reference_count=int(fields[2]), used_by=fields[3].rstrip(',').split(',') if fields[3] != '-' else [],
                    state=fields[4], address_raw=fields[5],
                    note='Kernel address may be redacted; module presence does not establish maliciousness.')
    if parser == 'maps':
        fields = line.split(None, 5)
        start, end = fields[0].split('-')
        start, end = int(start, 16), int(end, 16)
        if end < start:
            raise ValueError('Invalid process mapping range')
        return dict(type='process_mapping', start_address=start, end_address=end,
                    size_bytes=end - start, permissions=fields[1], offset=int(fields[2], 16),
                    mapped_device=fields[3], mapped_inode=int(fields[4]),
                    mapped_path=fields[5] if len(fields) > 5 else '',
                    note='Observed mapping only; mapped file contents were not read.')
    if parser == 'mountinfo':
        before, after = line.split(' - ', 1)
        left, right = before.split(), after.split()
        return dict(type='active_mount', mount_id=int(left[0]), parent_id=int(left[1]),
                    device=left[2], root=unescape(left[3]), mountpoint=unescape(left[4]),
                    mount_options=left[5].split(','), optional_fields=left[6:],
                    filesystem=right[0], source=unescape(right[1]), super_options=right[2].split(','))
    if parser == 'partitions':
        return dict(type='block_partition', major=int(fields[0]), minor=int(fields[1]),
                    blocks_1024=int(fields[2]), name=fields[3])
    if parser == 'arp':
        return dict(type='arp_neighbor', address=fields[0], hardware_type_raw=fields[1],
                    flags_raw=fields[2], hardware_address=fields[3], mask=fields[4], interface=fields[5],
                    note='Current ARP cache, not connection history.')
    if parser == 'route':
        return dict(type='ipv4_route', interface=fields[0], destination=ipv4(fields[1]),
                    gateway=ipv4(fields[2]), flags_raw=fields[3], metric=int(fields[6]), mask=ipv4(fields[7]))
    if parser == 'ipv6_route':
        return dict(type='ipv6_route', destination=socket.inet_ntop(socket.AF_INET6, bytes.fromhex(fields[0])),
                    destination_prefix=int(fields[1], 16),
                    source=socket.inet_ntop(socket.AF_INET6, bytes.fromhex(fields[2])), source_prefix=int(fields[3], 16),
                    gateway=socket.inet_ntop(socket.AF_INET6, bytes.fromhex(fields[4])),
                    metric=int(fields[5], 16), flags_raw=fields[8], interface=fields[9])
    if parser == 'net_dev':
        interface, counters = line.rsplit(':', 1)
        values = [int(value) for value in counters.split()]
        if len(values) != 16 or any(value < 0 for value in values):
            raise ValueError('Invalid network interface counters')
        labels = ('bytes', 'packets', 'errors', 'dropped', 'fifo', 'frame', 'compressed', 'multicast')
        tx_labels = ('bytes', 'packets', 'errors', 'dropped', 'fifo', 'collisions', 'carrier', 'compressed')
        return dict(type='network_interface_counters', interface=interface.strip(),
                    receive=dict(zip(labels, values[:8])), transmit=dict(zip(tx_labels, values[8:])))
    if parser == 'if_inet6':
        return dict(type='interface_ipv6_address', address=socket.inet_ntop(socket.AF_INET6, bytes.fromhex(fields[0])),
                    interface_index=int(fields[1], 16), prefix_length=int(fields[2], 16),
                    scope_raw=fields[3], flags_raw=fields[4], interface=fields[5])
    raise ValueError('Unknown kernel table parser')
