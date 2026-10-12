"""Read namespace views through pinned proc directories without setns/root traversal."""
import os

from artifacts.parser_support import check_cancelled
from artifacts.live_tables import parse_line


def identity(collector, descriptor, candidate, kind):
    # Import lazily: live imports this module for collection.
    from artifacts.live import process_stat
    if candidate.get('start_ticks') is not None:
        if process_stat(collector.read('stat', descriptor))['start_ticks'] != candidate['start_ticks']:
            raise ValueError('Namespace representative process identity changed')
    if os.readlink('ns/' + kind, dir_fd=descriptor) != candidate['namespace']:
        raise ValueError('Namespace membership changed during snapshot')


def collect_views(collector, groups, candidates, owners):
    """One stable observation per namespace/table, retrying accessible representatives."""
    from artifacts.live import endpoint, TCP_STATES
    coverage = []
    specs = {'net': [(name, 'socket', 1) for name in ('tcp', 'tcp6', 'udp', 'udp6', 'unix')] +
                    [('arp', 'arp', 1), ('route', 'route', 1), ('ipv6_route', 'ipv6_route', 0),
                     ('dev', 'net_dev', 2), ('if_inet6', 'if_inet6', 0)],
             'mnt': [('mountinfo', 'mountinfo', 0)]}
    for kind in ('net', 'mnt'):
        for namespace, representatives in candidates[kind].items():
            check_cancelled(collector.cancelled)
            status = dict(type='namespace_coverage', kind=kind, namespace=namespace,
                          representatives=[{key: value for key, value in rep.items() if key != 'namespace'}
                                           for rep in representatives], tables={})
            for table, parser, skip in specs[kind]:
                failures = []
                accepted = False
                for rep in representatives:
                    check_cancelled(collector.cancelled)
                    base = collector.proc / rep['relative_path']
                    path = base / ('net/' + table if kind == 'net' else table)
                    collector.progress(str(path))
                    descriptor = None
                    try:
                        descriptor = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC |
                                             (0 if rep['relative_path'] == 'self' else os.O_NOFOLLOW))
                        identity(collector, descriptor, rep, kind)
                        text = collector.read('net/' + table if kind == 'net' else table, descriptor)
                        identity(collector, descriptor, rep, kind)
                        rows = []
                        parse_errors = 0
                        for number, line in enumerate(text.splitlines()[skip:], skip + 1):
                            check_cancelled(collector.cancelled)
                            if not line.strip():
                                continue
                            try:
                                if parser == 'socket':
                                    fields = line.split(None, 7) if table == 'unix' else line.split()
                                    if table == 'unix':
                                        inode = fields[6]
                                        row = dict(socket_type_raw=fields[4], state_raw=fields[5],
                                                   flags_raw=fields[3], address=fields[7] if len(fields) > 7 else '')
                                    else:
                                        inode = fields[9]
                                        row = dict(local=endpoint(fields[1], table.endswith('6')),
                                                   remote=endpoint(fields[2], table.endswith('6')),
                                                   state_raw=fields[3], uid=int(fields[7]))
                                        if table.startswith('tcp'):
                                            row['state'] = TCP_STATES.get(int(fields[3], 16), 'UNKNOWN')
                                    row.update(type='socket', protocol=table, inode=inode,
                                               observed_owners=owners.get((namespace, inode), []))
                                else:
                                    row = parse_line(parser, line)
                                row.update(locator=f'{path}:{number}',
                                           **{'network_namespace' if kind == 'net' else 'mount_namespace': namespace},
                                           representative_pid=rep.get('pid'), representative_tid=rep.get('tid'),
                                           representative_start_ticks=rep.get('start_ticks'))
                                rows.append(row)
                            except (ValueError, IndexError, OSError) as error:
                                parse_errors += 1
                                collector.warn(f'{path}:{number}', error)
                        identity(collector, descriptor, rep, kind)
                        groups['Network Connections' if kind == 'net' else 'Device Information'].extend(rows)
                        status['tables'][table] = dict(status='partial' if parse_errors else 'observed',
                                                       source=str(path), records=len(rows), parse_errors=parse_errors,
                                                       failed_representatives=failures)
                        accepted = True
                        break
                    except (OSError, ValueError) as error:
                        failures.append(dict(source=str(path), error=str(error)))
                        collector.warn(path, error)
                    finally:
                        if descriptor is not None:
                            os.close(descriptor)
                if not accepted:
                    status['tables'][table] = dict(status='unavailable', failed_representatives=failures)
            coverage.append(status)
    return coverage


def add_candidate(candidates, kind, namespace, relative_path, **values):
    if namespace is not None:
        candidates[kind].setdefault(namespace, []).append(dict(namespace=namespace,
                                                               relative_path=str(relative_path), **values))


def discover_threads(collector, folder, process, candidates):
    """Threads may unshare mount/network namespaces independently of their leader."""
    from artifacts.live import process_stat
    try:
        names = os.listdir(folder / 'task')
    except FileNotFoundError:
        return
    except OSError as error:
        collector.warn(folder / 'task', error)
        return
    for tid in sorted((name for name in names if name.isdigit() and int(name) != process['pid']), key=int):
        check_cancelled(collector.cancelled)
        relative = f"{process['pid']}/task/{tid}"
        descriptor = None
        try:
            descriptor = os.open(collector.proc / relative, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            first = process_stat(collector.read('stat', descriptor))
            membership = {}
            for kind in ('net', 'mnt'):
                try:
                    membership[kind] = os.readlink('ns/' + kind, dir_fd=descriptor)
                except OSError as error:
                    collector.warn(collector.proc / relative / 'ns' / kind, error)
            if process_stat(collector.read('stat', descriptor))['start_ticks'] != first['start_ticks']:
                raise ValueError('Thread identity changed during namespace discovery')
            for kind, namespace in membership.items():
                add_candidate(candidates, kind, namespace, relative, pid=process['pid'], tid=int(tid),
                              start_ticks=first['start_ticks'])
        except (OSError, ValueError) as error:
            collector.warn(collector.proc / relative, error)
        finally:
            if descriptor is not None:
                os.close(descriptor)
