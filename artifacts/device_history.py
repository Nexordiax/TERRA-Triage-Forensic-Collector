"""Correlate acquired log records within each observed filesystem log root."""
import os
import re

from analyzers.device_timeline import correlate, utc_usec
from artifacts.login_devices import SESSION_START, SESSION_STOP, session_events
from artifacts.parser_support import check_cancelled, utc_time


def log_root(path):
    path = os.path.abspath(path)
    for marker in ('/var/log/', '/run/utmp'):
        if marker in path:
            return path.split(marker, 1)[0] or '/'
    return None


def first(fields, key):
    value = fields.get(key)
    return value[0] if isinstance(value, list) and value else value


def login_intervals(rows, source, cancelled):
    opened, sessions = {}, []
    for row in rows:
        check_cancelled(cancelled)
        if row.get('type') != 'login_record' or row.get('source_semantics') == 'failed login records':
            continue
        kind = row.get('record_type')
        value = utc_usec(row.get('timestamp_utc'))
        if value is None:
            continue
        key = (row.get('pid'), row.get('terminal'))
        if kind == 'user_process' and row.get('username'):
            session = dict(type='login_session', locator=source['path'] + ':' + row['locator'],
                session_id=f"{source['path']}:{row['locator']}", username=row['username'],
                leader_pid=row.get('pid'), terminal=row.get('terminal'), start_realtime_usec=value,
                start_timestamp_utc=row['timestamp_utc'], source_sha256=source['sha256'], present_at_snapshot=False)
            if key in opened:
                opened[key].update(end_realtime_usec=value, end_timestamp_utc=row['timestamp_utc'])
            opened[key] = session
            sessions.append(session)
        elif kind == 'dead_process' and key in opened:
            opened.pop(key).update(end_realtime_usec=value, end_timestamp_utc=row['timestamp_utc'])
        elif kind == 'boot_time':
            for session in opened.values():
                session.update(end_realtime_usec=value, end_timestamp_utc=row['timestamp_utc'])
            opened.clear()
    return sessions


def annotate_history(records, cancelled=lambda: False):
    """Only acquired records, no additional reads; returns replacement parsed metadata."""
    scopes = {}
    for record in records:
        check_cancelled(cancelled)
        root = log_root(record['path'])
        parsed = record.get('parsed_artifact', {})
        if root is None or record.get('generated_snapshot') or parsed.get('status') not in ('parsed', 'partial'):
            continue
        scope = scopes.setdefault(root, dict(sessions=[], events=[], journal_sessions=[], records={}, machine_ids=set()))
        scope['records'][record['id']] = record
        entries = parsed.get('entries', [])
        if parsed.get('parser') == 'utmp' and '/btmp' not in record['path']:
            scope['sessions'].extend(login_intervals(entries, record, cancelled))
        for index, row in enumerate(entries):
            check_cancelled(cancelled)
            fields = row.get('fields', {})
            boot = first(fields, '_BOOT_ID')
            machine = first(fields, '_MACHINE_ID')
            if isinstance(machine, str) and re.fullmatch(r'[0-9a-f]{32}', machine):
                scope['machine_ids'].add(machine)
            common = dict(row, locator=record['path'] + ':' + row['locator'], source_sha256=record['sha256'],
                          boot_id=row.get('boot_id') or boot, monotonic_usec=row.get('monotonic_usec'),
                          machine_id=machine, timestamp_raw_usec=row.get('timestamp_raw_usec'))
            if row.get('type') == 'device_connection_event':
                if not common.get('timestamp_utc'):
                    timestamp = utc_usec(row.get('timestamp_raw'))
                    common['timestamp_utc'] = utc_time(timestamp, 1000000) if timestamp else None
                scope['events'].append((record['id'], index, common))
            unit = first(fields, '_SYSTEMD_UNIT')
            if first(fields, 'MESSAGE_ID') in (SESSION_START, SESSION_STOP) and boot and unit == 'systemd-logind.service':
                common['fields'] = {name: first(fields, name) for name in fields}
                scope['journal_sessions'].append(common)
    updates = {}
    for root, scope in scopes.items():
        check_cancelled(cancelled)
        scope['sessions'].extend(session_events(scope['journal_sessions']))
        if len(scope['machine_ids']) == 1:
            machine = next(iter(scope['machine_ids']))
            for session in scope['sessions']:
                session.setdefault('machine_id', machine)
        elif len(scope['machine_ids']) > 1:
            for _, _, event in scope['events']:
                event['machine_identity_required'] = True
        correlated = correlate([event for _, _, event in scope['events']], scope['sessions'], cancelled)
        for (record_id, index, original), row in zip(scope['events'], correlated):
            parsed = updates.setdefault(record_id, dict(scope['records'][record_id]['parsed_artifact'],
                entries=list(scope['records'][record_id]['parsed_artifact']['entries'])))
            # Raw-source locator remains unchanged; derived links include original path/hash.
            row.update(locator=scope['records'][record_id]['parsed_artifact']['entries'][index]['locator'],
                       correlation_scope=root, source_scope='acquired_target_logs')
            parsed['entries'][index] = row
    return updates
