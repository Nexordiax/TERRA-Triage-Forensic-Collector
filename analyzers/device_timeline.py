"""Conservative temporal correlation; never attribute physical actions to a user."""
from datetime import datetime, timezone

from artifacts.parser_support import check_cancelled


def normalized_boot(value):
    return value.replace('-', '').lower() if isinstance(value, str) else value


def utc_usec(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return None
        difference = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return (difference.days * 86400 + difference.seconds) * 1000000 + difference.microseconds
    except (AttributeError, ValueError, OverflowError):
        return None


def correlate(events, sessions, cancelled=lambda: False):
    """Prefer same-boot monotonic ordering, retaining uncertain/unmatched observations."""
    result = []
    latest = {}
    for session in sessions:
        check_cancelled(cancelled)
        if session.get('session_class', 'user') not in ('user', 'user-early', 'user-light', 'user-early-light'):
            continue
        user = session.get('username') or ('uid:' + str(session['uid']) if session.get('uid') is not None else None)
        user_key = (session.get('machine_id'), user)
        timestamp = session.get('start_realtime_usec') or utc_usec(session.get('start_timestamp_utc'))
        if user and timestamp is not None:
            previous = latest.get(user_key)
            same_boot = previous and normalized_boot(previous.get('boot_id')) == normalized_boot(session.get('boot_id')) and session.get('boot_id')
            if same_boot and previous.get('start_monotonic_usec') is not None and session.get('start_monotonic_usec') is not None:
                newer = session['start_monotonic_usec'] >= previous['start_monotonic_usec']
            else:
                newer = not previous or timestamp >= (previous.get('start_realtime_usec') or utc_usec(previous.get('start_timestamp_utc')))
            if newer:
                latest[user_key] = session
    for event in events:
        check_cancelled(cancelled)
        row = dict(event, session_matches=[])
        event_boot = normalized_boot(event.get('boot_id'))
        for session in sessions:
            check_cancelled(cancelled)
            if session.get('session_class', 'user') not in ('user', 'user-early', 'user-light', 'user-early-light'):
                continue
            session_boot = normalized_boot(session.get('boot_id'))
            if event.get('machine_id') and session.get('machine_id') and event['machine_id'] != session['machine_id']:
                continue
            if event.get('machine_identity_required') and not session.get('machine_id'):
                continue
            if event_boot and session_boot and event_boot != session_boot:
                continue
            if event_boot and event_boot == session_boot and event.get('monotonic_usec') is not None and session.get('start_monotonic_usec') is not None:
                value, start, end = event['monotonic_usec'], session['start_monotonic_usec'], session.get('end_monotonic_usec')
                basis = 'same_boot_monotonic'
            else:
                value = event.get('timestamp_raw_usec') or utc_usec(event.get('timestamp_utc'))
                start = session.get('start_realtime_usec') or utc_usec(session.get('start_timestamp_utc'))
                end = session.get('end_realtime_usec') or utc_usec(session.get('end_timestamp_utc'))
                basis = 'realtime_only_clock_changes_possible'
            if value is None or start is None or value < start or (end is not None and value >= end):
                continue
            # A historical login without logout is not proof the session was open.
            relation = ('during_logind_session_lifetime' if session.get('end_semantics') else
                        'during_recorded_session' if end is not None or session.get('present_at_snapshot') else 'after_login_end_unknown')
            user = session.get('username') or ('uid:' + str(session['uid']) if session.get('uid') is not None else None)
            start_realtime = session.get('start_realtime_usec') or utc_usec(session.get('start_timestamp_utc'))
            latest_session = latest.get((session.get('machine_id'), user), {})
            if session.get('boot_id') and normalized_boot(session.get('boot_id')) == normalized_boot(latest_session.get('boot_id')) and session.get('start_monotonic_usec') is not None:
                is_latest = session['start_monotonic_usec'] == latest_session.get('start_monotonic_usec')
            else:
                is_latest = bool(user and start_realtime == (latest_session.get('start_realtime_usec') or utc_usec(latest_session.get('start_timestamp_utc'))))
            row['session_matches'].append(dict(session_id=session['session_id'], username=session.get('username'),
                uid=session.get('uid'), session_locator=session.get('locator'),
                session_source_sha256=session.get('source_sha256') or session.get('source_snapshot', {}).get('sha256'),
                session_note=session.get('note'), session_end_semantics=session.get('end_semantics'),
                boot_id=session.get('boot_id'),
                latest_recorded_login_for_user=is_latest,
                session_start_timestamp_utc=session.get('start_timestamp_utc'),
                relation=relation, ordering_basis=basis, event_clock=event.get('event_clock', 'source_timestamp'),
                timing_note='Journal reception may follow the physical event' if event.get('event_clock') == 'journal_receipt_monotonic' else None))
        row['session_scope'] = ('Temporal relation to recorded login sessions; does not identify who connected the device'
                                if row['session_matches'] else 'No supported login-session relation established')
        row['since_recorded_login'] = bool(row['session_matches'])
        row['since_latest_recorded_login_for_users'] = list(dict.fromkeys(
            match['username'] or ('uid:' + str(match['uid'])) for match in row['session_matches']
            if match['latest_recorded_login_for_user']))
        result.append(row)
    return result


def match_present_devices(devices, events, cancelled=lambda: False):
    """Require a current connect generation plus matching vendor/product and serial."""
    generations = {}
    for event in events:
        check_cancelled(cancelled)
        key = (normalized_boot(event.get('boot_id')), event.get('bus_path'))
        if event.get('action') == 'connect':
            generations[key] = dict(event, descriptors={}, evidence=[event['locator']])
        elif key in generations:
            current = generations[key]
            if event.get('action') == 'disconnect':
                generations.pop(key)
            else:
                current['evidence'].append(event['locator'])
                for field in ('idVendor', 'idProduct', 'serial', 'device_number'):
                    if field in event:
                        current['descriptors'][field] = event[field]
    result = []
    for device in devices:
        check_cancelled(cancelled)
        row = dict(device)
        key = (normalized_boot(device.get('boot_id')), device.get('bus_path'))
        generation = generations.get(key)
        if generation:
            expected = generation['descriptors']
            # Without serial, a reused port/device number is an identity candidate only.
            identity = bool(device.get('serial')) and all(expected.get(field) == device.get(field)
                                                        for field in ('idVendor', 'idProduct', 'serial'))
            number_matches = generation.get('device_number') is None or str(generation['device_number']) == device.get('devnum')
            if identity and number_matches:
                row.update(observed_connection_event=generation['locator'],
                           connection_timestamp_utc=generation.get('timestamp_utc'),
                           connection_timestamp_semantics='UTC belongs to the observed source record; journal receipt may follow the physical event',
                           connection_monotonic_usec=generation.get('monotonic_usec'),
                           session_matches=generation.get('session_matches', []),
                           since_recorded_login=generation.get('since_recorded_login', False),
                           identity_evidence=generation['evidence'],
                           connection_semantics='Present USB descriptors agree with latest observed connection generation; temporal association only')
        result.append(row)
    return result
