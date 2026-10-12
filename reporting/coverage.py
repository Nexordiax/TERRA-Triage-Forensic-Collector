"""Collection coverage, independent of whether a particular search found matches."""
from collections import Counter


def diagnostic_group(message, level):
    message = str(message).lower()
    if any(word in message for word in ('permission denied', 'not accessible', 'inaccessible', 'access denied')):
        return 'inaccessible_inputs'
    if any(word in message for word in ('changed', 'replaced', 'disappeared', 'no such file')):
        return 'changed_or_missing_inputs'
    if any(word in message for word in ('encrypted', 'credential', 'password', 'passphrase')) and level != 'info':
        return 'protected_inputs'
    if any(word in message for word in ('limit', 'bound', 'timeout', 'budget')) and level != 'info':
        return 'analysis_limits'
    if any(word in message for word in ('excluded', 'skipped', 'not scanned')):
        return 'excluded_inputs'
    if any(word in message for word in ('unsupported', 'unavailable', 'dependency')):
        return 'unsupported_or_unavailable_analysis'
    return 'other_errors' if level == 'error' else 'other_warnings' if level == 'warning' else None


def build_summary(records, diagnostics, diagnostic_count, context):
    scan = context.get('scan_summary') or {}
    stored = scan.get('coverage') or {}
    issues = dict(stored.get('diagnostic_events', {}))
    if not issues:
        issues = dict(Counter(group for entry in diagnostics
                             if (group := diagnostic_group(entry.get('message', ''), entry.get('level', '')))))
    states = Counter((row.get('parsed_artifact') or {}).get('status', 'not_requested')
                     for row in records if row.get('kind') == 'file' and not row.get('memory_image'))
    archives = stored.get('archives') or {
        'containers_analyzed': sum(bool(row.get('archive_coverage')) for row in records),
        'members_searched': sum(row.get('archive_coverage', {}).get('members_searched', 0) for row in records),
        'containers_needing_credentials': sum(bool(row.get('archive_coverage', {}).get('needs_credentials')) for row in records)}
    return dict(status=scan.get('status', 'not recorded'), partial_collection=context.get('partial_scan', False),
                targets=(context.get('targets') or {}).get('paths', []),
                files_examined=scan.get('examined'), files_completed=stored.get('files_completed'),
                files_hash_checked=scan.get('hash_checked'), hash_matches=scan.get('hash_matches'),
                exported_files=sum(row.get('kind') == 'file' and not row.get('original_bytes_unavailable') for row in records),
                original_files_unavailable=sum(bool(row.get('original_bytes_unavailable')) for row in records),
                parser_states=dict(states), archives=archives,
                skipped_nonregular_entries=stored.get('skipped_nonregular_entries', 0),
                diagnostic_events=issues, diagnostics_recorded=diagnostic_count,
                diagnostics_saved=len(diagnostics), diagnostics_omitted=max(0, diagnostic_count - len(diagnostics)),
                issue_examples=[dict(entry) for entry in diagnostics if entry.get('level') in ('warning', 'error')][:20],
                notes=['Diagnostic counts describe events, not unique inaccessible files.',
                       'No match does not mean no evidence exists in inaccessible, unsupported, encrypted or skipped inputs.',
                       'Logical file collection does not search deleted files or unallocated space.',
                       'Image and sampled-video screening require examiner review.'])


def summary_text(summary):
    lines = ['TERRA Collection Coverage Summary',
             'Status: ' + str(summary['status']).replace('_', ' '),
             'Partial collection: ' + str(summary['partial_collection']),
             'Targets: ' + ', '.join(summary['targets']),
             f"Files examined: {summary.get('files_examined')} · Completed: {summary.get('files_completed')} · Exported: {summary['exported_files']}",
             f"Files hash-checked: {summary.get('files_hash_checked')} · Hash matches: {summary.get('hash_matches')}",
             f"Archive coverage: {summary['archives']}",
             f"Original files unavailable after recovery: {summary.get('original_files_unavailable', 0)}",
             f"Parser results: {summary['parser_states']}",
             f"Nonregular filesystem entries skipped: {summary['skipped_nonregular_entries']}",
             f"Diagnostics: {summary['diagnostics_recorded']} recorded, {summary['diagnostics_saved']} saved, {summary['diagnostics_omitted']} omitted"]
    for group, count in sorted(summary['diagnostic_events'].items()):
        lines.append(group.replace('_', ' ').capitalize() + ': ' + str(count) + ' diagnostic events')
    lines.extend(['', *summary['notes']])
    if summary['issue_examples']:
        lines.append('\nExample collection issues (see logs for details):')
        lines.extend(f"[{entry.get('level')}] {entry.get('path')}: {entry.get('message')}" for entry in summary['issue_examples'])
    return '\n'.join(lines) + '\n'
