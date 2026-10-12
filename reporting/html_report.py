"""Self-contained offline HTML report; source strings are rendered as text."""
import html


def report_body(manifest):
    """Shared report contents for PDF and HTML exports."""
    def escape(value):
        return html.escape(str(value).encode('utf-8', errors='backslashreplace').decode('utf-8'))

    case = manifest.get('case') or {}
    sections = ['<h1>TERRA Triage Report</h1>',
                f"<p>Exported: {escape(manifest['exported_at'])}<br>Case: {escape(case.get('name') or 'Quick triage')}<br>",
                f"Case ID: {escape(case.get('id', ''))}<br>Examiner: {escape(case.get('examiner', ''))}</p>",
                f"<p>{escape(manifest['file_count'])} files exported. {escape(manifest['directory_count'])} folder-name findings recorded.</p>",
                '<p>This is a logical file export. Deleted files, unallocated space, and a disk image are not included. RAM captures, when included under terra/memory/, have separate acquisition scope and completeness metadata.</p>']
    sections.append(f"<p>Scan status: {escape((manifest.get('scan_summary') or {}).get('status', 'not recorded'))}<br>Partial collection: {escape(manifest.get('partial_scan', False))}</p>")
    if manifest.get('exclude_memory_images') and manifest.get('memory_acquisition'):
        memory = (manifest['memory_acquisition'].get('record') or {})
        sections.append(f"<p>RAM is saved separately and is not duplicated in this triage ZIP.<br>RAM path: {escape(memory.get('path', 'not acquired'))}<br>RAM SHA-256: {escape(memory.get('sha256', ''))}<br>Complete physical RAM: {escape(memory.get('complete_physical_ram', False))}</p>")
    if manifest.get('coverage_summary'):
        from reporting.coverage import summary_text
        sections.append('<h2>Collection coverage</h2><pre>' + escape(summary_text(manifest['coverage_summary'])) + '</pre>')
    for entry in manifest['entries']:
        sections.append(f"<h3>{escape(entry['category'])}: {escape(entry['source_path'])}</h3>")
        if entry.get('source_scope') == 'live_host':
            sections.append(f"<p>Scope: running collector host metadata snapshot<br>Collection provenance: {escape(entry.get('provenance', {}))}</p>")
        sections.append(f"<p>Type: {escape(entry['kind'])}<br>Status: {escape(entry['export_status'])}<br>Size: {escape(entry['size'])} bytes<br>ZIP path: {escape(entry.get('archive_path') or 'Folder metadata only')}<br>SHA-256: {escape(entry.get('sha256', ''))}<br>Matches: {escape(entry['matches'])}</p>")
    for entry in manifest['entries']:
        parsed = entry.get('parsed_artifact')
        if parsed:
            sections.append(f"<p>Structured artifact: {escape(parsed['artifact_id'])}<br>Parser: {escape(parsed['parser'])} v{escape(parsed['parser_version'])}<br>Status: {escape(parsed['status'])}<br>Records: {escape(parsed['record_count'])}<br>Record types: {escape(parsed.get('record_types', {}))}<br>Analysis metadata: {escape(parsed['metadata_path'])}<br>Limitations: {escape(parsed.get('limitations', []))}<br>Parser error: {escape(parsed.get('error', ''))}</p>")
    sections.append(f"<p>Diagnostics recorded: {escape(manifest['diagnostic_count'])}. See terra/logs/diagnostics.jsonl in the archive.</p>")
    return ''.join(sections)


def build_html_report(manifest):
    document = ("<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width, initial-scale=1'>"
                "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
                "<title>TERRA Triage Report</title><style>"
                "body{background:#303030;color:#ededed;font:16px/1.6 sans-serif;max-width:1100px;margin:2rem auto;padding:0 1.5rem;}"
                "h1,h2,h3{color:#fff;}h3{border-top:1px solid #666;padding-top:1rem;}"
                "p,pre,h3{overflow-wrap:anywhere;}pre{white-space:pre-wrap;background:#3d3d3d;padding:1rem;}"
                "@media print{body{background:white;color:black;margin:0;max-width:none;}h1,h2,h3{color:black;}pre{background:#eee;}}"
                "</style></head><body>" + report_body(manifest) + "</body></html>\n")
    return document.encode('utf-8')
