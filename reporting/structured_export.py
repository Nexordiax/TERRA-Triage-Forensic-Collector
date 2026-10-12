"""Stream portable derived records with source hashes; raw evidence is separate."""
import csv
from collections import Counter
import hashlib
import io
import json
import zipfile
from pathlib import Path
from urllib.parse import quote


def write_structured(archive, record, index, checksums, check_cancelled):
    parsed = record.get('parsed_artifact')
    if not parsed:
        return None
    base = f'terra/analysis/artifact-{index:06d}'
    entries = []
    for number, row in enumerate(parsed.get('entries', [])):
        check_cancelled()
        exported = dict(row)
        if row.get('type') in ('email_attachment', 'signal_attachment') and row.get('extraction_status') == 'extracted':
            payload = bytes.fromhex(exported.pop('payload_hex'))
            if hashlib.sha256(payload).hexdigest() != row['payload_sha256']:
                raise ValueError('Derived attachment checksum mismatch.')
            # Original names are metadata only; archive paths cannot escape their folder.
            label = Path(str(row.get('filename') or 'attachment.bin').replace('\\', '/')).name[:100]
            name = base + f'/attachments/{number:06d}-' + quote(label, safe='-_.')
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100600 << 16
            archive.writestr(info, payload)
            checksums[name] = row['payload_sha256']
            exported['payload_archive_path'] = name
        entries.append(exported)
    metadata = {key:value for key,value in parsed.items() if key != 'entries'}
    metadata['record_types'] = dict(Counter(row.get('type','unknown') for row in parsed.get('entries',[])))
    metadata.update(source_path=record['path'],source_sha256=record['sha256'])
    if record.get('source_scope'):
        metadata.update(source_scope=record['source_scope'], collection_provenance=record.get('provenance', {}))
    metadata_name = base + '/metadata.json'
    payload = json.dumps(metadata,indent=2,ensure_ascii=True).encode()
    archive.writestr(metadata_name,payload)
    checksums[metadata_name] = hashlib.sha256(payload).hexdigest()
    result = dict(metadata,metadata_path=metadata_name)
    if parsed['status'] not in ('parsed', 'partial'):
        return result
    provenance = {'artifact_id':parsed['artifact_id'],'parser':parsed['parser'],
                  'parser_version':parsed['parser_version'],'source_path':record['path'],
                  'source_sha256':record['sha256'],'inputs':parsed['inputs'],
                  'parser_status':parsed['status']}
    if record.get('source_scope'):
        provenance.update(source_scope=record['source_scope'], collection_provenance=record.get('provenance', {}))
    columns = list(dict.fromkeys(['type','locator'] + [key for row in entries for key in row]))
    for extension in ('jsonl','csv'):
        name = base + '/records.' + extension
        info = zipfile.ZipInfo(name)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100600 << 16
        digest = hashlib.sha256()
        with archive.open(info,'w',force_zip64=True) as output:
            if extension == 'csv':
                buffer = io.StringIO(newline='')
                writer = csv.DictWriter(buffer,fieldnames=['source_path','source_sha256',*columns])
                writer.writeheader()
                data = buffer.getvalue().encode()
                output.write(data)
                digest.update(data)
            for row in entries:
                check_cancelled()
                if extension == 'jsonl':
                    data = (json.dumps(dict(row,provenance=provenance),ensure_ascii=True)+'\n').encode()
                else:
                    buffer.seek(0)
                    buffer.truncate(0)
                    values = {key:json.dumps(value,ensure_ascii=True) if isinstance(value,(dict,list)) else value
                              for key,value in row.items()}
                    writer.writerow(dict(values,source_path=record['path'],source_sha256=record['sha256']))
                    data = buffer.getvalue().encode()
                output.write(data)
                digest.update(data)
        checksums[name] = digest.hexdigest()
        result[extension + '_path'] = name
    return result
