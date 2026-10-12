import hashlib
import json
import os
import re
import stat
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from urllib.parse import quote

from PySide6.QtCore import QObject, QThread, Signal, Slot, QFile
from reporting.structured_export import write_structured
from artifacts.catalog import CATALOG
from reporting.pdf_report import build_pdf_report
from reporting.html_report import build_html_report
from reporting.coverage import build_summary, summary_text
from storage.source_file import open_record_device, validate_source
from reporting.zip_metadata import evidence_info


class ExportCancelled(Exception):
    pass


def public_context(value):
    if isinstance(value, dict):
        return {key: public_context(item) for key, item in value.items() if key != '_decryption_secrets'}
    if isinstance(value, (list, tuple)):
        return [public_context(item) for item in value]
    return value


def export_basename(case=None, date=None):
    date = date or datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')
    name = (case or {}).get('name') or (case or {}).get('id') or ''
    name = re.sub(r'[^\w.-]+', '_', name, flags=re.ASCII).strip('._')[:80]
    return (name + '-' if name else '') + date


def destination_is_target(destination, targets):
    parent = os.path.realpath(os.path.dirname(os.path.abspath(destination)))
    return any(os.path.commonpath([parent, os.path.realpath(root)]) == os.path.realpath(root)
               for root in targets.get('paths', []))


class ArchivePaths:
    """Keep target hierarchies while escaping unsafe names and case collisions."""
    def __init__(self, targets, source_tree=True, volumes=None):
        self.roots = list(dict.fromkeys(os.path.abspath(root) for root in targets.get('paths', [])))
        self.names = {}
        self.used = set()
        self.source_tree = True
        if volumes is None:
            from artifacts.volume_metadata import mounted_volumes
            volumes = mounted_volumes()
        self.volumes = volumes
        self.evidence_roots = []
        self.volume_names = {}

    def component(self, parent, original):
        key = (parent, original)
        if key in self.names:
            return self.names[key]
        # Allocate the database basename first, so a portable case-collision
        # rename is shared by its SQLite sidecars regardless of scan order.
        sidecar = next((suffix for suffix in ('-wal', '-shm', '-journal') if original.endswith(suffix)), None)
        if sidecar:
            candidate = self.component(parent, original[:-len(sidecar)]) + sidecar
            if (parent, candidate.casefold()) not in self.used:
                self.used.add((parent, candidate.casefold()))
                self.names[key] = candidate
                return candidate
        name = quote(original, safe='-_.()', encoding='utf-8', errors='surrogatepass')
        if self.source_tree:
            name = ''.join(quote(char, safe='', encoding='utf-8', errors='surrogatepass')
                           if ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF or char in '<>:"/\\|?*%' else char for char in original)
        if name in ('', '.', '..'):
            name = ''.join('%2E' for _ in original) or '_'
        while name.endswith('.'):
            name = name[:-1] + '%2E'
        if name.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}:
            name = '_' + name
        candidate = name
        suffix = 0
        while (parent, candidate.casefold()) in self.used:
            suffix += 1
            candidate = f'{name}~{suffix}'
        self.used.add((parent, candidate.casefold()))
        self.names[key] = candidate
        return candidate

    def path_for(self, source, device=None):
        source = os.path.abspath(source)
        candidates = [(index, root) for index, root in enumerate(self.roots, 1)
                      if os.path.commonpath([source, root]) == root]
        if not candidates:
            raise ValueError(f'Finding is outside the selected targets: {source}')
        _, root = max(candidates, key=lambda item: len(item[1]))
        mounts = [row for row in self.volumes
                  if os.path.commonpath([source, row['mount_point']]) == row['mount_point']
                  and (device is None or row['device'] == device)]
        mount = max(mounts, key=lambda row: len(row['mount_point'])) if mounts else None
        key = (mount['device'], mount['mount_point'], mount.get('filesystem_root', '/')) if mount else ('unknown', device)
        if key not in self.volume_names:
            parent = f'evidence/volume-{len(self.volume_names) + 1:03d}'
            self.volume_names[key] = parent
            self.evidence_roots.append(dict(mount or dict(device=device, mount_point=None, filesystem_type=None,
                                                       metadata_source='unavailable; absolute source paths retained'),
                                           archive_root=parent, selected_source_roots=[]))
        parent = self.volume_names[key]
        mapping = next(row for row in self.evidence_roots if row['archive_root'] == parent)
        if root not in mapping['selected_source_roots']:
            mapping['selected_source_roots'].append(root)
        relative = os.path.relpath(source, mount['mount_point']) if mount else source.lstrip('/')
        if mount and mount.get('filesystem_root', '/') != '/':
            relative = mount['filesystem_root'].lstrip('/') + '/' + relative
        for part in Path(relative).parts:
            if part in ('..', ''):
                raise ValueError('Unsafe source path.')
            parent += '/' + self.component(parent, part)
        return parent


class ZipExporter:
    def __init__(self, records, diagnostics, diagnostic_count, context, cancel=None, progress=None):
        self.records = ([record for record in records if not record.get('memory_image')]
                        if context.get('exclude_memory_images') else records)
        self.diagnostics = diagnostics
        self.diagnostic_count = diagnostic_count
        # Local examiner passwords/keys are configuration only, never provenance.
        self.context = public_context(context)
        self.cancel = cancel if cancel is not None else Event()
        self.progress = progress or (lambda value: None)

    def check_cancelled(self):
        if self.cancel.is_set():
            raise ExportCancelled()

    def save(self, destination, allow_target=False):
        destination = Path(os.path.abspath(destination))
        if destination.suffix.lower() != '.zip':
            raise ValueError('Choose a ZIP filename ending in .zip.')
        if not destination.parent.is_dir():
            raise ValueError('Destination folder does not exist.')
        targets = self.context.get('targets') or {'paths': []}
        if destination_is_target(str(destination), targets) and not allow_target:
            raise ValueError('Destination is on an examined target. Explicitly acknowledge this write or choose another destination.')
        for record in self.records:
            if os.path.realpath(destination) == os.path.realpath(record['path']):
                raise ValueError('The archive destination cannot replace an evidence source file.')
        self.check_cancelled()
        reserved = None
        temporary = None
        published = False
        try:
            # Reserve the new name exclusively; never overwrite an existing file.
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            reserved = os.fstat(descriptor)
            os.close(descriptor)
            descriptor, temporary = tempfile.mkstemp(prefix='.terra-export-', suffix='.part', dir=destination.parent)
            os.close(descriptor)
            result = self.write_archive(temporary)
            self.verify_archive(temporary, result.pop('checksums'))
            self.check_cancelled()
            digest = hashlib.sha256()
            hashed = 0
            last_update = 0
            archive_size = os.stat(temporary).st_size
            with open(temporary, 'rb') as source:
                while chunk := source.read(1024 * 1024):
                    self.check_cancelled()
                    digest.update(chunk)
                    hashed += len(chunk)
                    now = time.monotonic()
                    if now - last_update >= 0.2:
                        self.progress({'phase': 'Hashing ZIP', 'done': int(hashed * 1000 / max(1, archive_size)),
                                       'total': 1000, 'path': f'{hashed / 1048576:.1f} / {archive_size / 1048576:.1f} MiB'})
                        last_update = now
                os.fsync(source.fileno())
            current = os.stat(destination, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (reserved.st_dev, reserved.st_ino):
                raise OSError('Destination changed during export; it was not overwritten.')
            os.replace(temporary, destination)
            temporary = None
            published = True
            return dict(result, coverage_summary=build_summary(self.records, self.diagnostics, self.diagnostic_count, self.context), path=str(destination), archive_sha256=digest.hexdigest(), status='saved')
        finally:
            if temporary:
                Path(temporary).unlink(missing_ok=True)
            if reserved and not published:
                try:
                    current = os.stat(destination, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (reserved.st_dev, reserved.st_ino):
                        destination.unlink()
                except FileNotFoundError:
                    pass

    def write_archive(self, filename):
        paths = ArchivePaths(self.context.get('targets') or {'paths': []}, volumes=(self.context.get('scan_summary') or {}).get('volume_metadata'))
        entries = []
        latest_sources = {row['path']: index for index, row in enumerate(self.records)}
        checksums = {}
        with zipfile.ZipFile(filename, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
            for index, record in enumerate(self.records):
                self.check_cancelled()
                self.progress({'phase': 'Exporting', 'done': index, 'total': len(self.records), 'path': record['path']})
                entry = {key: value for key, value in record.items() if key not in ('data', 'path', 'content_retained', 'retention_reason', 'parsed_artifact')}
                entry['source_path'] = record['path']
                entry['archive_path'] = None
                if record['kind'] == 'directory':
                    entry['export_status'] = 'directory_metadata'
                elif record.get('original_bytes_unavailable'):
                    entry['export_status'] = 'original_bytes_unavailable'
                    entry['export_error'] = 'Original bytes were not cached and the source changed or disappeared after recovery. Earlier metadata and derived findings are preserved.'
                else:
                    name = ('terra/memory/' + paths.component('terra/memory', Path(record['path']).name)
                            if record.get('memory_image') else
                            'terra/live/' + paths.component('terra/live', Path(record['path']).name)
                            if record.get('generated_snapshot') else paths.path_for(record['path'], record.get('device')))
                    if latest_sources[record['path']] != index:
                        name = f'terra/evidence-versions/artifact-{index:06d}/' + name
                    try:
                        device, _ = open_record_device(record)
                        digest = hashlib.sha256()
                        size = 0
                        last_update = 0
                        try:
                            info = evidence_info(name, record)
                            with archive.open(info, 'w', force_zip64=True) as output:
                                while not device.atEnd():
                                    self.check_cancelled()
                                    chunk = bytes(device.read(1024 * 1024))
                                    if not chunk:
                                        raise OSError('Source read failed before reaching the end of the file.')
                                    output.write(chunk)
                                    digest.update(chunk)
                                    size += len(chunk)
                                    now = time.monotonic()
                                    if now - last_update >= 0.2:
                                        self.progress({'phase': 'Exporting', 'done': index, 'total': len(self.records),
                                                       'path': f"{record['path']} · {size / 1048576:.1f} / {record['size'] / 1048576:.1f} MiB"})
                                        last_update = now
                                if isinstance(device, QFile):
                                    validate_source(record, device.handle())
                            if size != record['size'] or digest.hexdigest() != record['sha256']:
                                raise ValueError('Exported bytes differ from the file verified during scanning.')
                        finally:
                            device.close()
                    except (OSError, ValueError) as error:
                        raise ValueError(f"Cannot export {record['path']}: {error}") from error
                    entry['archive_path'] = name
                    entry['export_status'] = 'exported'
                    entry['export_source'] = 'scan_copy' if record.get('content_retained', True) else 'verified_source_file'
                    checksums[name] = digest.hexdigest()
                parsed = write_structured(archive, record, index, checksums, self.check_cancelled)
                if parsed:
                    entry['parsed_artifact'] = parsed
                entries.append(entry)
            now = datetime.now(timezone.utc).isoformat()
            file_count = sum(entry['export_status'] == 'exported' for entry in entries)
            manifest = dict(self.context, format='terra-logical-export', format_version=2, export_layout='volume_source_tree',
                            exported_at=now, entries=entries, file_count=file_count,
                            directory_count=sum(entry['kind'] == 'directory' for entry in entries),
                            diagnostic_count=self.diagnostic_count,
                            diagnostics_saved=len(self.diagnostics))
            manifest['coverage_summary'] = build_summary(self.records, self.diagnostics, self.diagnostic_count, self.context)
            manifest['coverage_summary_paths'] = ['terra/reports/collection-summary.txt', 'terra/reports/collection-summary.json']
            manifest['evidence_roots'] = paths.evidence_roots
            manifest['timestamp_policy'] = dict(dos_time='UTC, two-second precision, 1980–2107 range',
                extended_timestamp='0x5455 UTC modification time where representable',
                ntfs_timestamp='0x000A UTC modification/access/birth times, 100ns precision; zero means unavailable',
                posix_ctime='Metadata/status change time in manifest only; never creation time',
                exact_values='Source nanosecond timestamps remain in manifest entries')
            scan_date = next((record['acquired_at'][:10] for record in self.records if record.get('acquired_at')), now[:10])
            report_name = export_basename(self.context.get('case'), scan_date) + '-Report.pdf'
            manifest['report_path'] = 'terra/reports/' + report_name
            manifest['html_report_path'] = 'terra/reports/' + report_name.removesuffix('.pdf') + '.html'
            payloads = {
                'terra/reports/collection-summary.txt': summary_text(manifest['coverage_summary']).encode('utf-8'),
                'terra/reports/collection-summary.json': json.dumps(manifest['coverage_summary'], indent=2, ensure_ascii=True).encode('utf-8'),
                'terra/analysis/linux-artifact-catalog.json': json.dumps(CATALOG,indent=2,ensure_ascii=True).encode(),
                'terra/manifest.json': json.dumps(manifest, indent=2, ensure_ascii=True).encode('utf-8'),
                'terra/logs/diagnostics.log': ''.join(f"{entry.get('time', '')} [{entry.get('level', '')}] {entry.get('path', '')}: {entry.get('message', '')}\n" for entry in self.diagnostics).encode('utf-8'),
                'terra/logs/diagnostics.jsonl': ''.join(json.dumps(entry, ensure_ascii=True) + '\n' for entry in self.diagnostics).encode('utf-8'),
                manifest['report_path']: build_pdf_report(manifest),
                manifest['html_report_path']: build_html_report(manifest),
                'terra/README.txt': (
                    'TERRA logical file export\n\n'
                    'evidence/volume-NNN/ preserves original paths relative to each source filesystem root.\n'
                    'terra/manifest.json maps volume directories to device, mount point, filesystem and selected source folders.\n'
                    'Target paths and original filenames are recorded in terra/manifest.json.\n'
                    'Unsafe or conflicting filenames are escaped for portable extraction.\n'
                    'Files contain the unchanged bytes verified during scanning.\n'
                    'Extract evidence/ and import its folders as logical files in your analysis tool.\n'
                    'This ZIP is not a disk image. If acquired, terra/memory/ contains a physical RAM LiME stream (possibly stopped/truncated) or a partial process-memory ZIP. Consult acquisition metadata for completeness.\n'
                    'LiME is a physical image. A process-memory ZIP contains raw virtual regions and a manifest; it is not a full RAM image.\n'
                    'terra/manifest.json records exact source timestamps, categories, matches, and SHA-256.\n'
                    'terra/analysis/ contains derived JSONL/CSV records, parser metadata, and the sourced Linux catalog.\n'
                    'terra/live/ contains generated snapshots of the running collector host, not files from offline targets.\n'
                    'Live snapshots include collection times, host, scope and limitations; their hashes verify snapshot bytes.\n'
                    'Derived records reference original input hashes and locators; raw files remain in evidence/.\n'
                    'terra/reports/ contains the PDF and offline HTML reports; terra/logs/ contains retained diagnostics.\n'
                    'terra/checksums.sha256 covers every member except the checksum list itself.\n'
                ).encode('utf-8'),
                'terra/IMPORT.txt': (
                    'TERRA logical evidence: extract the ZIP to an examiner working location.\n'
                    'AXIOM Process: Evidence sources > Computer > Linux > Load evidence > Image; open this ZIP and select evidence/volume-NNN folders. Alternatively, extract and use Files and folders.\n'
                    'AXIOM also documents ZIP archive input via Load evidence > Image; select the evidence directories for processing. The extracted-folder workflow is the portable alternative.\n'
                    'Add each evidence/volume-NNN directory and select relevant artifact processing options.\n'
                    'Autopsy: Add Data Source > Logical Files > Local files and folders; add the evidence directories.\n'
                    'Original files and browser/database companions remain together. The source_tree layout preserves original filesystem paths beneath each volume root.\n'
                    'Use terra/manifest.json for original paths, exact timestamps and escaped/colliding filename mappings.\n'
                    'Reports, logs and derived analysis are separate from the original evidence directories.\n'
                    'terra/reports/collection-summary.txt and .json describe search coverage and recorded limitations.\n'
                    'Earlier cached source versions recovered after a change are under terra/evidence-versions/. Original bytes unavailable after recovery are identified in the manifest and are not exported as files.\n'
                    'This is a selected logical collection, not E01/RAW/L01 or an AXIOM case database.\n'
                    'Artifact decoding depends on the analysis tool, version, selected artifacts and available keys.\n'
                    'Reference: https://www.magnetforensics.com/docs/axiom-cyber/html/Content/Resources/PDFs/Magnet%20AXIOM%20Cyber%20User%20Guide.pdf\n'
                    'Reference: https://sleuthkit.org/autopsy/docs/user-docs/4.22.0/ds_page.html\n'
                ).encode('utf-8'),
            }
            for name, payload in payloads.items():
                self.check_cancelled()
                archive.writestr(name, payload)
                checksums[name] = hashlib.sha256(payload).hexdigest()
            checksum_data = ''.join(f'{digest}  {name}\n' for name, digest in checksums.items()).encode('utf-8')
            archive.writestr('terra/checksums.sha256', checksum_data)
            checksums['terra/checksums.sha256'] = hashlib.sha256(checksum_data).hexdigest()
        return {'file_count': file_count, 'directory_count': sum(entry['kind'] == 'directory' for entry in entries), 'checksums': checksums}

    def verify_archive(self, filename, checksums):
        with zipfile.ZipFile(filename, 'r') as archive:
            if set(archive.namelist()) != set(checksums):
                raise ValueError('Archive member verification failed.')
            for index, (name, expected) in enumerate(checksums.items()):
                self.check_cancelled()
                self.progress({'phase': 'Verifying ZIP', 'done': index, 'total': len(checksums), 'path': name})
                digest = hashlib.sha256()
                read = 0
                last_update = 0
                total_bytes = archive.getinfo(name).file_size
                with archive.open(name) as source:
                    while chunk := source.read(1024 * 1024):
                        self.check_cancelled()
                        digest.update(chunk)
                        read += len(chunk)
                        now = time.monotonic()
                        if now - last_update >= 0.2:
                            self.progress({'phase': 'Verifying ZIP', 'done': index, 'total': len(checksums),
                                           'path': f'{name} · {read / 1048576:.1f} / {total_bytes / 1048576:.1f} MiB'})
                            last_update = now
                if digest.hexdigest() != expected:
                    raise ValueError(f'Archive SHA-256 verification failed: {name}')


class ExportWorker(QThread):
    progress = Signal(dict)

    def __init__(self, exporter, destination, allow_target, parent=None):
        super().__init__(parent)
        self.exporter = exporter
        self.destination = destination
        self.allow_target = allow_target
        self.result = None
        exporter.progress = self.progress.emit

    def run(self):
        try:
            self.result = self.exporter.save(self.destination, self.allow_target)
        except ExportCancelled:
            self.result = {'status': 'cancelled', 'error': 'Export cancelled. No completed archive was saved.'}
        except Exception as error:
            self.result = {'status': 'failed', 'error': str(error)}


class ExportController(QObject):
    progress = Signal(dict)
    completed = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None

    @property
    def running(self):
        return self.worker is not None

    def start(self, destination, store, context, allow_target=False):
        if self.running:
            raise RuntimeError('An export is already running.')
        records, diagnostics, count = store.snapshot()
        exporter = ZipExporter(records, diagnostics, count, context)
        self.worker = ExportWorker(exporter, destination, allow_target, self)
        self.worker.progress.connect(self.progress)
        self.worker.finished.connect(self._finished)
        self.worker.start()

    def stop(self):
        if self.worker:
            self.worker.exporter.cancel.set()

    @Slot()
    def _finished(self):
        worker = self.worker
        self.worker = None
        self.completed.emit(worker.result)
        worker.deleteLater()
