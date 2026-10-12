import os
import stat
import time
import hashlib
import json
from datetime import datetime, timezone
from threading import Event

from PySide6.QtCore import QObject, QThread, Signal, Slot, Qt
from analyzers.matching.hash_matcher import HashMatcher
from analyzers.matching.keyword_matcher import KeywordMatcher
from artifacts.file_collector import FileCollector, CollectionCancelled
from artifacts.registry import category_for
from artifacts.catalog import definition_for, source_links
from artifacts.parsing import parse_artifact
from artifacts.live import LiveCollector, snapshot_bytes
from artifacts.encrypted import detect, header_limit, EntropySample, candidate, subgroup, SOURCES as ENCRYPTION_SOURCES
from artifacts.encrypted_volumes import collect as encrypted_volumes, SOURCES as VOLUME_SOURCES
from artifacts.device_history import annotate_history
from analyzers.content import analyze as analyze_content, eligible as content_eligible
from storage.memory_store import MemoryStore, MemoryLimitError
from controllers.scan_scheduler import ReadQueue, select_workers, select_analysis_workers
from artifacts.archive_credentials import ArchiveCredentials
from analyzers.containers import ARCHIVES, OFFICE
from pathlib import Path
from reporting.coverage import diagnostic_group


class ScanEngine:
    """Synchronous collection core; the GUI runs it on a worker thread."""
    excluded_roots = ('/proc', '/sys', '/dev', '/run')

    def __init__(self, targets, configuration, store, cancel=None, on_finding=None,
                 on_progress=None, on_diagnostic=None, collector=None):
        self.targets = targets
        self.configuration = configuration
        self.store = store
        self.cancel = cancel if cancel is not None else Event()
        self.on_finding = on_finding or (lambda record: None)
        self.on_progress = on_progress or (lambda progress: None)
        self.on_diagnostic = on_diagnostic or (lambda diagnostic: None)
        self.collector = collector or FileCollector()
        self.read_workers = select_workers(targets.get('paths', []), configuration.get('scan_workers'))
        self.analysis_workers = select_analysis_workers(configuration.get('analysis_workers'))
        if collector is not None and 'scan_workers' not in configuration:
            self.read_workers = 1  # Custom collectors retain their existing serial contract.
        if collector is not None and 'analysis_workers' not in configuration:
            self.analysis_workers = 1
        # Warm-cache benchmarks show thread overhead dominates small-file reads.
        # Explicit backend overrides remain useful for validation and tuning.
        self.parallel_min_bytes = 0 if 'scan_workers' in configuration else 1024 * 1024
        self.counts = {'examined': 0, 'collected': 0, 'findings': 0,
                       'hash_checked': 0, 'hash_matches': 0, 'errors': 0,
                       'parsed_records': 0, 'parsed_files': 0, 'partial_parsed_files': 0, 'parser_failures': 0}
        self.current_file_bytes = 0
        self.current_file_size = 0
        self.visited = set()
        self.finished_paths = set()
        self.finished_identities = {}
        self.completed_since_checkpoint = set()
        self.invalidated_completed = set()
        self.target_identities = {}
        from artifacts.volume_metadata import mounted_volumes
        self.volume_metadata = mounted_volumes()
        self.recovery = None
        self.recovery_context = {}
        self.restored_session = False
        self.last_summary = None
        self.finished_directories = set()
        self.resume_count = 0
        self.live_finished = False
        self.volumes_finished = False
        self.supporting_collected = set()
        self.last_progress = 0
        self.archive_credentials = ArchiveCredentials()
        self.locked_archives = {}
        self.archive_retry = False
        self.credential_limit_logged = False
        self.coverage_issues = {}
        self.skipped_nonregular_entries = 0
        self.archive_coverage = {}
        self.analysis_bytes = 0
        self.analysis_max_bytes = 64 * 1024 * 1024
        self.options = configuration['options']
        self.keywords = KeywordMatcher(configuration['keywords'])
        self.ocr_keywords = KeywordMatcher(configuration.get('ocr_keywords', []))
        self.hashes = HashMatcher(configuration['hashes'] if self.options['hash_matches'] else [])
        self.references = {os.path.realpath(path) for key in ('hash_files', 'keyword_files', 'ocr_files', 'image_files')
                           for path in configuration.get(key, [])}
        self.references.update(os.path.realpath(path) for path in targets.get('excluded_files', []))
        recovery_path = configuration.get('recovery', {}).get('path')
        if recovery_path:
            self.references.update(os.path.realpath(recovery_path + suffix) for suffix in ('', '-journal', '-wal', '-shm'))

    def log(self, path, message, level='error'):
        entry = {'time': datetime.now(timezone.utc).isoformat(), 'path': str(path),
                 'message': str(message), 'level': level}
        group = diagnostic_group(message, level)
        if group:
            self.coverage_issues[group] = self.coverage_issues.get(group, 0) + 1
        self.store.log(entry)
        if level == 'error':
            self.counts['errors'] += 1
        if self.store.diagnostic_count <= 10000:
            self.on_diagnostic(entry)

    def progress(self, path, force=False):
        now = time.monotonic()
        if force or now - self.last_progress >= 0.1:
            self.last_progress = now
            self.on_progress(dict(self.counts, path=path, bytes_used=self.store.bytes_used,
                                  file_bytes_read=self.current_file_bytes, file_size=self.current_file_size))

    def add(self, metadata, data=b''):
        if self.cancel.is_set():
            raise CollectionCancelled()
        if metadata.get('kind') == 'directory' and metadata['path'] in self.finished_directories:
            return
        self.discover_archive_credentials(metadata, data)
        if self.archive_retry:
            existing = next((row for row in self.store.records if row['path'] == metadata['path'] and row.get('sha256') == metadata.get('sha256')), None)
            if existing:
                record = self.store.replace(existing['id'], dict(metadata, acquired_at=existing['acquired_at']), data)
                self.on_finding(record)
                return
        record = self.store.add(dict(metadata, acquired_at=datetime.now(timezone.utc).isoformat()), data)
        if metadata.get('kind') == 'directory':
            self.finished_directories.add(metadata['path'])
        self.counts['findings'] += 1
        self.counts['collected'] += 1
        self.on_finding(record)

    def excluded(self, path):
        roots = self.excluded_roots + tuple(os.path.abspath(root) for root in self.targets.get('excluded_directories', []))
        return any(path == root or path.startswith(root + '/') for root in roots)

    def run(self):
        status = 'completed'
        try:
            if not self.targets.get('paths'):
                raise ValueError('No target paths were selected.')
            self.prepare_recovery()
            if self.restored_session:
                self.validate_recovered_sources()
            if self.options['hash_matches']:
                self.log('Hash matching', f"Loaded {len(self.hashes.hashes)} unique file hashes; algorithms: {', '.join(sorted(self.hashes.names)) or 'none'}.", 'info')
            if self.targets.get('collect_live', False) and not self.live_finished:
                self.collect_live()
                self.live_finished = True
            if self.configuration['collection_mode'] == 'all_supported' and not self.volumes_finished:
                self.collect_encrypted_volumes()
                self.volumes_finished = True
            for root in dict.fromkeys(os.path.abspath(path) for path in self.targets['paths']):
                if self.cancel.is_set():
                    raise CollectionCancelled()
                if self.excluded(root):
                    self.log(root, 'Pseudo-filesystem or runtime directory excluded; not scanned.', 'warning')
                    continue
                try:
                    root_stat = os.stat(root, follow_symlinks=False)
                    if not stat.S_ISDIR(root_stat.st_mode):
                        raise ValueError('Target must be a directory and cannot be a symbolic link.')
                    self.walk(root, root_stat.st_dev)
                except (OSError, ValueError) as error:
                    self.log(root, error)
            self.retry_locked_archives()
            self.progress('Correlating acquired device events with login sessions', force=True)
            self.store.annotate_parsed(annotate_history(self.store.records, self.cancel.is_set))
        except CollectionCancelled:
            status = 'stopped'
        except MemoryLimitError as error:
            self.log('RAM storage', error)
            status = 'memory_limit'
        except Exception as error:
            self.log('Scan', error)
            status = 'failed'
        if status == 'completed' and self.cancel.is_set():
            status = 'stopped'
        if status == 'completed' and self.counts['errors']:
            status = 'completed_with_errors'
        if self.options['hash_matches']:
            self.log('Hash matching', f"Hash comparison finished: {self.counts['hash_checked']} files checked against {len(self.hashes.hashes)} reference hashes; {self.counts['hash_matches']} matching files (including contained members).",
                     'warning' if self.counts['hash_checked'] == 0 else 'info')
        self.progress('', force=True)
        summary = dict(self.counts, status=status, resume_count=self.resume_count, bytes_used=self.store.bytes_used,
                       diagnostic_count=self.store.diagnostic_count, coverage=self.coverage_summary(),
                       volume_metadata=self.volume_metadata)
        self.last_summary = summary
        self.checkpoint(summary, force=True)
        summary.update(errors=self.counts['errors'], diagnostic_count=self.store.diagnostic_count, coverage=self.coverage_summary())
        if summary['status'] == 'completed' and summary['errors']:
            summary['status'] = 'completed_with_errors'
        return summary

    def prepare_recovery(self):
        options = self.configuration.get('recovery') or {}
        if not options.get('path'):
            return
        from storage.recovery import RecoverySession, identity
        from controllers.export_controller import destination_is_target
        if destination_is_target(options['path'], self.targets) and not options.get('allow_target'):
            if self.recovery:
                self.recovery.blocked = True
                self.log(options['path'], 'Recovery destination is within an examined target. Acknowledge the progress write before resuming.', 'warning')
                raise CollectionCancelled()
            raise ValueError('Recovery destination is on an examined target; explicit acknowledgement is required.')
        if self.recovery:
            self.recovery.blocked = False
            return
        self.target_identities = {path: {key:value for key,value in identity(path).items() if key in ('device','inode')}
                                  for path in self.targets['paths']}
        self.recovery = RecoverySession(options['path'], self.recovery_context).create()
        self.log(options['path'], 'Recovery enabled at the explicitly selected destination. Evidence copies and progress are saved there.', 'info')
        self.checkpoint(force=True)

    def checkpoint(self, summary=None, force=False):
        if self.recovery is None or self.recovery.failed:
            return
        try:
            self.recovery.save(self, summary, force)
        except Exception as error:
            self.recovery.failed = True
            self.log(self.recovery.path, 'Recovery checkpoint failed; collection continues in RAM. Last committed progress may still be recoverable: ' + str(error))

    def validate_recovered_sources(self):
        from storage.recovery import identity
        for path, expected in self.target_identities.items():
            try:
                actual = identity(path)
                if any(actual[key] != value for key, value in expected.items()):
                    raise ValueError('Target device or root directory was replaced')
            except (OSError, ValueError) as error:
                self.log(path, 'Cannot resume this target: ' + str(error) + '. Restore the original target and try Resume again.', 'warning')
                raise CollectionCancelled() from error
        for path in list(self.finished_paths):
            if self.cancel.is_set(): raise CollectionCancelled()
            try:
                changed = identity(path) != self.finished_identities[path]
            except OSError:
                changed = True
            if changed:
                self.finished_paths.remove(path)
                self.supporting_collected.discard(path)
                self.invalidated_completed.add(path)
                for record in self.store.records:
                    if record['path'] == path:
                        record['recovery_source_changed'] = True
                        if not record.get('content_retained', True): record['original_bytes_unavailable'] = True
                        self.store.record_versions[record['id']] += 1
                self.log(path, 'Source changed or disappeared since checkpoint. Earlier findings retained; current files will be searched again.', 'warning')
        for provenance in getattr(self, 'restored_credential_sources', []):
            path = provenance.get('source_path', '')
            if not any(os.path.commonpath((os.path.abspath(path), os.path.abspath(root))) == os.path.abspath(root) for root in self.targets['paths']):
                continue
            try:
                if os.stat(path, follow_symlinks=False).st_size > 1024 * 1024: continue
                data, metadata = self.collector.collect(path, self.cancel.is_set, retention_limit=1024 * 1024)
                if metadata['sha256'] == provenance.get('source_sha256'):
                    self.discover_archive_credentials(dict(metadata, path=path), data)
            except (OSError, ValueError):
                self.log(path, 'Discovered credential source unavailable or changed after recovery; candidate not reused.', 'warning')
        self.restored_session = False

    def discover_archive_credentials(self, metadata, data=b''):
        self.archive_credentials.inspect(metadata, data)
        if self.archive_credentials.limit_reached and not self.credential_limit_logged:
            self.credential_limit_logged = True
            self.log(metadata['path'], 'Archive credential candidate limit reached (32); additional discovered candidates are not tried.', 'warning')

    def coverage_summary(self):
        return dict(files_completed=len(self.finished_paths),
                    skipped_nonregular_entries=self.skipped_nonregular_entries,
                    diagnostic_events=dict(self.coverage_issues),
                    archives=dict(containers_analyzed=len(self.archive_coverage),
                                  members_searched=sum(row.get('members_searched', 0) for row in self.archive_coverage.values()),
                                  expanded_bytes_searched=sum(row.get('expanded_bytes_searched', 0) for row in self.archive_coverage.values()),
                                  containers_needing_credentials=sum(bool(row.get('needs_credentials')) for row in self.archive_coverage.values())))

    def retry_locked_archives(self):
        if not self.archive_credentials.values or not self.locked_archives:
            return
        self.archive_retry = True
        try:
            for path, expected in list(self.locked_archives.items()):
                if self.cancel.is_set():
                    raise CollectionCancelled()
                self.progress('Retrying encrypted archive with discovered credentials: ' + path, force=True)
                try:
                    acquired = self.read_file(path, None, self.store.remaining_bytes, self.cancel.is_set)
                    if acquired is False or any(acquired[3][key] != value for key, value in expected.items()):
                        self.log(path, 'Encrypted archive changed since acquisition; retry results discarded.', 'warning')
                        continue
                    examined, checked = self.counts['examined'], self.counts['hash_checked']
                    self._scan_file(path, None, acquired)
                    self.counts['examined'], self.counts['hash_checked'] = examined, checked
                except (OSError, ValueError) as error:
                    self.log(path, error, 'warning')
            records = self.store.records
            self.counts['findings'] = self.counts['collected'] = len(records)
            self.counts['hash_matches'] = sum(bool(row.get('matches', {}).get('hashes')) + len(row.get('matches', {}).get('archive_hashes', [])) for row in records)
            self.counts['parsed_records'] = sum((row.get('parsed_artifact') or {}).get('record_count', 0) for row in records)
        finally:
            self.archive_retry = False

    def collect_live(self):
        self.progress('Collecting live Linux state', force=True)
        groups, provenance = LiveCollector(cancelled=self.cancel.is_set, diagnostic=self.log,
                                          progress=self.progress).collect()
        for category, entries in groups.items():
            if any(row.get('generated_snapshot') and row['category'] == category for row in self.store.records):
                continue
            matches = {}
            if self.configuration['collection_mode'] != 'all_supported':
                selected = []
                for row in entries:
                    check = {}
                    if self.options['file_names']:
                        names = self.keywords.match_name(os.path.basename(row.get('exe', row.get('target', row.get('mapped_path', '')))))
                        if names:
                            check['file_names'] = names
                    if self.options['file_contents']:
                        contents = self.keywords.match_content(snapshot_bytes([row], {}))
                        if contents:
                            check['file_contents'] = contents
                    if check:
                        selected.append(row)
                        for key, values in check.items():
                            matches[key] = list(dict.fromkeys(matches.get(key, []) + values))
                entries = selected
            if not entries:
                continue
            data = snapshot_bytes(entries, provenance)
            digest = hashlib.sha256(data).hexdigest()
            parsed = dict(artifact_id='live_' + category.lower().replace(' ', '_'),
                          parser='linux_live', parser_version=1, status='parsed',
                          entries=entries, record_count=len(entries), sources=provenance['sources'],
                          limitations=provenance['limitations'], inputs=[])
            self.add(dict(path='live://' + category.lower().replace(' ', '-') + '.json',
                          category=category, kind='file', generated_snapshot=True,
                          source_scope='live_host', provenance=provenance, content_retained=True,
                          size=len(data), sha256=digest, calculated_hashes={'sha256': digest},
                          matches=matches, parsed_artifact=parsed,
                          collection='RAM-resident live host metadata snapshot; not a target file'), data)
            self.counts['parsed_files'] += 1
            self.counts['parsed_records'] += len(entries)
            self.progress(category, force=True)

    def collect_encrypted_volumes(self):
        rows = encrypted_volumes(self.targets, self.cancel.is_set, self.log)
        for format_name in sorted({row['format'] for row in rows}):
            entries = [row for row in rows if row['format'] == format_name]
            data = snapshot_bytes(entries, {'sources': VOLUME_SOURCES})
            digest = hashlib.sha256(data).hexdigest()
            self.add(dict(path='live://encrypted-volumes/' + format_name + '.json',
                          category='Encrypted Containers', category_subgroups={'Encrypted Containers': format_name},
                          kind='file', generated_snapshot=True, source_scope='selected_mounted_volume_metadata',
                          content_retained=True, size=len(data), sha256=digest, calculated_hashes={'sha256': digest}, matches={},
                          collection='RAM-resident mounted-volume metadata; not a disk image',
                          parsed_artifact=dict(artifact_id='mounted_encrypted_volumes', parser='kernel_mount_metadata',
                                               parser_version=1, status='parsed', entries=entries, record_count=len(entries),
                                               sources=VOLUME_SOURCES, limitations=['Metadata identification; volume contents not acquired or decrypted.'], inputs=[])), data)
            self.counts['parsed_files'] += 1
            self.counts['parsed_records'] += len(entries)

    def walk(self, root, device):
        queue = ReadQueue(self) if max(self.read_workers, self.analysis_workers) > 1 else None
        try:
            self.walk_directories(root, device, queue)
            if queue:
                queue.drain()
        finally:
            if queue:
                queue.close()

    def walk_directories(self, root, device, queue):
        # fwalk keeps directory descriptors open so file acquisition uses the
        # visited directory, even if its pathname is renamed during collection.
        for directory, folders, files, directory_fd in os.fwalk(
                root, topdown=True, follow_symlinks=False,
                onerror=lambda error: self.log(error.filename or root, error)):
            if self.cancel.is_set():
                raise CollectionCancelled()
            identity = os.fstat(directory_fd)
            key = (identity.st_dev, identity.st_ino)
            if key in self.visited:
                folders[:] = []
                continue
            self.visited.add(key)
            allowed = []
            for name in folders:
                path = os.path.join(directory, name)
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        self.skipped_nonregular_entries += 1
                        continue
                    if self.excluded(path):
                        self.log(path, 'Pseudo-filesystem, runtime or configured directory excluded; not scanned.', 'info')
                        continue
                    # Each selected volume is scanned separately; don't spill
                    # from a selected folder into a different mounted device.
                    if info.st_dev != device:
                        self.log(path, 'Different mounted device skipped; select that volume explicitly.', 'warning')
                        continue
                    allowed.append(name)
                except OSError as error:
                    self.log(path, error)
            folders[:] = allowed
            if self.options['folder_names']:
                matches = self.keywords.match_name(os.path.basename(directory))
                if matches:
                    self.add({'category': 'Folder Name Matches', 'path': directory,
                              'kind': 'directory', 'matches': {'folder_names': matches},
                              'size': 0, 'collection': 'directory metadata'})
            for name in files:
                if self.cancel.is_set():
                    raise CollectionCancelled()
                path = os.path.join(directory, name)
                if os.path.abspath(path) in self.supporting_collected:
                    continue
                if os.path.abspath(path) in self.finished_paths:
                    continue
                if os.path.abspath(path) in self.references:
                    self.log(path, 'Reference list or generated RAM image excluded from filesystem triage.', 'info')
                    continue
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode):
                        self.skipped_nonregular_entries += 1
                        continue
                    definition = definition_for(path)
                    eligibility_options = dict(self.configuration.get('analysis_options', {}))
                    eligibility_options['_inventory_embedded'] = bool(eligibility_options.get('document_images'))
                    if self.configuration.get('ocr_keywords'):
                        eligibility_options['ocr'] = True
                    # Containers depend on credentials discovered earlier in the scan;
                    # structured artifacts may acquire companion snapshots. Keep both
                    # on the coordinator. Independent media can overlap even on HDDs.
                    media = (self.analysis_workers > 1 and content_eligible(path, eligibility_options)
                             and Path(path).suffix.lower() not in ARCHIVES | OFFICE
                             and (definition is None or definition['parser'] is None))
                    if queue and (media or self.read_workers > 1 and info.st_size >= self.parallel_min_bytes) and (definition is None or definition['parser'] is None):
                        queue.submit(path, directory_fd, info.st_size, self.content_options(path) if media else None)
                    else:
                        if queue:
                            queue.drain()
                        self.scan_file(path, directory_fd)
                except (OSError, ValueError) as error:
                    self.log(path, error)
                self.progress(path)
            if queue:
                queue.drain()

    def read_file(self, path, directory_fd, retention_limit, cancelled, on_progress=None):
        """Independent read/match state; workers never publish or mutate scan counters."""
        category = category_for(path)
        matches = {}
        if self.options['file_names']:
            names = self.keywords.match_name(os.path.basename(path))
            if names:
                matches['file_names'] = names
        all_supported = self.configuration['collection_mode'] == 'all_supported'
        if not (matches or all_supported or self.options['file_names'] and content_eligible(path, self.configuration.get('analysis_options', {})) or self.options['file_contents'] or self.options['hash_matches'] or self.configuration.get('ocr_keywords') or self.configuration.get('analysis_options', {}).get('image_references')):
            return False
        hash_stream = self.hashes.stream(integrity_sha256=True)
        content_stream = self.keywords.stream() if self.options['file_contents'] else None
        header = bytearray()
        entropy = EntropySample()

        def consume(chunk):
            # Public LUKS2 JSON metadata may exceed one block; all other probes stay at 64 KiB.
            probe = header if len(header) >= 16 else bytes(header) + chunk[:16]
            limit = header_limit(probe)
            if len(header) < limit:
                header.extend(chunk[:limit - len(header)])
            entropy.update(chunk)
            hash_stream.update(chunk)
            if content_stream:
                content_stream.update(chunk)

        data, metadata = self.collector.collect(
            path, cancelled, directory_fd, on_chunk=consume,
            on_progress=on_progress, retention_limit=retention_limit)
        if cancelled():
            raise CollectionCancelled()
        hash_stream.integrity_sha256 = metadata['sha256']
        if self.options['file_contents']:
            contents = content_stream.matches()
            if contents:
                matches['file_contents'] = contents
        if self.options['hash_matches']:
            hashes = hash_stream.matches()
            if hashes:
                matches['hashes'] = hashes
        return category, matches, data, metadata, hash_stream, header, entropy

    def scan_file(self, path, directory_fd, acquired=None, content_analysis=None):
        metadata = self._scan_file(path, directory_fd, acquired, content_analysis)
        completed = os.path.abspath(path)
        self.finished_paths.add(completed)
        from storage.recovery import identity
        try:
            fields = ('size', 'mtime_ns', 'ctime_ns', 'device', 'inode')
            self.finished_identities[completed] = {key: metadata[key] for key in fields} if metadata else identity(path)
            self.completed_since_checkpoint.add(completed)
        except OSError:
            self.finished_paths.discard(completed)
        self.checkpoint()

    def content_options(self, path):
        analysis_options = self.configuration.get('analysis_options', {})
        if self.configuration.get('ocr_keywords'):
            analysis_options = dict(analysis_options, ocr=True)
        container = Path(path).suffix.lower() in ARCHIVES | OFFICE
        return dict(analysis_options, _inventory_embedded=bool(analysis_options.get('document_images')), _archive_passwords=list(self.archive_credentials.values) if container else [],
                    container_hashes=sorted(self.hashes.hashes) if container else [],
                    container_keywords=self.configuration.get('keywords', []) if container and self.options['file_contents'] else [],
                    container_name_keywords=self.configuration.get('keywords', []) if container else [],
                    container_file_names=self.options['file_names'],
                    container_stream_name=os.path.basename(os.path.splitext(path)[0]),
                    container_compressed_tar=path.lower().endswith(('.tar.gz', '.tar.bz2', '.tar.xz')))

    def analyze_acquired(self, path, directory_fd, acquired, options, cancelled, budget):
        _, matches, data, metadata, *_ = acquired
        if not (self.configuration['collection_mode'] == 'all_supported' or matches or self.options['file_names'] or self.options['file_contents'] or self.options['hash_matches'] or self.configuration.get('ocr_keywords') or options.get('image_references')):
            return None
        return analyze_content(path, metadata, data, directory_fd, options, cancelled, max_result_bytes=budget)

    def _scan_file(self, path, directory_fd, acquired=None, content_analysis=None):
        self.counts['examined'] += 1
        self.current_file_bytes = 0
        self.current_file_size = 0
        self.progress(path)

        def read_progress(bytes_read, size):
            self.current_file_bytes, self.current_file_size = bytes_read, size
            self.progress(path)

        if acquired is None:
            acquired = self.read_file(path, directory_fd, self.store.remaining_bytes, self.cancel.is_set, read_progress)
        if acquired is False:
            return
        category, matches, data, metadata, hash_stream, header, entropy = acquired
        self.discover_archive_credentials(dict(metadata, path=path), data)
        all_supported = self.configuration['collection_mode'] == 'all_supported'
        if self.options['hash_matches']:
            self.counts['hash_checked'] += 1
            if matches.get('hashes'):
                self.counts['hash_matches'] += 1
        analysis_options = self.content_options(path)
        if content_eligible(path, analysis_options) and (all_supported or matches or self.options['file_names'] or self.options['file_contents'] or self.options['hash_matches'] or self.configuration.get('ocr_keywords') or analysis_options.get('image_references')):
            self.progress('Analyzing document/image/video: ' + path, force=True)
            remaining = self.analysis_max_bytes - self.analysis_bytes
            # Speculative results cannot spend the coordinator's remaining budget.
            # Re-run at the serial budget boundary so limits/findings stay equivalent.
            if content_analysis is None or len(json.dumps(content_analysis, ensure_ascii=True).encode()) > remaining:
                content_analysis = analyze_content(path, metadata, data, directory_fd, analysis_options, self.cancel.is_set,
                                                   max_result_bytes=remaining)
            if content_analysis.get('archive_coverage'):
                metadata['archive_coverage'] = content_analysis['archive_coverage']
                self.archive_coverage[path] = dict(content_analysis['archive_coverage'])
                if content_analysis['archive_coverage'].get('needs_credentials'):
                    self.locked_archives[path] = {key: metadata[key] for key in ('size', 'sha256', 'mtime_ns', 'ctime_ns', 'device', 'inode')}
                else:
                    self.locked_archives.pop(path, None)
            for limitation in content_analysis['limitations']:
                self.log(path, limitation, 'warning')
            if self.options['file_contents']:
                for row in content_analysis['entries']:
                    if row.get('text'):
                        found = self.keywords.match_content(row['text'].encode('utf-8', errors='replace'))
                        if found:
                            row['matched_keywords'] = found
                            matches['file_contents'] = list(dict.fromkeys(matches.get('file_contents', []) + found))
                            metadata.setdefault('content_match_sources', []).append(dict(
                                type=row['type'], locator=row['locator'], keywords=found))
            for row in content_analysis['entries']:
                if row.get('type') == 'archive_member':
                    if row.get('matched_hashes'):
                        matches.setdefault('archive_hashes', []).append(dict(locator=row['locator'], hashes=row['matched_hashes']))
                        metadata.setdefault('additional_categories', []).append('Hash Matches')
                        self.counts['hash_matches'] += 1
                    for source_key, match_key in (('matched_content', 'file_contents'), ('matched_names', 'file_names')):
                        if row.get(source_key):
                            matches[match_key] = list(dict.fromkeys(matches.get(match_key, []) + row[source_key]))
                            metadata.setdefault('content_match_sources', []).append(dict(type=row['type'], locator=row['locator'], keywords=row[source_key]))
                if row.get('type') == 'image_similarity_match':
                    matches.setdefault('image_similarity', []).append(
                        f"{row['reference_path']} ({row['similarity_percent']:.2f}% similarity)")
                if row.get('type') == 'ocr_text' and row.get('text'):
                    found = self.ocr_keywords.match_content(row['text'].encode('utf-8', errors='replace'))
                    if found:
                        row['matched_ocr_entries'] = found
                        matches['ocr'] = list(dict.fromkeys(matches.get('ocr', []) + found))
                        metadata.setdefault('ocr_match_sources', []).append(dict(locator=row['locator'], entries=found))
        if matches or all_supported:
            definition = definition_for(path)
            if definition is None:
                from artifacts.cryptocurrency.parser import identify
                crypto_parser = identify(data or bytes(header))
                if crypto_parser:
                    definition = dict(id='cryptocurrency_content_wallet', category='Cryptocurrency', parser=crypto_parser,
                                      sources=['crypto_web3'] if crypto_parser == 'crypto_ethereum' else ['crypto_electrum_schema'],
                                      notes='Wallet structure recognized from acquired JSON; no network or ownership verification.')
                    category = 'Cryptocurrency'
            container = detect(header)
            sample = entropy.result()
            if not container and candidate(path, sample):
                container = dict(type='encrypted_container_candidate', format='High-entropy candidates (unconfirmed)',
                                 detection='Sample entropy at least 7.8 bits/byte; encryption and cipher not established; compression can produce the same result')
            if container:
                if category == 'Cryptocurrency':
                    metadata.setdefault('additional_categories', []).append('Cryptocurrency')
                category = 'Encrypted Containers'
                container.update(sample)
                metadata['category_subgroups'] = {'Encrypted Containers': subgroup(container)}
                metadata['encryption_detection'] = container
            if definition:
                if '/tor-browser/' in path.lower() or '/torbrowser/' in path.lower() or '/tor browser/' in path.lower():
                    metadata.setdefault('additional_categories', []).append('Dark Web Apps')
                self.progress(path, force=True)
                try:
                    parsed = parse_artifact(definition, path, metadata, data, directory_fd, self.cancel.is_set,
                                            dict(self.configuration, _selected_paths=self.targets['paths']))
                except CollectionCancelled:
                    raise
                except Exception as error:
                    if self.cancel.is_set():
                        raise CollectionCancelled() from error
                    self.counts['parser_failures'] += 1
                    parsed = {'artifact_id': definition['id'], 'parser': definition['parser'],
                              'parser_version': 1, 'status': 'failed', 'record_count': 0, 'entries': [],
                              'error': str(error), 'sources': source_links(definition),
                              'inputs': [{'path': path, 'sha256': metadata['sha256'], 'size': metadata['size']}]}
                    self.log(path, f"Structured parser {definition['parser']} failed; raw evidence retained: {error}", 'warning')
                for supporting, supporting_data in parsed.pop('_supporting_snapshots', []):
                    supporting_path = supporting['path']
                    existing = next((record for record in self.store.records if record['path'] == supporting_path), None)
                    if existing and existing.get('sha256') != supporting['sha256']:
                        parsed.update(status='failed', entries=[], record_count=0,
                                      error='Companion changed since its earlier acquisition; structured records were discarded.')
                        self.counts['parser_failures'] += 1
                        self.log(path, parsed['error'], 'warning')
                        continue
                    if not existing:
                        self.counts['examined'] += 1
                        supporting_hashes = self.hashes.stream()
                        supporting_content = self.keywords.stream() if self.options['file_contents'] else None
                        for offset in range(0, len(supporting_data), 1024 * 1024):
                            if self.cancel.is_set():
                                raise CollectionCancelled()
                            chunk = supporting_data[offset:offset + 1024 * 1024]
                            supporting_hashes.update(chunk)
                            if supporting_content:
                                supporting_content.update(chunk)
                        supporting_matches = {}
                        if self.options['file_names']:
                            names = self.keywords.match_name(os.path.basename(supporting_path))
                            if names:
                                supporting_matches['file_names'] = names
                        if supporting_content:
                            contents = supporting_content.matches()
                            if contents:
                                supporting_matches['file_contents'] = contents
                        if self.options['hash_matches']:
                            self.counts['hash_checked'] += 1
                            hashes = supporting_hashes.matches()
                            if hashes:
                                supporting_matches['hashes'] = hashes
                                self.counts['hash_matches'] += 1
                        self.add(dict(supporting, category=definition['category'], kind='file', matches=supporting_matches,
                                      content_retained=True, collection='verified parser companion snapshot',
                                      supporting_artifact_for=path,
                                      calculated_hashes=dict(supporting_hashes.calculated(), sha256=supporting['sha256'])), supporting_data)
                    self.supporting_collected.add(os.path.abspath(supporting_path))
                if parsed['status'] == 'parsed':
                    self.counts['parsed_files'] += 1
                    self.counts['parsed_records'] += parsed['record_count']
                elif parsed['status'] == 'partial':
                    self.counts['partial_parsed_files'] += 1
                    self.counts['parsed_records'] += parsed['record_count']
                for limitation in parsed.get('limitations', []):
                    if definition['parser']:
                        self.log(path, limitation, 'warning')
                metadata['parsed_artifact'] = parsed
                if any(row.get('type') == 'device_connection_event' for row in parsed.get('entries', [])):
                    metadata['additional_categories'] = ['Connected Devices']
            if container:
                header_analysis = dict(artifact_id='encrypted_header', parser='encrypted_header',
                    parser_version=1, status='parsed', record_count=1, entries=[dict(container, locator='offset:0')],
                    sources=ENCRYPTION_SOURCES, limitations=['Header recognition does not validate or decrypt the complete container.'],
                    inputs=[dict(path=path, sha256=metadata['sha256'], size=metadata['size'])])
                existing = metadata.get('parsed_artifact')
                if existing:
                    metadata['parsed_artifact'] = dict(existing,
                        entries=existing['entries'] + header_analysis['entries'],
                        record_count=existing['record_count'] + 1,
                        limitations=existing.get('limitations', []) + header_analysis['limitations'])
                else:
                    metadata['parsed_artifact'] = header_analysis
                if not existing:
                    self.counts['parsed_files'] += 1
                self.counts['parsed_records'] += 1
            if content_analysis:
                if content_analysis['entries']:
                    self.analysis_bytes += len(json.dumps(content_analysis, ensure_ascii=True).encode())
                existing = metadata.get('parsed_artifact')
                if existing:
                    metadata['parsed_artifact'] = dict(existing,
                        supplemental_analysis_status=content_analysis['status'],
                        entries=existing['entries'] + content_analysis['entries'],
                        record_count=existing['record_count'] + content_analysis['record_count'],
                        limitations=existing.get('limitations', []) + content_analysis['limitations'],
                        sources=list(dict.fromkeys(existing.get('sources', []) + content_analysis['sources'])))
                    self.counts['parsed_records'] += content_analysis['record_count']
                else:
                    metadata['parsed_artifact'] = content_analysis
                    self.counts['parsed_records'] += content_analysis['record_count']
                    if content_analysis['status'] == 'parsed':
                        self.counts['parsed_files'] += 1
                    elif content_analysis['status'] == 'partial':
                        self.counts['partial_parsed_files'] += 1
                    else:
                        self.counts['parser_failures'] += 1
                if any(row.get('preview') for row in content_analysis['entries']):
                    metadata['additional_categories'] = list(dict.fromkeys(metadata.get('additional_categories', []) + ['Pictures']))
                skin_categories = []
                for row in content_analysis['entries']:
                    if row.get('type') in ('skin_colour_screen', 'skin_semantic_screen') and row['review_candidate']:
                        skin_categories.append('Video Skin Review' if row.get('media_kind') == 'video' else 'Skin-colour Review')
                if skin_categories:
                    metadata['additional_categories'] = list(dict.fromkeys(metadata.get('additional_categories', []) + skin_categories))
            self.add(dict(metadata, category=category or ('Other Files' if all_supported else 'Other File Matches'), path=path,
                          kind='file', matches=matches,
                          calculated_hashes=dict(hash_stream.calculated(), sha256=metadata['sha256']),
                          collection='verified source file'), data)

        return metadata


class ScanWorker(QThread):
    finding = Signal(dict)
    progress = Signal(dict)
    diagnostic = Signal(dict)

    def __init__(self, targets, configuration, store, parent=None, engine=None):
        super().__init__(parent)
        self.cancel = Event()
        self.summary = None
        self.engine = engine or ScanEngine(targets, configuration, store, self.cancel,
                                          self.finding.emit, self.progress.emit, self.diagnostic.emit)
        if engine:
            engine.cancel = self.cancel
            engine.visited.clear()
            engine.resume_count += 1
            engine.on_finding = self.finding.emit
            engine.on_progress = self.progress.emit
            engine.on_diagnostic = self.diagnostic.emit
            engine.log('Scan resume', 'Resuming the same selected targets and configuration. Completed paths and prior findings are retained; interrupted files are retried. Live evidence is not an atomic snapshot.', 'info')

    def run(self):
        self.summary = self.engine.run()


class ScanController(QObject):
    finding = Signal(dict)
    hash_match = Signal(dict)
    progress = Signal(dict)
    diagnostic = Signal(dict)
    completed = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.store = MemoryStore()
        self.paused_engine = None

    @property
    def running(self):
        return self.worker is not None

    def start(self, targets, configuration, recovery_context=None):
        if self.running:
            raise RuntimeError('A scan is already running.')
        self.store = MemoryStore()
        self.paused_engine = None
        self.worker = ScanWorker(targets, configuration, self.store, self)
        self.worker.engine.recovery_context = recovery_context or {}
        self._start_worker()

    def _start_worker(self):
        self.worker.finding.connect(self._finding, Qt.ConnectionType.QueuedConnection)
        self.worker.progress.connect(self.progress)
        self.worker.diagnostic.connect(self.diagnostic)
        self.worker.finished.connect(self._finished, Qt.ConnectionType.QueuedConnection)
        self.worker.start()

    def resume(self):
        if self.running or self.paused_engine is None:
            raise RuntimeError('No stopped scan is available to resume.')
        engine = self.paused_engine
        self.paused_engine = None
        self.worker = ScanWorker(engine.targets, engine.configuration, self.store, self, engine=engine)
        self._start_worker()

    def stop(self):
        if self.worker:
            self.worker.cancel.set()

    @Slot(dict)
    def _finding(self, record):
        self.finding.emit(record)
        if record['matches'].get('hashes') or record['matches'].get('archive_hashes'):
            self.hash_match.emit(record)

    @Slot()
    def _finished(self):
        worker = self.worker
        self.worker = None
        self.paused_engine = worker.engine if worker.summary['status'] == 'stopped' else None
        self.finished_engine = worker.engine
        self.completed.emit(worker.summary)
        worker.deleteLater()
