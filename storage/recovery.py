"""Explicitly selected, transactional recovery sessions. No pickle or target writes by default."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from urllib.parse import quote
import uuid

from storage.memory_store import MemoryStore

FORMAT_VERSION = 1
MAX_JSON = 32 * 1024 * 1024
MAX_RECORD_JSON = 16 * 1024 * 1024
MAX_RECORDS = 1_000_000


def public(value):
    if isinstance(value, dict):
        return {key: public(item) for key, item in value.items() if key not in ('_decryption_secrets', '_archive_passwords')}
    if isinstance(value, (tuple, list)): return [public(item) for item in value]
    return value


def encode(value, maximum=MAX_JSON):
    text = json.dumps(value, ensure_ascii=True, separators=(',', ':'))
    if len(text) > maximum:
        raise ValueError('Recovery metadata exceeds its size bound')
    return text


def identity(path):
    info = os.stat(path, follow_symlinks=False)
    return dict(size=info.st_size, mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
                device=info.st_dev, inode=info.st_ino)


def readonly(path):
    if not stat.S_ISREG(os.stat(path, follow_symlinks=False).st_mode):
        raise ValueError('Select a regular recovery session file, not a symbolic link')
    with open(path, 'rb') as source:
        header = source.read(100)
    if not header.startswith(b'SQLite format 3\0') or int.from_bytes(header[68:72], 'big') != 0x54455252:
        raise ValueError('Not a TERRA recovery session')
    # SQLite may need to roll back a hot journal left by a crash. This write is
    # confined to the recovery file the user explicitly selected to reopen.
    mode = 'rw' if Path(str(path) + '-journal').exists() else 'ro'
    connection = sqlite3.connect('file:' + quote(str(Path(path).absolute()), safe='/') + '?mode=' + mode, uri=True)
    connection.execute('SELECT name FROM sqlite_master LIMIT 1').fetchone()
    connection.execute('PRAGMA trusted_schema=OFF')
    connection.execute('PRAGMA query_only=ON')
    connection.execute('PRAGMA temp_store=MEMORY')
    connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_JSON + 32 * 1024 * 1024)
    return connection


class RecoverySession:
    """Write incremental evidence records and completed paths in one durable transaction."""
    def __init__(self, filename, context=None, session_id=None, expected_identity=None):
        self.path = str(Path(filename).absolute())
        self.context = public(context or {})
        self.session_id = session_id
        self.expected_identity = expected_identity
        self.saved_versions = {}
        self.last_save = 0
        self.last_completed = 0
        self.failed = False
        self.blocked = False

    def check_identity(self):
        current = identity(self.path)
        if self.expected_identity and any(current[key] != self.expected_identity[key] for key in ('device', 'inode')):
            raise OSError('Recovery destination was replaced; no progress was written')
        return current

    def create(self):
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.expected_identity = identity(self.path)
        self.session_id = uuid.uuid4().hex
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('PRAGMA application_id=1413829202')
            connection.execute('PRAGMA temp_store=MEMORY')
            connection.executescript('''
                CREATE TABLE session (id INTEGER PRIMARY KEY CHECK(id=1), format_version INTEGER NOT NULL,
                    session_id TEXT NOT NULL, state TEXT NOT NULL, sha256 TEXT NOT NULL);
                CREATE TABLE records (id INTEGER PRIMARY KEY, metadata TEXT NOT NULL, data BLOB NOT NULL,
                    sha256 TEXT NOT NULL);
                CREATE TABLE completed (path TEXT PRIMARY KEY, metadata TEXT NOT NULL);
                CREATE TABLE diagnostics (id INTEGER PRIMARY KEY, entry TEXT NOT NULL);
            ''')
            self.check_identity()
        return self

    def save(self, engine, summary=None, force=False):
        if self.failed or self.blocked: return
        now = time.monotonic()
        if not force and now - self.last_save < 5 and len(engine.finished_paths) - self.last_completed < 20:
            return
        self.check_identity()
        state = dict(targets=engine.targets, configuration=public(engine.configuration), context=self.context,
                     counts=engine.counts, summary=summary, resume_count=engine.resume_count,
                     live_finished=engine.live_finished, volumes_finished=engine.volumes_finished,
                     finished_directories=sorted(engine.finished_directories), supporting_collected=sorted(engine.supporting_collected),
                     locked_archives=engine.locked_archives, analysis_bytes=engine.analysis_bytes,
                     diagnostic_count=engine.store.diagnostic_count, coverage_issues=engine.coverage_issues,
                     skipped_nonregular_entries=engine.skipped_nonregular_entries, archive_coverage=engine.archive_coverage,
                     target_identities=engine.target_identities, volume_metadata=engine.volume_metadata,
                     credential_sources=[{key:value for key,value in row.items() if key != 'secret'} for row in engine.archive_credentials.values],
                     saved_at=time.time())
        encoded = encode(state)
        versions = dict(engine.store.record_versions)
        with closing(sqlite3.connect(self.path, timeout=1)) as connection, connection:
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('PRAGMA temp_store=MEMORY')
            current = connection.execute('SELECT session_id FROM session WHERE id=1').fetchone()
            if current and current[0] != self.session_id:
                raise ValueError('Recovery session identity mismatch')
            with engine.store._lock:
                for record in engine.store.records:
                    if self.saved_versions.get(record['id']) == versions[record['id']]: continue
                    metadata = encode({key:value for key,value in record.items() if key != 'data'}, MAX_RECORD_JSON)
                    digest = hashlib.sha256(metadata.encode() + record['data']).hexdigest()
                    connection.execute('INSERT OR REPLACE INTO records VALUES (?,?,?,?)',
                                       (record['id'], metadata, record['data'], digest))
                for index, entry in enumerate(engine.store.diagnostics):
                    connection.execute('INSERT OR IGNORE INTO diagnostics VALUES (?,?)', (index, encode(entry)))
            for path in engine.completed_since_checkpoint:
                connection.execute('INSERT OR REPLACE INTO completed VALUES (?,?)', (path, encode(engine.finished_identities[path])))
            for path in engine.invalidated_completed:
                if path not in engine.finished_paths:
                    connection.execute('DELETE FROM completed WHERE path=?', (path,))
            connection.execute('INSERT OR REPLACE INTO session VALUES (1,?,?,?,?)',
                               (FORMAT_VERSION, self.session_id, encoded, hashlib.sha256(encoded.encode()).hexdigest()))
            self.check_identity()
        self.saved_versions = versions
        engine.completed_since_checkpoint.clear()
        engine.invalidated_completed.clear()
        self.last_completed = len(engine.finished_paths)
        self.last_save = now


def load_session(filename, cancelled=lambda: False):
    """Load a data-only checkpoint; validate hashes and bounds before accepting any evidence."""
    from controllers.scan_controller import ScanEngine
    connection = readonly(filename)
    before = identity(filename)
    try:
        row = connection.execute('SELECT format_version,session_id,state,sha256 FROM session WHERE id=1').fetchone()
        if not row or row[0] != FORMAT_VERSION or len(row[2]) > MAX_JSON or hashlib.sha256(row[2].encode()).hexdigest() != row[3]:
            raise ValueError('Invalid, corrupt or unsupported recovery session')
        state = json.loads(row[2])
        targets, configuration = state['targets'], state['configuration']
        configuration['recovery'] = dict(configuration.get('recovery', {}), path=str(Path(filename).absolute()))
        if not isinstance(targets.get('paths'), list) or not all(isinstance(path, str) and os.path.isabs(path) for path in targets['paths']):
            raise ValueError('Invalid recovery targets')
        if configuration.get('collection_mode') not in ('all_supported', 'matches_only') or set(configuration.get('options', {})) != {'folder_names','file_names','file_contents','hash_matches'}:
            raise ValueError('Invalid recovery configuration')
        count, data_bytes = connection.execute('SELECT COUNT(*),COALESCE(SUM(length(data)),0) FROM records').fetchone()
        store = MemoryStore()
        if count > MAX_RECORDS or data_bytes > store.max_bytes:
            raise ValueError('Recovery evidence exceeds the supported RAM storage bound')
        for record_id, metadata, data, checksum in connection.execute('SELECT id,metadata,data,sha256 FROM records ORDER BY id'):
            if cancelled(): raise ValueError('Recovery loading cancelled')
            if record_id != len(store.records) or len(metadata) > MAX_RECORD_JSON or hashlib.sha256(metadata.encode() + data).hexdigest() != checksum:
                raise ValueError('Corrupt recovery evidence record')
            record = json.loads(metadata)
            if (record.get('kind') not in ('file', 'directory') or not isinstance(record.get('path'), str)
                    or not isinstance(record.get('category'), str) or not isinstance(record.get('matches'), dict)
                    or not isinstance(record.get('size'), int) or record['size'] < 0
                    or not isinstance(record.get('collection'), str)):
                raise ValueError('Invalid recovery evidence metadata')
            if record['kind'] == 'file' and record.get('content_retained', True):
                if len(data) != record.get('size') or hashlib.sha256(data).hexdigest() != record.get('sha256'):
                    raise ValueError('Recovery evidence hash mismatch')
            store.add(record, data)
        diagnostics = connection.execute('SELECT entry FROM diagnostics ORDER BY id').fetchall()
        if len(diagnostics) > 10000: raise ValueError('Recovery diagnostic limit exceeded')
        store.diagnostics = [json.loads(entry[0]) for entry in diagnostics]
        store.diagnostic_count = state['diagnostic_count']
        if not isinstance(store.diagnostic_count, int) or store.diagnostic_count < len(store.diagnostics):
            raise ValueError('Invalid recovery diagnostic count')
        engine = ScanEngine(targets, configuration, store)
        engine.counts = state['counts']
        for name in ('resume_count','live_finished','volumes_finished','analysis_bytes','coverage_issues','skipped_nonregular_entries','archive_coverage','locked_archives','target_identities'):
            setattr(engine, name, state[name])
        # Older sessions have no acquisition-time mount snapshot. Do not
        # substitute current mounts for their original volume identities.
        engine.volume_metadata = state.get('volume_metadata', [])
        engine.finished_directories = set(state['finished_directories'])
        engine.supporting_collected = set(state['supporting_collected'])
        completed = connection.execute('SELECT path,metadata FROM completed').fetchall()
        if len(completed) > MAX_RECORDS: raise ValueError('Recovery completed-path limit exceeded')
        for path, metadata in completed:
            engine.finished_paths.add(path)
            engine.finished_identities[path] = json.loads(metadata)
        for record in store.records:
            engine.archive_credentials.inspect(record, record['data'])
        if any(identity(filename)[key] != before[key] for key in before):
            raise ValueError('Recovery file changed while loading; results discarded')
        engine.recovery = RecoverySession(filename, state['context'], row[1], before)
        engine.recovery.saved_versions = dict(store.record_versions)
        engine.references.update(os.path.realpath(str(Path(filename).absolute()) + suffix) for suffix in ('', '-journal', '-wal', '-shm'))
        engine.last_summary = state.get('summary')
        engine.restored_session = True
        engine.restored_credential_sources = state.get('credential_sources', [])
        return engine, state['context'], state.get('summary')
    except (sqlite3.Error, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError('Invalid or incomplete recovery session: ' + type(error).__name__) from None
    finally:
        connection.close()
