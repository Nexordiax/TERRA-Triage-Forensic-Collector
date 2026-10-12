from threading import RLock


class MemoryLimitError(RuntimeError):
    pass


class MemoryStore:
    def __init__(self, max_bytes=256 * 1024 * 1024, max_records=None):
        self.max_bytes = max_bytes
        self.max_records = max_records
        self.bytes_used = 0
        self._reserved_bytes = 0
        self.records = []
        self.record_versions = {}
        self.diagnostics = []
        self.diagnostic_count = 0
        self._lock = RLock()

    def add(self, metadata, data=b''):
        with self._lock:
            if self.max_records is not None and len(self.records) >= self.max_records:
                raise MemoryLimitError('RAM finding-record limit reached; scan stopped without writing evidence to disk.')
            if self.bytes_used + self._reserved_bytes + len(data) > self.max_bytes:
                if metadata.get('generated_snapshot'):
                    raise MemoryLimitError('Live snapshot RAM limit reached; volatile evidence cannot be reopened from a source file.')
                data = b''
                metadata = dict(metadata, content_retained=False,
                                retention_reason='Total RAM file-byte retention limit reached.',
                                collection='verified source file')
            record = dict(metadata, id=len(self.records), data=data)
            self.records.append(record)
            self.record_versions[record["id"]] = 1
            self.bytes_used += len(data)
            return {key: value for key, value in record.items() if key != 'data'}

    @property
    def remaining_bytes(self):
        with self._lock:
            return max(0, self.max_bytes - self.bytes_used - self._reserved_bytes)

    def reserve_bytes(self, count):
        with self._lock:
            if count < 0 or count > self.max_bytes - self.bytes_used - self._reserved_bytes:
                return False
            self._reserved_bytes += count
            return True

    def release_bytes(self, count):
        with self._lock:
            if not 0 <= count <= self._reserved_bytes:
                raise ValueError('Invalid scan RAM reservation release.')
            self._reserved_bytes -= count

    def get(self, record_id):
        with self._lock:
            return self.records[record_id]

    def snapshot(self):
        with self._lock:
            return ([dict(record) for record in self.records],
                    [dict(entry) for entry in self.diagnostics], self.diagnostic_count)

    def log(self, diagnostic):
        with self._lock:
            self.diagnostic_count += 1
            if len(self.diagnostics) < 10000:
                self.diagnostics.append(dict(diagnostic))

    def annotate_parsed(self, updates):
        """Replace derived interpretation only; acquired bytes and source hashes stay intact."""
        with self._lock:
            for record_id, parsed in updates.items():
                self.records[record_id]['parsed_artifact'] = parsed
                self.record_versions[record_id] += 1

    def replace(self, record_id, metadata, data=b''):
        """Replace interpretation of the same verified source after an archive retry."""
        with self._lock:
            old = self.records[record_id]
            if old.get('sha256') != metadata.get('sha256') or old['path'] != metadata['path']:
                raise ValueError('Cannot replace evidence with a different source or hash.')
            if not data and old['data']:
                data = old['data']
                metadata = dict(metadata, content_retained=True)
            available = self.max_bytes - self.bytes_used + len(old['data']) - self._reserved_bytes
            if len(data) > available:
                data = old['data']
                metadata = dict(metadata, content_retained=old.get('content_retained', True))
            self.bytes_used += len(data) - len(old['data'])
            record = dict(metadata, id=record_id, data=data)
            self.records[record_id] = record
            self.record_versions[record_id] += 1
            return {key: value for key, value in record.items() if key != 'data'}
