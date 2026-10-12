"""Discover labelled archive secrets and already decoded saved logins offline."""
import hashlib
import json
from pathlib import Path
import re

INDEX = json.loads(Path(__file__).with_name('archive_credential_index.json').read_text())


class ArchiveCredentials:
    maximum = 32
    def __init__(self):
        self.values = []
        self.limit_reached = False
        self.fingerprints = set()

    def add(self, secret, path, sha256, locator):
        if not isinstance(secret, str) or not secret or len(secret) > 4096 or '\0' in secret:
            return
        fingerprint = hashlib.sha256(secret.encode()).hexdigest()
        if fingerprint in self.fingerprints: return
        if len(self.values) >= self.maximum:
            self.limit_reached = True
            return
        self.fingerprints.add(fingerprint)
        self.values.append(dict(secret=secret, source_path=path, source_sha256=sha256, locator=locator))

    def inspect(self, metadata, data=b''):
        name = Path(metadata['path']).name.lower()
        if len(data) <= 1024 * 1024 and (name in INDEX['filenames'] or name.startswith('.env.')):
            text = data.decode('utf-8', errors='replace')
            for number, line in enumerate(text.splitlines(), 1):
                match = re.fullmatch(r'\s*(?:export\s+)?([\w.-]+)\s*[=:]\s*(.*?)\s*', line)
                if match and match[1].lower() in INDEX['keys']:
                    value = match[2]
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in '\"\'':
                        value = value[1:-1]
                    self.add(value, metadata['path'], metadata['sha256'], f'line:{number}/key:{match[1]}')
            if name.endswith('.json'):
                try:
                    document = json.loads(text)
                    if isinstance(document, dict):
                        for key, value in document.items():
                            if key.lower() in INDEX['keys']:
                                self.add(value, metadata['path'], metadata['sha256'], 'json:' + key)
                except (ValueError, AttributeError):
                    pass
        parsed = metadata.get('parsed_artifact') or {}
        if parsed.get('parser') in ('firefox_logins', 'chromium_logins'):
            for row in parsed.get('entries', []):
                if row.get('decryption_status') == 'decrypted':
                    self.add(row.get('password'), metadata['path'], metadata['sha256'], row.get('locator', '') + '/password')
