"""Authenticated local Signal attachments; selected profile companions only."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import PurePosixPath

from artifacts.decryption import cipher_bytes
from artifacts.parser_support import ParseError, check_cancelled, entry
from artifacts.sqlite_snapshot import table_rows


def decrypt(data, encoded_key, size):
    try:
        key = base64.b64decode(encoded_key, validate=True)
    except (ValueError, TypeError):
        raise ParseError('Signal attachment key has invalid encoding.') from None
    if len(key) != 64 or isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ParseError('Signal attachment key/size is invalid.')
    if len(data) < 64 or (len(data) - 48) % 16:
        raise ParseError('Signal attachment ciphertext is truncated or malformed.')
    if not hmac.compare_digest(hmac.digest(key[32:], data[:-32], 'sha256'), data[-32:]):
        raise ParseError('Signal attachment authentication failed.')
    plain = cipher_bytes(data[16:-32], key[:32], data[:16])
    if size > len(plain):
        raise ParseError('Signal attachment plaintext is shorter than its declared size.')
    return plain[:size]  # Signal's authenticated additional padding follows the declared bytes.


def extract(connection, database_path, reader, cancelled, enabled=True):
    records = table_rows(connection, 'messages', ('id', 'json'))
    if records is None:
        return [], []
    root = os.path.join(os.path.dirname(os.path.dirname(database_path)), 'attachments.noindex')
    rows, warnings = [], []
    budget, examined = 32 * 1024 * 1024, 0
    for source in records:
        check_cancelled(cancelled)
        try:
            message = json.loads(source['json'])
        except (ValueError, TypeError):
            warnings.append('Malformed Signal message attachment metadata; original evidence retained.')
            continue
        if not isinstance(message, dict):
            continue
        # Only documented attachment-bearing message fields, not arbitrary JSON paths.
        pending = [('attachments', message.get('attachments', [])),
                   ('quote.attachments', message.get('quote', {}).get('attachments', []) if isinstance(message.get('quote'), dict) else []),
                   ('preview', message.get('preview', [])), ('sticker', message.get('sticker', {}))]
        visited = 0
        while pending:
            locator, value = pending.pop()
            check_cancelled(cancelled)
            visited += 1
            if visited > 20000:
                warnings.append('Signal attachment metadata traversal limit reached.')
                break
            if isinstance(value, list):
                if len(value) + len(pending) > 20000:
                    warnings.append('Signal attachment metadata traversal limit reached.')
                    break
                pending.extend((f'{locator}[{index}]', item) for index, item in enumerate(value))
                continue
            if not isinstance(value, dict):
                continue
            pending.extend((locator + '.' + name, value[name]) for name in ('thumbnail', 'image', 'data')
                           if isinstance(value.get(name), dict))
            if not isinstance(value.get('path'), str):
                continue
            examined += 1
            if examined > 10000:
                warnings.append('Signal attachment count limit reached (10000 per database).')
                return rows, list(dict.fromkeys(warnings))
            row = entry('signal_attachment', f"messages:{source['id']}/{locator}", message_id=source['id'],
                        filename=value.get('fileName'), mime_type=value.get('contentType'),
                        size=value.get('size'), attachment_version=value.get('version'), extraction_status='unavailable')
            try:
                relative = PurePosixPath(value['path'])
                if relative.is_absolute() or '\\' in value['path'] or '\0' in value['path'] or any(part in ('', '.', '..') for part in value['path'].split('/')):
                    raise ParseError('Unsafe Signal attachment relative path.')
                path = os.path.join(root, *relative.parts)
                row['encrypted_source_path'] = path
                if isinstance(row['size'], bool) or not isinstance(row['size'], int) or not 0 <= row['size'] <= budget:
                    raise ParseError('Signal attachment extraction RAM budget reached (32 MiB per database).')
                raw = reader(path)
                if value.get('version') == 2:
                    if not enabled:
                        raise ParseError('Offline attachment decryption disabled.')
                    plain = decrypt(raw, value.get('localKey'), row['size'])
                    row['authentication'] = 'HMAC-SHA256 verified'
                elif value.get('version') in (None, 1) and not value.get('localKey'):
                    plain = raw
                    if len(plain) != row['size']:
                        raise ParseError('Legacy plaintext Signal attachment size mismatch.')
                    row['authentication'] = 'Unencrypted local file; size verified, no authentication tag'
                else:
                    raise ParseError('Unsupported local Signal attachment encryption version.')
                if value.get('plaintextHash') and value['plaintextHash'].lower() != hashlib.sha256(plain).hexdigest():
                    raise ParseError('Signal attachment plaintext hash mismatch.')
                budget -= len(plain)
                row.update(extraction_status='extracted', payload_hex=plain.hex(),
                           payload_sha256=hashlib.sha256(plain).hexdigest(), encrypted_source_sha256=hashlib.sha256(raw).hexdigest(),
                           note='Derived local attachment bytes; no download, rendering, execution or cloud access.')
            except Exception:
                check_cancelled(cancelled)
                row['extraction_error'] = 'Missing/inaccessible attachment, unsupported format, failed integrity check or extraction limit; original evidence retained.'
                warnings.append(row['extraction_error'])
            rows.append(row)
    return rows, list(dict.fromkeys(warnings))
