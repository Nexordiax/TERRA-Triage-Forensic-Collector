"""Identify native encrypted stores without claiming their contents decrypted."""
import hashlib
import json
import struct

from artifacts.parser_support import ParseError, check_cancelled, entry
from artifacts.sqlite_snapshot import table_rows


def telegram(data, cancelled):
    check_cancelled(cancelled)
    if len(data) < 24 or data[:4] != b'TDF$':
        raise ParseError('Not a supported Telegram Desktop TDF$ container.')
    version = struct.unpack_from('<I', data, 4)[0]
    payload = data[8:-16]
    digest = hashlib.md5()
    for offset in range(0, len(payload), 1024 * 1024):
        check_cancelled(cancelled)
        digest.update(payload[offset:offset + 1024 * 1024])
    digest.update(struct.pack('<II', len(payload), version))
    digest.update(b'TDF$')
    if digest.digest() != data[-16:]:
        raise ParseError('Telegram Desktop container checksum mismatch.')
    yield entry('telegram_container', 'offset:0', application_version_raw=version,
                payload_bytes=len(payload), checksum_valid=True, content_decrypted=False,
                note='Validated outer wrapper only; no messages or session credentials are decoded. MD5 is a format checksum, not authentication.')


def signal_config(data, cancelled):
    document = json.loads(data)
    if not isinstance(document, dict):
        raise ParseError('Signal configuration must be an object.')
    check_cancelled(cancelled)
    # Record key availability, never expose keys as parsed findings.
    yield entry('signal_configuration', 'root', plaintext_key_present=isinstance(document.get('key'), str),
                encrypted_key_present=isinstance(document.get('encryptedKey'), str),
                safe_storage_backend=document.get('safeStorageBackend'),
                note='Key presence only; protected keys are not unlocked and SQLCipher is not decrypted.')


def signal_messages(connection, cancelled):
    rows = table_rows(connection, 'messages', ('id', 'json'))
    if rows is None:
        raise ParseError('Signal messages table missing.')
    for row in rows:
        check_cancelled(cancelled)
        row = dict(row)
        message = json.loads(row['json'])
        if not isinstance(message, dict):
            raise ParseError('Signal message JSON must be an object.')
        yield entry('chat_message', f"messages:{row['id']}", message_id=row['id'],
                    conversation_id=row.get('conversationId', message.get('conversationId')),
                    body=row.get('body', message.get('body')),
                    source=message.get('source'), source_service_id=message.get('sourceServiceId'),
                    sent_at_raw=row.get('sent_at', message.get('sent_at')),
                    received_at_raw=row.get('received_at', message.get('received_at')),
                    direction_raw=row.get('type', message.get('type')), fields=message,
                    note='Parsed from a read-only RAM SQLite snapshot; encrypted inputs require authenticated SQLCipher decoding.')
