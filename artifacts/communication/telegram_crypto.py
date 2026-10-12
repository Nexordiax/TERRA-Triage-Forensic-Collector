"""Offline Telegram Desktop TDF$/AES-IGE decoding and tagged local drafts."""
import hashlib
import hmac
import os
import struct

from artifacts.communication.native_metadata import telegram as wrapper
from artifacts.companions import read_companion
from artifacts.parser_support import ParseError, check_cancelled, entry


class Stream:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, size):
        if size < 0 or size > len(self.data) - self.offset:
            raise ParseError('Truncated Telegram stream field.')
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def number(self, code):
        return struct.unpack('>' + code, self.take(struct.calcsize('>' + code)))[0]

    def blob(self):
        size = self.number('I')
        return b'' if size == 0xffffffff else self.take(size)

    def text(self):
        try:
            return self.blob().decode('utf-16-be')
        except UnicodeError:
            raise ParseError('Invalid Telegram QString encoding.') from None


def decrypt(encrypted, local_key, cancelled):
    if len(local_key) != 256 or len(encrypted) <= 16 or len(encrypted) % 16:
        raise ParseError('Invalid Telegram local key or encrypted block size.')
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise ParseError('Telegram crypto dependency missing: install requirements-forensics.txt.') from None
    message_key = encrypted[:16]
    # Telegram aesDecryptLocal uses the old-MTProto key schedule with x=8.
    a = hashlib.sha1(message_key + local_key[8:40]).digest()
    b = hashlib.sha1(local_key[40:56] + message_key + local_key[56:72]).digest()
    c = hashlib.sha1(local_key[72:104] + message_key).digest()
    d = hashlib.sha1(message_key + local_key[104:136]).digest()
    key = a[:8] + b[8:20] + c[4:16]
    iv = a[8:20] + b[:8] + c[16:20] + d[:8]
    previous_cipher, previous_plain = iv[:16], iv[16:]
    decoder = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    plain = bytearray()
    for offset in range(16, len(encrypted), 16):
        if offset % 65536 == 16:
            check_cancelled(cancelled)
        block = encrypted[offset:offset + 16]
        mixed = decoder.update(bytes(left ^ right for left, right in zip(block, previous_plain)))
        decoded = bytes(left ^ right for left, right in zip(mixed, previous_cipher))
        plain.extend(decoded)
        previous_cipher, previous_plain = block, decoded
    decoder.finalize()
    if not hmac.compare_digest(hashlib.sha1(plain).digest()[:16], message_key):
        raise ParseError('Telegram encrypted block integrity check failed: incorrect key or corrupt evidence.')
    size = struct.unpack_from('<I', plain)[0]
    if size < 4 or size > len(plain) or size <= len(plain) - 16:
        raise ParseError('Invalid Telegram decrypted length.')
    return bytes(plain[4:size])


def local_key(path, targets, secrets, cancelled):
    supplied = secrets.get('telegram_key')
    if supplied:
        try:
            key = bytes.fromhex(supplied)
        except ValueError:
            raise ParseError('Invalid supplied Telegram local key.') from None
        if len(key) != 256:
            raise ParseError('Telegram local key must be 256 bytes.')
        return key, []
    parts = os.path.abspath(path).split(os.sep)
    if 'tdata' not in parts:
        raise ParseError('Telegram tdata root cannot be determined.')
    root = os.sep.join(parts[:len(parts) - parts[::-1].index('tdata')])
    candidates = []
    for suffix in ('s', '0', '1'):
        try:
            data, metadata = read_companion(os.path.join(root, 'key_data' + suffix), targets, cancelled)
            candidates.append((metadata['mtime_ns'], data, metadata))
        except FileNotFoundError:
            continue
    if not candidates:
        raise ParseError('Telegram key_data companion unavailable in the selected targets.')
    modern = next((item for item in candidates if item[2]['path'].endswith('key_datas')), None)
    _, data, metadata = modern or max(candidates, key=lambda item: item[0])
    list(wrapper(data, cancelled))
    stream = Stream(data[8:-16])
    salt, encrypted_key = stream.blob(), stream.blob()
    stream.blob()  # encrypted account-info, not needed for local container decoding.
    if len(salt) != 32:
        raise ParseError('Unsupported Telegram local-key salt.')
    # New key_data trailers may retain an independently usable empty-passcode open wrap.
    password = secrets.get('telegram_passcode', '').encode('utf-8') if stream.offset == len(stream.data) else b''
    prehash = hashlib.sha512(salt + password + salt).digest()
    key = hashlib.pbkdf2_hmac('sha512', prehash, salt, 100000 if password else 1, 256)
    try:
        plain = decrypt(encrypted_key, key, cancelled)
    except ParseError:
        raise ParseError('Telegram local-key unwrap failed. Supply a correct legacy passcode or the 256-byte local key; newer protected passcode wraps are unsupported.') from None
    if len(plain) != 256:
        raise ParseError('Invalid unwrapped Telegram key length.')
    return plain, [(metadata, data)]


def drafts(plain, cancelled):
    stream = Stream(plain)
    tag = stream.number('Q')
    supported = {0xffffffffffffff01, 0xffffffffffffff03, 0xffffffffffffff05, 0xffffffffffffff06}
    if tag not in supported:
        return None
    peer, count = stream.number('Q'), stream.number('I')
    if not 1 <= count <= 1000:
        raise ParseError('Invalid Telegram draft count.')
    result = []
    for index in range(count):
        check_cancelled(cancelled)
        key = stream.number('i' if tag == 0xffffffffffffff01 else 'q')
        text, text_tags = stream.text(), stream.blob()
        reply_peer = stream.number('q') if tag in (0xffffffffffffff05, 0xffffffffffffff06) else peer
        reply_message = stream.number('q')
        values = {}
        if tag == 0xffffffffffffff06:
            values['suggestion_raw'] = [stream.number('Q'), stream.number('Q')]
        if tag in (0xffffffffffffff05, 0xffffffffffffff06):
            values['webpage_url'] = stream.text()
            values['webpage_flags_raw'] = [stream.number('i') for _ in range(5)]
        else:
            values['preview_state_raw'] = stream.number('i')
        result.append(entry('chat_draft', f'draft:{index}', peer_id_raw=peer, draft_key_raw=key, body=text,
                            reply_peer_raw=reply_peer, reply_message_id_raw=reply_message,
                            text_tags_hex=text_tags.hex(), **values,
                            note='A locally stored draft, not evidence that a message was sent or received.'))
    if stream.offset != len(plain):
        raise ParseError('Unsupported Telegram draft trailing fields.')
    return result


def parse(data, path, targets, secrets, enabled, cancelled):
    rows = list(wrapper(data, cancelled))
    warnings, supporting = [], []
    try:
        if not enabled:
            raise ParseError('Offline decryption disabled.')
        key, supporting = local_key(path, targets, secrets, cancelled)
        name = os.path.basename(path)
        stream = Stream(data[8:-16])
        if name.startswith('key_') or name.startswith('map'):
            stream.blob(); stream.blob()
        encrypted = stream.blob()
        if stream.offset != len(stream.data) and not name.startswith('key_'):
            raise ParseError('Unsupported Telegram multi-block container.')
        plain = decrypt(encrypted, key, cancelled)
        decoded = drafts(plain, cancelled) if len(plain) >= 8 else None
        rows[0].update(content_decrypted=True, decrypted_bytes=len(plain),
                       plaintext_sha256=hashlib.sha256(plain).hexdigest(),
                       note='Validated local AES-IGE block; arbitrary containers are not interpreted as chat history.')
        if decoded is not None:
            rows.extend(decoded)
            return rows, warnings, 'parsed', supporting
        rows.append(entry('telegram_decrypted_container', 'encrypted-block', encoding='hex', value=plain.hex(),
                          note='Decrypted container bytes; schema not recognized as messages.'))
        warnings.append('Telegram container decrypted, but its inner schema is not supported as messages. Desktop tdata does not supply complete cloud chat history.')
    except (ParseError, OSError) as error:
        check_cancelled(cancelled)
        rows[0]['decryption_error'] = str(error)
        warnings.append(str(error))
    return rows, warnings, 'partial', supporting
