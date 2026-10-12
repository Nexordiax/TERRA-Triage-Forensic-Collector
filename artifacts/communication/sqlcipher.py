"""Authenticated SQLCipher 3/4 raw-key database and WAL decoding in RAM."""
import hashlib
import hmac
import struct

from artifacts.decryption import cipher_bytes
from artifacts.parser_support import ParseError, check_cancelled
from artifacts.sqlite_snapshot import checksum, merge_wal


class RawKeyDecoder:
    def __init__(self, key):
        if len(key) != 32:
            raise ParseError('Signal SQLCipher key must be 32 bytes.')
        self.key = key

    def page(self, raw, number, cancelled):
        check_cancelled(cancelled)
        if len(raw) != self.page_size:
            raise ParseError('Truncated SQLCipher page.')
        start = 16 if number == 1 else 0
        end = self.page_size - self.reserve
        iv = raw[end:end + 16]
        expected = raw[end + 16:end + 16 + self.digest_size]
        actual = hmac.digest(self.hmac_key, raw[start:end] + iv + struct.pack('<I', number), self.digest)
        if not hmac.compare_digest(actual, expected):
            raise ParseError('SQLCipher page authentication failed: incorrect key or changed/corrupt evidence.')
        prefix = b'SQLite format 3\0' if number == 1 else b''
        plain = prefix + cipher_bytes(raw[start:end], self.key, iv, unpad=False) + b'\0' * self.reserve
        if number == 1 and (plain[16:18] != struct.pack('>H', self.page_size) or plain[20] != self.reserve):
            raise ParseError('SQLCipher plaintext page-size/reserve mismatch.')
        return plain

    def __call__(self, database, wal, cancelled):
        if len(database) < 1024:
            raise ParseError('Truncated SQLCipher database.')
        self.salt = database[:16]
        selected = None
        # Signal uses raw keys and SQLCipher defaults, with legacy v3 compatibility.
        for page_size, reserve, digest in ((4096, 80, 'sha512'), (1024, 48, 'sha1')):
            check_cancelled(cancelled)
            if len(database) % page_size:
                continue
            self.page_size, self.reserve, self.digest = page_size, reserve, digest
            self.digest_size = hashlib.new(digest).digest_size
            self.hmac_key = hashlib.pbkdf2_hmac(digest, self.key, bytes(value ^ 0x3a for value in self.salt), 2, 32)
            try:
                selected = self.page(database[:page_size], 1, cancelled)
                break
            except ParseError:
                continue
        if selected is None:
            raise ParseError('SQLCipher authentication failed or unsupported profile (Signal raw-key v3/v4 defaults supported).')
        plain = bytearray(selected)
        for offset in range(self.page_size, len(database), self.page_size):
            plain.extend(self.page(database[offset:offset + self.page_size], offset // self.page_size + 1, cancelled))
        decoded_wal, warnings = self.wal(wal, cancelled)
        image, merge_warnings = merge_wal(bytes(plain), decoded_wal, cancelled)
        return image, warnings + merge_warnings

    def wal(self, wal, cancelled):
        if not wal:
            return b'', []
        if len(wal) < 32:
            raise ParseError('Truncated encrypted WAL header.')
        magic, version, size, _, salt1, salt2, first, second = struct.unpack('>8I', wal[:32])
        if magic not in (0x377f0682, 0x377f0683) or version != 3007000 or size != self.page_size:
            raise ParseError('Invalid/incompatible encrypted WAL header.')
        order = '<' if magic == 0x377f0682 else '>'
        original = checksum(wal[:24], order)
        if original != (first, second):
            raise ParseError('Encrypted WAL header checksum failed.')
        rebuilt = original
        output = bytearray(wal[:32])
        warnings = []
        width = 24 + size
        for offset in range(32, len(wal), width):
            check_cancelled(cancelled)
            frame = wal[offset:offset + width]
            if len(frame) != width:
                warnings.append('Incomplete encrypted WAL tail omitted.')
                break
            page, commit, frame_salt1, frame_salt2, first, second = struct.unpack('>6I', frame[:24])
            if (frame_salt1, frame_salt2) != (salt1, salt2):
                warnings.append('Stale encrypted WAL tail omitted.')
                break
            original = checksum(frame[:8] + frame[24:], order, original)
            if not page or original != (first, second):
                warnings.append('Encrypted WAL tail with invalid checksum/page omitted.')
                break
            plain = self.page(frame[24:], page, cancelled)
            rebuilt = checksum(frame[:8] + plain, order, rebuilt)
            output.extend(frame[:16] + struct.pack('>2I', *rebuilt) + plain)
        return bytes(output), warnings
