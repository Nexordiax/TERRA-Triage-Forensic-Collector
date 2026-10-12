"""NSS key3.db decoding from bounded Berkeley DB 1.85 RAM bytes."""
import hashlib
import hmac
import struct

from artifacts.browsers.credentials import KEY_ID, der, unwrap
from artifacts.decryption import cipher_bytes
from artifacts.parser_support import ParseError, check_cancelled


def records(data, cancelled):
    if len(data) < 60 or struct.unpack_from('>II', data) != (0x61561, 2):
        raise ParseError('Unsupported Firefox key3 Berkeley DB header/version.')
    order, size = struct.unpack_from('>II', data, 8)
    if order not in (1234, 4321) or size < 512 or size > 65536 or size & (size - 1) or len(data) % size:
        raise ParseError('Invalid key3 page size/byte order.')
    expected = struct.unpack_from('>I', data, 56)[0]
    if expected > 100000:
        raise ParseError('Excessive key3 record count.')
    endian = '<' if order == 1234 else '>'
    result = {}
    for start in range(size, len(data), size):
        if len(result) == expected:
            break  # NSS can append free/bitmap pages after its live records.
        check_cancelled(cancelled)
        page = data[start:start + size]
        count = struct.unpack_from(endian + 'H', page)[0]
        if not count:
            continue
        if count % 2 or 2 + count * 2 + 4 > size:
            raise ParseError('Invalid key3 page offset count.')
        offsets = struct.unpack_from(endian + str(count) + 'H', page, 2)
        previous = size
        for index in range(0, count, 2):
            check_cancelled(cancelled)
            key_start, value_start = offsets[index:index + 2]
            if not 2 + count * 2 + 4 <= value_start < key_start < previous:
                raise ParseError('Unsupported key3 overflow or malformed record offsets.')
            key, value = page[key_start:previous], page[value_start:key_start]
            if key in result:
                raise ParseError('Duplicate key3 database key.')
            result[key] = value
            previous = value_start
    if len(result) != expected:
        raise ParseError('Key3 record count mismatch; unsupported overflow or incomplete snapshot.')
    return result


def keys(data, password, cancelled):
    values = records(data, cancelled)
    try:
        salt, check = values[b'global-salt'], values[b'password-check']
        if len(salt) > 1024 or len(check) < 19 or not 1 <= check[1] <= 20 or 3 + check[1] > len(check) - 16:
            raise ParseError('Malformed Firefox key3 password check.')
        entry_salt = check[3:3 + check[1]]
        password_hash = (hashlib.sha384 if len(salt) == 48 else hashlib.sha1)(salt + password.encode('utf-8')).digest()
        combined = hashlib.sha1(password_hash + entry_salt).digest()
        padded = entry_salt.ljust(20, b'\0')
        temporary = hmac.digest(combined, padded, 'sha1')
        material = hmac.digest(combined, padded + entry_salt, 'sha1') + hmac.digest(combined, temporary + entry_salt, 'sha1')
        if cipher_bytes(check[-16:], material[:24], material[-8:], '3des') != b'password-check':
            raise ParseError('Firefox key3 primary password verification failed.')
        private = values[KEY_ID]
        if len(private) < 4 or private[1] > 20 or 3 + private[1] + private[2] >= len(private):
            raise ParseError('Malformed Firefox key3 private key header.')
        encoded = private[3 + private[1] + private[2]:]
        outer = der(unwrap(encoded, salt, password))
        inner = der(outer[2].asOctets())
        if int(inner[1]) != int.from_bytes(KEY_ID, 'big'):
            raise ParseError('Firefox key3 private key identifier mismatch.')
        key = int(inner[3])
        if key < 0 or key.bit_length() > 192:
            raise ParseError('Unsupported Firefox key3 credential key length.')
        return {KEY_ID: key.to_bytes(24, 'big')}
    except ParseError:
        raise
    except Exception:
        raise ParseError('Malformed or unavailable Firefox key3 credential key.') from None
