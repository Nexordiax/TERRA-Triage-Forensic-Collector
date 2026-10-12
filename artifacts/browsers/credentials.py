"""Firefox NSS key4 and Linux Chromium SafeStorage decoding from RAM snapshots."""
import base64
import hashlib
import hmac

from artifacts.decryption import cipher_bytes
from artifacts.parser_support import ParseError, check_cancelled
from artifacts.sqlite_snapshot import table_rows

KEY_ID = bytes.fromhex('f8000000000000000000000000000001')
TRIPLE_DES = '1.2.840.113549.3.7'
AES_256 = '2.16.840.1.101.3.4.1.42'


def der(data):
    if not isinstance(data, bytes) or len(data) > 1024 * 1024:
        raise ParseError('Invalid or oversized NSS DER record.')
    try:
        from pyasn1.codec.der.decoder import decode
        value, remainder = decode(data)
        if remainder:
            raise ValueError()
        return value
    except ImportError:
        raise ParseError('NSS DER dependency missing: install requirements-forensics.txt.') from None
    except Exception:
        raise ParseError('Invalid NSS DER record.') from None


def unwrap(data, global_salt, password):
    try:
        record = der(data)
        oid = str(record[0][0])
        parameters = record[0][1]
        ciphertext = record[1].asOctets()
        # NSS uses SHA-384 for its newer 48-byte global salts, SHA-1 otherwise.
        password_hash = (hashlib.sha384 if len(global_salt) == 48 else hashlib.sha1)(global_salt + password.encode('utf-8')).digest()
        if oid == '1.2.840.113549.1.12.5.1.3':
            salt = parameters[0].asOctets()
            if len(salt) > 20 or int(parameters[1]) != 1:
                raise ParseError('Unsupported legacy NSS salt/iteration parameters.')
            padded = salt.ljust(20, b'\0')
            combined = hashlib.sha1(password_hash + salt).digest()
            first = hmac.digest(combined, padded + salt, 'sha1')
            temporary = hmac.digest(combined, padded, 'sha1')
            material = first + hmac.digest(combined, temporary + salt, 'sha1')
            return cipher_bytes(ciphertext, material[:24], material[-8:], '3des')
        if oid != '1.2.840.113549.1.5.13':
            raise ParseError('Unsupported NSS password-based cipher.')
        kdf, cipher = parameters[0], parameters[1]
        parameters = kdf[1]
        if (str(kdf[0]) != '1.2.840.113549.1.5.12' or str(cipher[0]) != AES_256
                or int(parameters[2]) != 32 or str(parameters[3][0]) != '1.2.840.113549.2.9'):
            raise ParseError('Unsupported NSS PBES2 parameters.')
        iterations = int(parameters[1])
        salt = parameters[0].asOctets()
        iv = cipher[1].asOctets()
        if not 1 <= iterations <= 2_000_000 or len(salt) > 1024 or len(iv) not in (14, 16):
            raise ParseError('Invalid or excessive NSS KDF parameters.')
        key = hashlib.pbkdf2_hmac('sha256', password_hash, salt, iterations, 32)
        return cipher_bytes(ciphertext, key, b'\x04\x0e' + iv if len(iv) == 14 else iv)
    except ParseError:
        raise
    except Exception:
        raise ParseError('Malformed NSS password-based encryption record.') from None


def firefox_keys(connection, password, cancelled):
    rows = table_rows(connection, 'metaData', ('id', 'item1', 'item2'))
    if rows is None:
        raise ParseError('Firefox key4 password metadata missing.')
    metadata = next((dict(row) for row in rows if row['id'] == 'password'), None)
    if metadata is None:
        raise ParseError('Firefox key4 password metadata missing.')
    salt = metadata['item1']
    if unwrap(metadata['item2'], salt, password) != b'password-check':
        raise ParseError('Firefox primary password verification failed.')
    rows = table_rows(connection, 'nssPrivate', ('a11', 'a102'))
    if rows is None:
        raise ParseError('Firefox key4 private key table missing.')
    keys = {}
    for row in rows:
        check_cancelled(cancelled)
        if row['a102'] == KEY_ID and row['a11']:
            key = unwrap(row['a11'], salt, password)
            if len(key) not in (24, 32):
                raise ParseError('Unsupported Firefox login key length.')
            keys[row['a102']] = key
    if not keys:
        raise ParseError('Firefox login key missing.')
    return keys


def firefox_value(encoded, keys):
    try:
        record = der(base64.b64decode(encoded, validate=True))
        key = keys.get(record[0].asOctets())
        if key is None:
            raise ParseError('Firefox login key identifier not found.')
        oid = str(record[1][0])
        if oid not in (TRIPLE_DES, AES_256) or len(key) != (24 if oid == TRIPLE_DES else 32):
            raise ParseError('Unsupported Firefox credential cipher/key length.')
        plain = cipher_bytes(record[2].asOctets(), key, record[1][1].asOctets(),
                             '3des' if oid == TRIPLE_DES else 'aes')
        return plain.decode('utf-8')
    except ParseError:
        raise
    except Exception:
        raise ParseError('Malformed Firefox encrypted credential.') from None
