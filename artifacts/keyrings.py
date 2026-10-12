"""Offline GNOME and classic KWallet decoding from RAM; no host keyring calls."""
import hashlib
import hmac
import struct

from artifacts.decryption import cipher_bytes
from artifacts.parser_support import ParseError, check_cancelled, entry, utc_time

GNOME_MAGIC = b'GnomeKeyring\n\r\0\n'
KWALLET_MAGIC = b'KWALLET\n\r\0\r\n'
MAX_ITEMS = 65536


class Reader:
    def __init__(self, data, cancelled):
        self.data, self.offset, self.cancelled = data, 0, cancelled

    def take(self, size):
        check_cancelled(self.cancelled)
        if size < 0 or self.offset + size > len(self.data):
            raise ParseError('Truncated keyring structure.')
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def integer(self, size=4):
        return int.from_bytes(self.take(size), 'big')

    def count(self):
        value = self.integer()
        if value > MAX_ITEMS:
            raise ParseError('Keyring item/attribute count exceeds the safety limit.')
        return value

    def blob(self):
        size = self.integer()
        return None if size == 0xffffffff else self.take(size)

    def text(self, encoding='utf-8'):
        value = self.blob()
        try:
            return value.decode(encoding) if value is not None else None
        except UnicodeError:
            raise ParseError('Invalid keyring string encoding.') from None

    def attributes(self):
        result = {}
        for _ in range(self.count()):
            name, kind = self.text(), self.integer()
            if name in result or kind not in (0, 1):
                raise ParseError('Invalid keyring attribute type or duplicate name.')
            result[name] = self.text() if kind == 0 else self.integer()
        return result


def gnome(data, password='', cancelled=lambda: False):
    if not data.startswith(GNOME_MAGIC):
        return gnome_text(data, cancelled)
    reader = Reader(data, cancelled)
    if reader.take(16) != GNOME_MAGIC or reader.take(4) != b'\0' * 4:
        raise ParseError('Unsupported GNOME keyring version/cipher.')
    name, created, modified = reader.text(), reader.integer(8), reader.integer(8)
    flags, timeout, iterations = reader.integer(), reader.integer(), reader.integer()
    if not 1 <= iterations <= 2_000_000:
        raise ParseError('Invalid or excessive GNOME keyring KDF iterations.')
    salt = reader.take(8)
    if any(reader.take(16)):
        raise ParseError('Unsupported GNOME keyring reserved fields.')
    items = []
    for _ in range(reader.count()):
        items.append(dict(identifier=reader.integer(), item_type=reader.integer(),
                          hashed_attributes=reader.attributes()))
    ciphertext = reader.take(reader.integer())
    if reader.offset != len(data) or len(ciphertext) < 16 or len(ciphertext) % 16:
        raise ParseError('Invalid GNOME keyring ciphertext size.')
    material = hashlib.sha256(password.encode('utf-8') + salt).digest()
    for index in range(1, iterations):
        if index % 1024 == 0:
            check_cancelled(cancelled)
        material = hashlib.sha256(material).digest()
    plain = cipher_bytes(ciphertext, material[:16], material[16:], unpad=False)
    if not hmac.compare_digest(plain[:16], hashlib.md5(plain[16:], usedforsecurity=False).digest()):
        raise ParseError('GNOME keyring locked: missing/wrong password or invalid checksum.')
    payload = Reader(plain[16:], cancelled)
    rows = [entry('keyring_collection', 'header', format='GNOME binary', name=name,
                  created_utc=utc_time(created), modified_utc=utc_time(modified),
                  flags=flags, lock_timeout_seconds=timeout, cipher='AES-128-CBC',
                  kdf='iterated SHA-256', iterations=iterations, checksum_valid=True,
                  note='MD5 is a format consistency check, not cryptographic authentication.')]
    for item in items:
        label, secret = payload.text(), payload.blob()
        created, modified = payload.integer(8), payload.integer(8)
        payload.blob()
        if any(payload.take(16)):
            raise ParseError('Unsupported GNOME item reserved fields.')
        attributes = payload.attributes()
        for _ in range(payload.count()):
            payload.integer()
            payload.text()
            payload.text()
            payload.blob()
            payload.integer()
        rows.append(entry('keyring_item', f"item:{item['identifier']}", identifier=item['identifier'],
                          item_type=item['item_type'], label=label, secret=secret, attributes=attributes,
                          created_utc=utc_time(created), modified_utc=utc_time(modified), decryption_status='decrypted'))
    if any(payload.take(len(payload.data) - payload.offset)):
        raise ParseError('Nonzero GNOME keyring trailing padding.')
    return rows


def gnome_text(data, cancelled):
    import configparser
    config = configparser.ConfigParser(interpolation=None, strict=True)
    config.optionxform = str
    try:
        text = data.decode('utf-8-sig')
        config.read_string(text)
        if not config.has_section('keyring'):
            raise ParseError('Unsupported GNOME keyring signature.')
        values, section = {}, None
        for line in text.splitlines():
            check_cancelled(cancelled)
            if line.strip().startswith('[') and line.strip().endswith(']'):
                section = line.strip()[1:-1]
            elif section and '=' in line and not line.lstrip().startswith(('#', ';')):
                key, value = line.split('=', 1)
                values[(section, key.strip())] = value
        rows = [entry('keyring_collection', 'header', format='GNOME textual',
                      name=config.get('keyring', 'display-name', fallback=None), encrypted=False)]
        for section in config.sections():
            check_cancelled(cancelled)
            if ':' in section or section == 'keyring':
                continue
            attributes = {}
            for group in config.sections():
                if group.startswith(section + ':attribute'):
                    name = config.get(group, 'name', fallback=None)
                    attributes[name] = config.get(group, 'value', fallback=None)
            secret = values.get((section, 'secret'))
            if secret is None and config.has_option(section, 'binary-secret'):
                secret = bytes.fromhex(config.get(section, 'binary-secret'))
            rows.append(entry('keyring_item', 'section:' + section, label=config.get(section, 'display-name', fallback=None),
                              attributes=attributes, secret=secret, decryption_status='plaintext'))
            if len(rows) > MAX_ITEMS:
                raise ParseError('Textual keyring exceeds the item limit.')
        return rows
    except (UnicodeError, ValueError, configparser.Error):
        raise ParseError('Malformed or unsupported textual GNOME keyring.') from None


def _kwallet_key(password, modern, salt, cancelled):
    encoded = password.encode('utf-8')
    if len(encoded) > 4096:
        raise ParseError('KWallet password exceeds the safety limit.')
    if modern:
        if salt is None or len(salt) != 56:
            raise ParseError('KWallet PBKDF2 requires its verified 56-byte .salt companion.')
        check_cancelled(cancelled)
        return hashlib.pbkdf2_hmac('sha512', encoded, salt, 50000, 56)
    pieces = [encoded[index:index + 16] for index in range(0, min(len(encoded), 48), 16)]
    if len(encoded) > 48:
        pieces.append(encoded[48:])
    pieces = pieces or [b'']
    digests = []
    for piece in pieces:
        for index in range(2000):
            if index % 512 == 0:
                check_cancelled(cancelled)
            piece = hashlib.sha1(piece).digest()
        digests.append(piece)
    widths = {1: [20], 2: [20, 20], 3: [20, 20, 16], 4: [14] * 4}[len(digests)]
    return b''.join(digest[:width] for digest, width in zip(digests, widths))


def kwallet(data, password='', salt=None, cancelled=lambda: False):
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
    reader = Reader(data, cancelled)
    if reader.take(12) != KWALLET_MAGIC:
        raise ParseError('KWallet signature missing.')
    major, minor, cipher, hashing = reader.take(4)
    if major != 0 or minor not in (0, 1) or cipher not in (0, 3) or hashing not in (0, 2):
        raise ParseError('Unsupported KWallet version/cipher (GPG wallets remain locked).')
    folders = reader.count()
    for _ in range(folders):
        reader.take(16)
        reader.take(reader.count() * 16)
    encrypted = reader.take(len(data) - reader.offset)
    if len(encrypted) < 32 or len(encrypted) % 8:
        raise ParseError('Invalid KWallet ciphertext size.')
    key = _kwallet_key(password, minor == 1, salt, cancelled)
    # KDE's BlowFish implementation swaps native words before/after its rounds;
    # on supported little-endian hosts the persisted blocks use standard byte order.
    decryptor = Cipher(Blowfish(key), modes.ECB()).decryptor()
    native = decryptor.update(encrypted) + decryptor.finalize()
    if cipher == 3:
        native = bytes(left ^ right for left, right in zip(native, b'\0' * 8 + encrypted[:-8]))
    size = int.from_bytes(native[8:12], 'big')
    if size > len(native) - 32 or not hmac.compare_digest(hashlib.sha1(native[12:12 + size]).digest(), native[-20:]):
        raise ParseError('KWallet locked: missing/wrong password or invalid checksum.')
    payload = Reader(native[12:12 + size], cancelled)
    rows = [entry('keyring_collection', 'header', format='KWallet', cipher='Blowfish-CBC' if cipher == 3 else 'Blowfish-ECB',
                  kdf='PBKDF2-SHA512' if minor == 1 else 'iterated SHA1', checksum_valid=True,
                  note='SHA1 format consistency check, not cryptographic authentication.')]
    while payload.offset < len(payload.data):
        folder, count = payload.text('utf-16-be'), payload.count()
        for index in range(count):
            label, kind, value = payload.text('utf-16-be'), payload.integer(), payload.blob()
            if kind not in (1, 2, 3):
                raise ParseError('Unsupported KWallet entry type.')
            row = entry('keyring_item', f'folder:{folder}/item:{index}', folder=folder, label=label,
                        item_type=kind, secret=value, decryption_status='decrypted')
            if kind == 3 and value:
                map_reader = Reader(value, cancelled)
                attributes = {}
                for _ in range(map_reader.count()):
                    name = map_reader.text('utf-16-be')
                    attributes[name] = map_reader.text('utf-16-be')
                if map_reader.offset != len(value):
                    raise ParseError('Trailing KWallet map data.')
                row['attributes'] = attributes
            rows.append(row)
    return rows
