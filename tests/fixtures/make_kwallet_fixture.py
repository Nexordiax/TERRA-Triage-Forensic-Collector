"""Generate known-data fixtures using KDE v6.18.0's native BlowFish class.

Run only in development with the separately compiled encrypt_native C wrapper;
no TERRA parser or key derivation function is used by this generator.
"""
import ctypes
import hashlib
import struct
import sys
from pathlib import Path


def string(value):
    encoded = value.encode('utf-16-be')
    return struct.pack('>I', len(encoded)) + encoded


def generate(library, destination):
    native = ctypes.CDLL(library)
    native.encrypt_native.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    password = b'fixture-wallet-password'
    salt = bytes(range(56))
    payload = string('Chromium Keys') + struct.pack('>I', 1) + string('Chromium Safe Storage')
    secret = b'fixture-safestorage'
    payload += struct.pack('>II', 1, len(secret)) + secret
    for modern, cbc in ((False, False), (False, True), (True, True)):
        if modern:
            key = hashlib.pbkdf2_hmac('sha512', password, salt, 50000, 56)
        else:
            parts = []
            for segment in (password[:16], password[16:]):
                for _ in range(2000):
                    segment = hashlib.sha1(segment).digest()
                parts.append(segment)
            key = b''.join(parts)
        plain = b'01234567' + struct.pack('>I', len(payload)) + payload
        plain += b'\x5a' * ((-len(plain) - 20) % 8) + hashlib.sha1(payload).digest()
        buffer = ctypes.create_string_buffer(plain, len(plain))
        assert native.encrypt_native(buffer, len(plain), key, len(key), int(cbc)) == len(plain)
        header = b'KWALLET\n\r\0\r\n' + bytes((0, int(modern), 3 if cbc else 0, 2 if modern else 0))
        hashes = struct.pack('>I', 1) + hashlib.md5(b'Chromium Keys').digest() + struct.pack('>I', 1) + hashlib.md5(b'Chromium Safe Storage').digest()
        name = 'kwallet-' + ('modern' if modern else 'legacy') + ('-cbc' if cbc else '-ecb')
        Path(destination, name + '.kwl').write_bytes(header + hashes + buffer.raw)
        if modern:
            Path(destination, name + '.salt').write_bytes(salt)


if __name__ == '__main__':
    generate(sys.argv[1], sys.argv[2])
