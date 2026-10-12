"""Small offline cryptographic primitives; errors never include keys or plaintext."""
import hashlib

from artifacts.parser_support import ParseError


def cipher_bytes(data, key, iv, algorithm='aes', unpad=True):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        if algorithm == '3des':
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            cipher = TripleDES(key)
        else:
            cipher = algorithms.AES(key)
        decryptor = Cipher(cipher, modes.CBC(iv)).decryptor()
        plain = decryptor.update(data) + decryptor.finalize()
        if unpad:
            remover = padding.PKCS7(cipher.block_size).unpadder()
            plain = remover.update(plain) + remover.finalize()
        return plain
    except ImportError:
        raise ParseError('Offline crypto dependency missing: install requirements-forensics.txt.') from None
    except (ValueError, TypeError):
        raise ParseError('Decryption failed: incorrect key, malformed ciphertext, or invalid padding.') from None


def chromium_value(data, password=''):
    if not isinstance(data, bytes):
        raise ParseError('Invalid protected value type.')
    if not data:
        return b''
    version = data[:3]
    if version == b'v10':
        secret = b'peanuts'
    elif version == b'v11':
        if not password:
            raise ParseError('Linux SafeStorage secret required for v11 ciphertext.')
        secret = password.encode('utf-8')
    else:
        raise ParseError('Unsupported protected value format (Linux v10/v11 CBC supported).')
    key = hashlib.pbkdf2_hmac('sha1', secret, b'saltysalt', 1, 16)
    return cipher_bytes(data[3:], key, b' ' * 16)
