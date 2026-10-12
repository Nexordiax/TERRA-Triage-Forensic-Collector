"""Resolve Signal keys exclusively from local configuration or selected evidence."""
import json
import os
import re

from artifacts.companions import read_companion
from artifacts.decryption import chromium_value
from artifacts.parser_support import ParseError


def signal_key(path, targets, secrets, cancelled):
    supplied = secrets.get('signal_key', '')
    if supplied:
        if not re.fullmatch('[0-9a-fA-F]{64}', supplied):
            raise ParseError('Invalid supplied Signal raw key length/encoding.')
        return bytes.fromhex(supplied), []
    config_path = os.path.join(os.path.dirname(os.path.dirname(path)), 'config.json')
    data, metadata = read_companion(config_path, targets, cancelled)
    try:
        config = json.loads(data)
        key = config.get('key')
        if not key and isinstance(config.get('encryptedKey'), str):
            key = chromium_value(bytes.fromhex(config['encryptedKey']),
                                  secrets.get('safe_storage_password', '')).decode('ascii')
        if not isinstance(key, str) or not re.fullmatch('[0-9a-fA-F]{64}', key):
            raise ParseError('Signal database key unavailable or invalid in selected configuration.')
    except ParseError:
        raise
    except Exception:
        raise ParseError('Invalid or unsupported Signal key configuration.') from None
    return bytes.fromhex(key), [(metadata, data)]
