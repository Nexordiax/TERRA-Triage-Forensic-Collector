"""Recognize public container headers without unlocking or executing evidence."""
import struct
import json
import math
from collections import Counter
from pathlib import Path

SOURCES = ['https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf',
           'https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/docs/on-disk-format-luks2.pdf',
           'https://keepass.info/help/kb/kdbx.html',
           'https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20%28BDE%29%20format.asciidoc',
           'https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KeePass2.cpp',
           'https://github.com/GNOME/gnome-keyring/blob/main/pkcs11/secret-store/gkm-secret-binary.c',
           'https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT']

MAX_HEADER_BYTES = 4 * 1024 * 1024


def header_limit(header):
    if len(header) >= 16 and header[:8] == b'LUKS\xba\xbe\0\2':
        size = struct.unpack_from('>Q', header, 8)[0]
        if 16384 <= size <= MAX_HEADER_BYTES and size & (size - 1) == 0:
            return size
    return 65536


class EntropySample:
    """First and final 32 KiB from the existing acquisition stream; no extra source read."""
    limit = 32768

    def __init__(self):
        self.first, self.last, self.size = bytearray(), b'', 0

    def update(self, chunk):
        self.first.extend(chunk[:max(0, self.limit - len(self.first))])
        self.last = (self.last + chunk[-self.limit:])[-self.limit:]
        self.size += len(chunk)

    def result(self):
        # Exclude overlap when the file is shorter than two sample windows.
        suffix_length = min(self.limit, max(0, self.size - len(self.first)))
        sample = bytes(self.first) + (self.last[-suffix_length:] if suffix_length else b'')
        entropy = -sum((count / len(sample)) * math.log2(count / len(sample))
                       for count in Counter(sample).values()) if sample else 0.0
        return dict(entropy_bits_per_byte=round(entropy, 6), entropy_sample_bytes=len(sample),
                    entropy_sampling='First and final 32 KiB, without overlap; at most 64 KiB',
                    entropy_sample_ranges=([[0, len(self.first)]] if self.first else []) +
                    ([[self.size - suffix_length, suffix_length]] if suffix_length else []))


def candidate(path, sample):
    # Restrict heuristics to plausible container/image files; compressed media are not flagged by entropy alone.
    suffix = Path(path).suffix.lower()
    return (suffix in ('', '.img', '.iso', '.raw', '.dd', '.bin', '.dat', '.vc', '.tc', '.crypt', '.enc', '.luks')
            and sample['entropy_sample_bytes'] >= 32768 and sample['entropy_bits_per_byte'] >= 7.8)


def subgroup(container):
    cipher = container.get('cipher')
    mode = container.get('cipher_mode')
    return container['format'] + ((' · ' + cipher + ('-' + mode if mode else '')) if cipher else '')


def detect(header):
    if len(header) >= 12 and header[:8] == bytes.fromhex('03d9a29a67fb4bb5'):
        version = struct.unpack_from('<I', header, 8)[0]
        if version >> 16 in (3, 4):
            result = dict(type='encrypted_container_header', format='KeePass KDBX',
                        major_version=version >> 16, minor_version=version & 65535,
                        detection='Public header signature and version; contents not decrypted')
            offset = 12
            while offset + (5 if version >> 16 == 4 else 3) <= len(header):
                field = header[offset]
                length_size = 4 if version >> 16 == 4 else 2
                size = int.from_bytes(header[offset + 1:offset + 1 + length_size], 'little')
                offset += 1 + length_size
                if size > len(header) - offset:
                    break
                if field == 2 and size == 16:
                    result['cipher'] = {'31c1f2e6bf714350be5805216afc5aff': 'AES-256-CBC',
                                        'd6038a2b8b6f4cb5a524339a31dbb59a': 'ChaCha20',
                                        'ad68f29f576f4bb9a36ad47af965346c': 'Twofish'}.get(bytes(header[offset:offset + size]).hex(), 'Unknown cipher UUID')
                offset += size
                if field == 0:
                    break
            return result
    if len(header) >= 8 and header[:6] == b'LUKS\xba\xbe':
        version = struct.unpack_from('>H', header, 6)[0]
        if version == 1 and len(header) >= 592:
            def text(offset, size):
                return header[offset:offset + size].split(b'\0', 1)[0].decode('ascii', errors='replace')
            return dict(type='encrypted_container_header', format='LUKS1',
                        cipher=text(8, 32), cipher_mode=text(40, 32), hash_spec=text(72, 32),
                        uuid=text(168, 40), payload_offset_sectors=struct.unpack_from('>I', header, 104)[0],
                        detection='Public header signature and version; may be detached header; contents not decrypted')
        if version == 2 and len(header) >= 4096:
            size = struct.unpack_from('>Q', header, 8)[0]
            if size >= 16384 and size <= 4 * 1024 * 1024 and size & (size - 1) == 0:
                result = dict(type='encrypted_container_header', format='LUKS2', header_area_bytes=size,
                            detection='Public header signature, version and size; checksum not validated; contents not decrypted')
                if len(header) >= size:
                    try:
                        document = json.loads(bytes(header[4096:size]).split(b'\0', 1)[0])
                        segments = document.get('segments', {})
                        if not isinstance(segments, dict) or len(segments) > 128:
                            raise ValueError('Invalid segments')
                        ciphers = sorted({item['encryption'] for item in segments.values()
                                          if isinstance(item, dict) and item.get('type') == 'crypt' and
                                          isinstance(item.get('encryption'), str) and len(item['encryption']) <= 128})
                        if ciphers:
                            result['cipher'] = ', '.join(ciphers)
                            result['cipher_locator'] = 'JSON segments.*.encryption (offset:4096)'
                    except (ValueError, TypeError, RecursionError):
                        result['metadata_note'] = 'LUKS2 JSON metadata is malformed or unsupported; cipher unknown.'
                return result
    if len(header) >= 512 and header[3:11] == b'-FVE-FS-' and header[510:512] == b'\x55\xaa':
        sector_size = struct.unpack_from('<H', header, 11)[0]
        if sector_size in (512, 1024, 2048, 4096):
            return dict(type='encrypted_container_header', format='BitLocker', bytes_per_sector=sector_size,
                        detection='BitLocker boot-sector signature, sector size and boot marker; cipher requires FVE metadata, not inferred')
    if header.startswith(b'GnomeKeyring\n\r\0\n'):
        return dict(type='encrypted_container_header', format='GNOME Keyring',
                    detection='Public binary keyring signature; contents not decrypted')
    if len(header) >= 16 and header.startswith(b'KWALLET\n\r\0\r\n'):
        return dict(type='encrypted_container_header', format='KWallet',
                    cipher={0: 'Blowfish-ECB', 3: 'Blowfish-CBC', 2: 'GPG'}.get(header[14], 'Unknown'),
                    detection='Public wallet signature and cipher field; header recognition does not unlock contents')
    if len(header) >= 30 and header[:4] == b'PK\3\4' and struct.unpack_from('<H', header, 6)[0] & 1:
        return dict(type='encrypted_container_header', format='Encrypted ZIP',
                    detection='Local ZIP member encrypted flag; archive validation and cipher identification not performed')
    return None
