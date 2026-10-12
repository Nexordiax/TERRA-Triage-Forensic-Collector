"""Wallet format metadata only; never run clients, connect to chains or use keys."""
import base64
import json
import re

from artifacts.parser_support import ParseError, check_cancelled, entry

MAX_JSON = 4 * 1024 * 1024
MAX_ROWS = 10000


def document(data):
    if len(data) > MAX_JSON:
        raise ParseError('Cryptocurrency JSON exceeds the 4 MiB interpretation limit; raw evidence retained.')
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError, RecursionError):
        raise ParseError('Unsupported or malformed cryptocurrency JSON; raw evidence retained.') from None
    if not isinstance(value, dict):
        raise ParseError('Cryptocurrency JSON must be an object.')
    return value


def ethereum(value):
    crypto = value.get('crypto', value.get('Crypto'))
    return (value.get('version') == 3 and isinstance(crypto, dict)
            and isinstance(crypto.get('cipherparams'), dict) and isinstance(crypto.get('kdfparams'), dict)
            and crypto.get('kdf') in ('scrypt', 'pbkdf2') and crypto.get('cipher') == 'aes-128-ctr'
            and isinstance(crypto['cipherparams'].get('iv'), str)
            and re.fullmatch(r'[0-9a-fA-F]{32}', crypto['cipherparams']['iv'])
            and all(isinstance(crypto.get(name), str) and re.fullmatch(r'[0-9a-fA-F]{64}', crypto[name])
                    for name in ('ciphertext', 'mac')))


def electrum(value):
    return (isinstance(value.get('wallet_type'), str) and isinstance(value.get('seed_version'), int)
            and not isinstance(value.get('seed_version'), bool)
            and any(name in value for name in ('addresses', 'keystore', 'accounts', 'x1/')))


def identify(data):
    """Recognize renamed JSON wallets; no broad suffix/string-only wallet claims."""
    if len(data) > MAX_JSON or not data.lstrip().startswith(b'{'):
        return None
    if not any(name in data[:65536] for name in (b'"wallet_type"', b'"cipherparams"', b'"Crypto"', b'"crypto"')):
        return None
    try:
        value = document(data)
        return 'crypto_ethereum' if ethereum(value) else 'crypto_electrum' if electrum(value) else None
    except ParseError:
        return None


def parse(parser, data, path, cancelled):
    check_cancelled(cancelled)
    note = 'Offline local evidence only; no blockchain query, balance verification, signing or wallet execution.'
    if parser == 'crypto_ethereum':
        value = document(data)
        if not ethereum(value):
            raise ParseError('Ethereum V3 keystore structure not recognized; path-based candidate only.')
        crypto = value.get('crypto', value.get('Crypto'))
        address = value.get('address')
        if address is not None and (not isinstance(address, str) or not re.fullmatch(r'(?:0x)?[0-9a-fA-F]{40}', address)):
            raise ParseError('Invalid public address in Ethereum keystore.')
        rows = [entry('cryptocurrency_keystore', 'JSON root', application='Ethereum-compatible',
                      format='Web3 Secret Storage V3', public_address=address, wallet_id=value.get('id'),
                      cipher=crypto['cipher'], kdf=crypto['kdf'],
                      kdf_parameters={name: crypto['kdfparams'][name] for name in ('n', 'r', 'p', 'c', 'dklen', 'prf') if name in crypto['kdfparams']},
                      decryption_status='locked', integrity_status='MAC not verified; structure recognized', note=note)]
        return rows, ['Encrypted private keys are retained only in the raw source; no key recovery attempted.'], 'partial'
    if parser == 'crypto_electrum':
        if not data.lstrip().startswith(b'{'):
            try:
                prefix = base64.b64decode(data[:8], validate=True)[:4]
            except ValueError:
                prefix = b''
            rows = [entry('cryptocurrency_wallet_candidate', 'offset:0', application='Electrum-compatible',
                          format='ECIES encrypted wallet' if prefix in (b'BIE1', b'BIE2') else 'Unknown wallet encoding',
                          identification='Known wallet path; encrypted prefix recognized' if prefix in (b'BIE1', b'BIE2') else 'Known wallet path only',
                          decryption_status='locked', note=note)]
            return rows, ['Encrypted/unknown wallet content remains in raw evidence.'], 'partial'
        value = document(data)
        if not electrum(value):
            raise ParseError('Electrum-compatible wallet structure not recognized; path-based candidate only.')
        rows = [entry('cryptocurrency_wallet', 'JSON root', application='Electrum-compatible',
                      wallet_type=value['wallet_type'], seed_version=value['seed_version'],
                      secret_material_present=any(name in value for name in ('seed', 'keystore', 'x1/')),
                      encryption_flag_raw=value.get('use_encryption'), note=note)]
        addresses = value.get('addresses', {})
        groups = addresses.items() if isinstance(addresses, dict) else [('imported', addresses)]
        for group, items in groups:
            items = items.keys() if isinstance(items, dict) else items if isinstance(items, list) else []
            for index, address in enumerate(items):
                check_cancelled(cancelled)
                if len(rows) >= MAX_ROWS:
                    return rows, ['Wallet record limit reached; remaining content retained raw.'], 'partial'
                if isinstance(address, str) and len(address) <= 160:
                    rows.append(entry('cryptocurrency_address', f'JSON addresses/{group}/{index}', address=address,
                                      address_group=group, validation='Stored address string; checksum and ownership not verified'))
        transactions = value.get('transactions', {})
        if isinstance(transactions, dict):
            for transaction in transactions:
                check_cancelled(cancelled)
                if len(rows) >= MAX_ROWS:
                    return rows, ['Wallet record limit reached; remaining content retained raw.'], 'partial'
                if re.fullmatch(r'[0-9a-fA-F]{64}', transaction):
                    rows.append(entry('cryptocurrency_transaction_reference', 'JSON transactions/' + transaction,
                                      transaction_id=transaction, note='Stored transaction reference; confirmation, amount and ownership not established.'))
        return rows, ['Private keys/seeds are not extracted into summaries; transaction bodies and unknown schemas remain raw.'], 'parsed'
    if parser == 'crypto_config':
        if len(data) > MAX_JSON:
            raise ParseError('Cryptocurrency configuration exceeds the 4 MiB interpretation limit; raw evidence retained.')
        rows = []
        for number, line in enumerate(data.decode('utf-8', errors='replace').splitlines(), 1):
            check_cancelled(cancelled)
            stripped = line.strip()
            if not stripped or stripped.startswith(('#', ';', '[')) or '=' not in stripped:
                continue
            name, value = stripped.split('=', 1)
            if name.strip() in ('datadir', 'walletdir', 'wallet', 'chain', 'testnet', 'regtest', 'server', 'port', 'rpcport', 'rpcbind', 'rpcconnect', 'connect', 'addnode', 'proxy'):
                rows.append(entry('cryptocurrency_configuration', f'line:{number}', setting=name.strip(), value=value.strip(), note=note))
            if len(rows) >= MAX_ROWS:
                return rows, ['Configuration record limit reached.'], 'partial'
        return rows or [entry('cryptocurrency_application_file', 'offset:0', identification='Known configuration path', note=note)], [], 'parsed'
    signature = ('SQLite' if data.startswith(b'SQLite format 3\0') else
                 'Berkeley DB' if len(data) >= 16 and any(int.from_bytes(data[12:16], order) in (0x53162, 0x61561) for order in ('little', 'big')) else 'Unrecognized/opaque')
    return [entry('cryptocurrency_application_file', 'offset:0', container_format=signature,
                  identification='Known cryptocurrency application path; does not by itself prove a wallet, funds or activity', note=note)], ['Application-specific contents retained raw; no wallet key or transaction-body decoding.'], 'partial'
