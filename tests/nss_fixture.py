"""Generate independent NSS credentials in a temporary development profile."""
import base64
import ctypes
import ctypes.util
import json
from pathlib import Path


class Item(ctypes.Structure):
    _fields_ = [('type', ctypes.c_uint), ('data', ctypes.POINTER(ctypes.c_ubyte)), ('len', ctypes.c_uint)]


def profile(root, password, backend='sql'):
    nss = ctypes.CDLL(ctypes.util.find_library('nss3'))
    nss.NSS_InitReadWrite.argtypes = [ctypes.c_char_p]
    nss.PK11_GetInternalKeySlot.restype = ctypes.c_void_p
    nss.PK11_InitPin.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    nss.PK11_CheckUserPassword.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    nss.PK11SDR_Encrypt.argtypes = [ctypes.POINTER(Item), ctypes.POINTER(Item), ctypes.POINTER(Item), ctypes.c_void_p]
    nss.SECITEM_FreeItem.argtypes = [ctypes.POINTER(Item), ctypes.c_int]
    nss.PK11_FreeSlot.argtypes = [ctypes.c_void_p]
    assert backend in ('sql', 'dbm')
    assert nss.NSS_InitReadWrite((backend + ':' + str(root)).encode()) == 0
    slot = None
    try:
        slot = nss.PK11_GetInternalKeySlot()
        assert nss.PK11_InitPin(slot, None, password.encode()) == 0
        assert nss.PK11_CheckUserPassword(slot, password.encode()) == 0

        def encrypt(plain):
            raw = plain.encode()
            buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
            source, key_id, output = Item(0, buffer, len(raw)), Item(), Item()
            assert nss.PK11SDR_Encrypt(ctypes.byref(key_id), ctypes.byref(source), ctypes.byref(output), None) == 0
            try:
                return base64.b64encode(ctypes.string_at(output.data, output.len)).decode()
            finally:
                nss.SECITEM_FreeItem(ctypes.byref(output), 0)

        login = {'hostname': 'https://example.test', 'encryptedUsername': encrypt('test-user'),
                 'encryptedPassword': encrypt('fixture-password')}
        Path(root, 'logins.json').write_text(json.dumps({'logins': [login]}))
    finally:
        if slot:
            nss.PK11_FreeSlot(slot)
        assert nss.NSS_Shutdown() == 0
