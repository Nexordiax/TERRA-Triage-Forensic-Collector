# Copyright (c) 2026 Gersi Hajrullahi.
# GPL-3.0-only with the UnRAR linking permission in
# licenses/TERRA-UnRAR-exception.txt. See COPYING and LICENSE.
"""Verified UnRAR DLL test-mode callbacks. No filesystem extraction or password argv."""
import ctypes as c
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import stat

# UnRAR source code may be used in any software to handle RAR archives without
# limitations free of charge, but cannot be used to develop RAR (WinRAR)
# compatible archiver and to re-create RAR compression algorithm, which is
# proprietary. Distribution of modified UnRAR source code in separate form or
# as a part of other software is permitted, provided that full text of this
# paragraph, starting from "UnRAR source code" words, is included in license,
# or in documentation if license is not available, and in source code comments
# of resulting package. Full licence: assets/tools/unrar/LICENSE.txt.
U = c.c_uint
Callback = c.CFUNCTYPE(c.c_int, U, c.c_long, c.c_long, c.c_long)


class OpenData(c.Structure):
    _pack_ = 1
    _fields_ = [('ArcName',c.c_char_p),('ArcNameW',c.c_wchar_p),('OpenMode',U),('OpenResult',U),
                ('CmtBuf',c.c_char_p),('CmtBufSize',U),('CmtSize',U),('CmtState',U),('Flags',U),
                ('Callback',Callback),('UserData',c.c_long),('OpFlags',U),('CmtBufW',c.c_wchar_p),
                ('MarkOfTheWeb',c.c_wchar_p),('Reserved',U*23)]


class HeaderData(c.Structure):
    _pack_ = 1
    _fields_ = [('ArcName',c.c_char*1024),('ArcNameW',c.c_wchar*1024),
                ('FileName',c.c_char*1024),('FileNameW',c.c_wchar*1024)] + [
                    (name,U) for name in ('Flags','PackSize','PackSizeHigh','UnpSize','UnpSizeHigh','HostOS','FileCRC','FileTime','UnpVer','Method','FileAttr')] + [
                ('CmtBuf',c.c_char_p)] + [(name,U) for name in ('CmtBufSize','CmtSize','CmtState','DictSize','HashType')] + [
                ('Hash',c.c_char*32),('RedirType',U),('RedirName',c.c_wchar_p),('RedirNameSize',U),('DirTarget',U)] + [
                    (name,U) for name in ('MtimeLow','MtimeHigh','CtimeLow','CtimeHigh','AtimeLow','AtimeHigh')] + [
                ('ArcNameEx',c.c_wchar_p),('ArcNameExSize',U),('FileNameEx',c.c_wchar_p),('FileNameExSize',U),('Reserved',U*982)]


def library():
    root = Path(__file__).resolve().parent.parent/'assets/tools/unrar'
    manifest = json.loads((root/'manifest.json').read_text())
    if platform.system() != manifest['platform'] or platform.machine() != manifest['architecture']:
        raise ValueError('Native encrypted-RAR reader is not bundled for this architecture')
    path = root/manifest['filename']
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != manifest['sha256']:
        raise ValueError('Native RAR reader integrity check failed')
    dll = c.CDLL(str(path))
    dll.RARGetDllVersion.restype = c.c_int
    if dll.RARGetDllVersion() != manifest['dll_version']:
        raise ValueError('Native RAR reader API version mismatch')
    dll.RAROpenArchiveEx.argtypes = [c.POINTER(OpenData)]; dll.RAROpenArchiveEx.restype = c.c_void_p
    dll.RARCloseArchive.argtypes = [c.c_void_p]
    dll.RARReadHeaderEx.argtypes = [c.c_void_p,c.POINTER(HeaderData)]
    dll.RARProcessFile.argtypes = [c.c_void_p,c.c_int,c.c_char_p,c.c_char_p]
    dll.RARSetPassword.argtypes = [c.c_void_p,c.c_char_p]; dll.RARSetPassword.restype = None
    return dll


def members(source, passwords, consume, limitation, maximum, byte_limit=64*1024*1024):
    dll = library()
    try:
        descriptor = os.dup(source.fileno())
    except (OSError, AttributeError):
        source.seek(0)
        data = source.read(64*1024*1024+1)
        if len(data) > 64*1024*1024:
            raise ValueError('Nested encrypted RAR input exceeds RAM bound')
        descriptor = os.memfd_create('terra-rar-input', os.MFD_CLOEXEC)
        with os.fdopen(os.dup(descriptor),'wb') as output: output.write(data)
        os.lseek(descriptor,0,os.SEEK_SET)
    try:
        errors = []
        for candidate in [None] + passwords[:32]:
            password = candidate['secret'] if candidate else ''
            payload = bytearray()
            outputs = []
            callback_error = []
            total = 0
            requests = 0
            @Callback
            def callback(message, user, first, second):
                nonlocal requests
                try:
                    if message == 1:  # UCM_PROCESSDATA
                        if second < 0 or len(payload)+second+total > byte_limit:
                            raise ValueError('Encrypted RAR expanded byte limit reached')
                        payload.extend(c.string_at(first,second))
                        return 1
                    if message in (2,4):  # ANSI/wide password request
                        requests += 1
                        if not password or requests > 4: return -1
                        if message == 4:
                            value = c.create_unicode_buffer(password)
                            if len(value) > second: return -1
                        else:
                            value = c.create_string_buffer(password.encode('utf-8'))
                            if len(value) > second: return -1
                        c.memmove(first,value,c.sizeof(value))
                        return 1
                    # Deny volume switching and requests for unusually large dictionaries.
                    return -1
                except Exception as error:
                    callback_error.append(error)
                    return -1
            opened = OpenData(ArcName=f'/proc/self/fd/{descriptor}'.encode(),OpenMode=1,Callback=callback)
            handle = dll.RAROpenArchiveEx(c.byref(opened))
            if not handle or opened.OpenResult:
                if handle: dll.RARCloseArchive(handle)
                errors.append(opened.OpenResult)
                continue
            if candidate:
                dll.RARSetPassword(handle, password.encode('utf-8'))
            complete = False
            try:
                if opened.Flags & 1: raise ValueError('Multipart RAR not searched; additional volumes are required')
                for index in range(maximum+1):
                    header = HeaderData()
                    code = dll.RARReadHeaderEx(handle,c.byref(header))
                    if code == 10:
                        complete = True; break
                    if code:
                        errors.append(code); break
                    if index == maximum: raise ValueError('RAR entry limit reached')
                    name = header.FileNameW or header.FileName.decode('utf-8',errors='replace')
                    size = header.UnpSize | header.UnpSizeHigh << 32
                    nonregular = header.RedirType or header.Flags & 0x20 or (header.HostOS == 3 and stat.S_IFMT(header.FileAttr) not in (0, stat.S_IFREG))
                    if nonregular or size > byte_limit-total:
                        limitation(name + ': nonregular/over-limit encrypted RAR member skipped')
                        code = dll.RARProcessFile(handle,0,None,None)  # RAR_SKIP
                        if code: errors.append(code); break
                        continue
                    payload.clear()
                    code = dll.RARProcessFile(handle,1,None,None)  # RAR_TEST, never RAR_EXTRACT
                    if callback_error: raise callback_error[0]
                    if code:
                        errors.append(code); break
                    if len(payload) != size: raise ValueError('Truncated decrypted RAR member')
                    total += len(payload)
                    outputs.append((name,bytes(payload),size,index,candidate if header.Flags & 4 or opened.Flags & 128 else None))
                if complete:
                    seen = set()
                    for name,data,size,index,credential in outputs:
                        if name in seen:
                            limitation('Duplicate RAR member name skipped: '+name); continue
                        seen.add(name)
                        stream = io.BytesIO(data)
                        consume(name,iter(lambda: stream.read(1024*1024),b''),size,index,credential)
                    return
            finally:
                dll.RARCloseArchive(handle)
        raise ValueError('Encrypted/corrupt RAR: no discovered credential verified it; reader error codes '+str(sorted(set(errors))))
    finally:
        os.close(descriptor)
