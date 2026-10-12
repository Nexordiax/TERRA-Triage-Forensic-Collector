import gzip
import io
import configparser
import re
import shlex
import struct
import xml.etree.ElementTree as ET
from urllib.parse import unquote

from artifacts.parser_support import ParseError, check_cancelled, entry, text_lines, utc_time
from artifacts.devices import usb_event


def parse(parser,data,path,cancelled):
    if parser == 'utmp':
        if str(path).endswith('.gz'):
            uncompressed = bytearray()
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
                while chunk := source.read(1024 * 1024):
                    check_cancelled(cancelled)
                    uncompressed.extend(chunk)
            data = bytes(uncompressed)
        if len(data) % 384:
            raise ParseError('Unsupported/truncated utmp layout; expected Linux little-endian 384-byte records.')
        types = {0:'empty',1:'run_level',2:'boot_time',3:'new_time',4:'old_time',5:'init_process',6:'login_process',7:'user_process',8:'dead_process',9:'accounting'}
        for offset in range(0,len(data),384):
            check_cancelled(cancelled)
            record = data[offset:offset+384]
            kind = struct.unpack_from('<h',record,0)[0]
            if kind not in types:
                raise ParseError('Unsupported utmp record type/byte order.')
            if kind == 0:
                continue
            def string(start,length):
                return record[start:start+length].split(b'\x00',1)[0].decode('utf-8',errors='replace')
            seconds,microseconds = struct.unpack_from('<ii',record,340)
            yield entry('login_record',f'offset:{offset}',record_type=types[kind],pid=struct.unpack_from('<i',record,4)[0],
                        username=string(44,32),terminal=string(8,32),host=string(76,256),
                        timestamp_utc=utc_time(seconds * 1000000 + microseconds,1000000),timestamp_raw=[seconds,microseconds],
                        layout='linux_le_384',source_semantics='failed login records' if '/btmp' in path else 'login/session records')
        return
    if parser == 'recent':
        if str(path).endswith('.desktop'):
            document = configparser.ConfigParser(interpolation=None,strict=False)
            document.read_string(data.decode('utf-8',errors='replace'))
            for section in document.sections():
                yield entry('recent_document',section,fields=dict(document[section]))
        else:
            probe = data.replace(b'\x00', b'').upper()
            if b'<!DOCTYPE' in probe or b'<!ENTITY' in probe:
                raise ParseError('XML DTD/entity declarations are not accepted in forensic inputs.')
            tree = ET.fromstring(data)
            for index,node in enumerate(tree.iter('bookmark')):
                check_cancelled(cancelled)
                title = node.find('title')
                yield entry('recent_document',f'bookmark:{index}',uri=node.get('href'),
                            title=title.text if title is not None else None,added=node.get('added'),
                            modified=node.get('modified'),visited=node.get('visited'),timestamp_note='XBEL timestamps retained with their original timezone notation.')
        return
    if parser == 'trash':
        document = configparser.ConfigParser(interpolation=None,strict=False)
        document.read_string(data.decode('utf-8',errors='replace'))
        if not document.has_section('Trash Info'):
            raise ParseError('Trash Info section missing.')
        yield entry('trashed_file','Trash Info',original_path=unquote(document.get('Trash Info','Path',fallback='')),
                    deletion_time_raw=document.get('Trash Info','DeletionDate',fallback=None),
                    timestamp_note='Trash deletion time is local wall time; timezone is not inferred.')
        return
    if parser == 'bash_history':
        timestamp = None
        pending = []
        start = 1
        for number,line in text_lines(data,path,cancelled):
            if re.fullmatch(r'#[0-9]{9,}',line):
                if pending:
                    yield entry('shell_command',f'line:{start}',shell='bash',command='\n'.join(pending),timestamp_utc=utc_time(timestamp),timestamp_raw=timestamp)
                timestamp = int(line[1:])
                pending = []
                start = number+1
            elif timestamp is not None:
                pending.append(line)
            elif line:
                yield entry('shell_command',f'line:{number}',shell='bash',command=line,timestamp_utc=None)
        if pending:
            yield entry('shell_command',f'line:{start}',shell='bash',command='\n'.join(pending),timestamp_utc=utc_time(timestamp),timestamp_raw=timestamp)
        return
    if parser == 'fish_history':
        command = None
        start = 1
        timestamp = None
        for number,line in text_lines(data,path,cancelled):
            if line.startswith('- cmd: '):
                if command is not None:
                    yield entry('shell_command',f'line:{start}',shell='fish',command=command,timestamp_utc=utc_time(timestamp),timestamp_raw=timestamp)
                command,start,timestamp = line[7:],number,None
            elif line.strip().startswith('when:'):
                timestamp = line.split(':',1)[1].strip()
        if command is not None:
            yield entry('shell_command',f'line:{start}',shell='fish',command=command,timestamp_utc=utc_time(timestamp),timestamp_raw=timestamp)
        return
    if parser == 'systemd':
        section = ''
        for number,line in text_lines(data,path,cancelled):
            stripped = line.strip()
            if stripped.startswith('[') and stripped.endswith(']'):
                section = stripped[1:-1]
            elif stripped and not stripped.startswith(('#',';')) and '=' in stripped:
                key,value = stripped.split('=',1)
                yield entry('service_configuration',f'line:{number}',section=section,key=key.strip(),value=value.strip(),note='Configured commands are not proof of execution and are never run.')
        return
    if parser == 'zsh_history':
        pending = []
        start = 1
        timestamp = None
        duration = None
        for number,line in text_lines(data,path,cancelled):
            if not pending:
                start = number
                match = re.match(r'^: ([0-9]+):([0-9]+);(.*)$',line)
                timestamp = match[1] if match else None
                duration = int(match[2]) if match else None
                line = match[3] if match else line
            if line.endswith('\\'):
                pending.append(line[:-1])
            else:
                pending.append(line)
                yield entry('shell_command',f'line:{start}',shell='zsh',command='\n'.join(pending),
                            timestamp_utc=utc_time(timestamp),duration_seconds=duration)
                pending = []
        if pending:
            yield entry('shell_command',f'line:{start}',shell='zsh',command='\n'.join(pending),
                        timestamp_utc=utc_time(timestamp),duration_seconds=duration,note='Trailing continuation in source history.')
        return
    for number,line in text_lines(data,path,cancelled):
        if not line:
            continue
        if parser == 'line_history':
            yield entry('command_history',f'line:{number}',command=line)
        elif parser == 'syslog':
            modern = re.match(r'^(\d{4}-\d\d-\d\dT\S+)\s+(\S+)\s+(\S+)\s+(.*)',line)
            traditional = re.match(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(\S+)\s+(\S+)\s+(.*)',line)
            match = modern or traditional
            timestamp = match[1] if match else None
            message = match[4] if match else line
            authentication = re.search(r'(Accepted|Failed) (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)', message)
            fields = ({'outcome': authentication[1].lower(), 'method': authentication[2],
                       'username': authentication[3], 'remote_address': authentication[4],
                       'remote_port': int(authentication[5])} if authentication else {})
            device_event = usb_event(message)
            if device_event:
                fields.update(device_event)
            yield entry('device_connection_event' if device_event else 'authentication_event' if authentication else 'system_log',f'line:{number}',timestamp_raw=timestamp,host=match[2] if match else None,
                        service=match[3] if match else None,message=match[4] if match else line,
                        timestamp_note='Timestamp retained exactly; missing year/timezone is not inferred.', **fields)
        elif parser == 'audit':
            match = re.search(r'msg=audit\(([0-9.]+):([0-9]+)\)',line)
            tokens = {}
            try:
                for token in shlex.split(line):
                    if '=' in token:
                        key,value = token.split('=',1)
                        tokens[key] = value
            except ValueError:
                pass
            yield entry('audit_record',f'line:{number}',event_serial=match[2] if match else None,
                        timestamp_raw=match[1] if match else None,
                        timestamp_utc=utc_time(round(float(match[1])*1000000),1000000) if match else None,fields=tokens,raw=line)
        elif parser == 'cron':
            if not line.lstrip().startswith('#'):
                yield entry('scheduled_job_configuration',f'line:{number}',definition=line,note='Configuration only; job is not executed.')
