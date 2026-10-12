import shlex
from artifacts.parser_support import entry, text_lines


def parse(parser,data,path,cancelled):
    if parser == 'os_release':
        values = {}
        for number,line in text_lines(data,path,cancelled):
            if '=' in line and not line.startswith('#'):
                key,value = line.split('=',1)
                tokens = shlex.split(value,comments=False)
                values[key] = ' '.join(tokens)
        yield entry('operating_system','key/value records',fields=values)
    elif parser == 'identity':
        for number,line in text_lines(data,path,cancelled):
            if line:
                yield entry('device_identity',f'line:{number}',value=line)
    elif parser == 'fstab':
        for number,line in text_lines(data,path,cancelled):
            fields = line.split()
            if len(fields) >= 4 and not line.lstrip().startswith('#'):
                yield entry('configured_mount',f'line:{number}',device=fields[0],mountpoint=fields[1],filesystem=fields[2],options=fields[3])
    else:
        for number,line in text_lines(data,path,cancelled):
            if line and not line.lstrip().startswith('#'):
                yield entry({'ssh':'ssh_configuration','network_profile':'network_configuration','network_text':'network_configuration'}[parser],f'line:{number}',definition=line,note='Stored configuration/history; not an active network connection.')
