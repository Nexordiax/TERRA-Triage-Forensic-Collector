import configparser
import re
from itertools import chain
from artifacts.parser_support import ParseError, entry, text_lines


def parse(parser,data,path,cancelled):
    if parser == 'desktop':
        document = configparser.ConfigParser(interpolation=None,strict=False)
        document.optionxform = str
        document.read_string(data.decode('utf-8',errors='replace'))
        if not document.has_section('Desktop Entry'):
            raise ParseError('Desktop Entry section missing.')
        values = dict(document['Desktop Entry'])
        yield entry('application_launcher','Desktop Entry',name=values.get('Name'),application_type=values.get('Type'),
                    exec_command=values.get('Exec'),version=values.get('Version'),hidden=values.get('Hidden'),
                    no_display=values.get('NoDisplay'),categories=values.get('Categories'),
                    note='Launcher presence does not by itself prove installation or execution.')
        return
    if parser == 'pacman':
        values = {}
        field = None
        for number,line in text_lines(data,path,cancelled):
            if line.startswith('%') and line.endswith('%'):
                field = line.strip('%')
            elif line and field:
                values[field] = values.get(field, '') + ('\n' if field in values else '') + line
        if 'NAME' not in values:
            raise ParseError('Pacman NAME field missing.')
        yield entry('package_record','pacman desc',manager='pacman',package=values['NAME'],version=values.get('VERSION'),architecture=values.get('ARCH'),fields=values,installed=True)
        return
    if parser in ('dpkg','apk'):
        current = {}
        field = None
        start = 1
        for number,line in chain(text_lines(data,path,cancelled), [(0,'')]):
            if not line:
                if current and (parser != 'dpkg' or 'Package' in current):
                    status = current.get('Status','')
                    yield entry('package_record',f'line:{start}',manager=parser,
                                package=current.get('Package',current.get('P',current.get('NAME'))),
                                version=current.get('Version',current.get('V',current.get('VERSION'))),
                                architecture=current.get('Architecture',current.get('A',current.get('ARCH'))),
                                status=status or None,installed=(status == 'install ok installed') if parser == 'dpkg' else True,
                                description=current.get('Description',current.get('T',current.get('DESC'))),fields=current)
                    current = {}
                field = None
                start = number + 1
            elif line.startswith((' ','\t')) and field:
                current[field] += '\n' + line.strip()
            elif ':' in line:
                field,value = line.split(':',1)
                current[field] = value.strip()
            else:
                raise ParseError(f'Malformed package record at line {number}.')
    elif parser == 'package_log':
        for number,line in text_lines(data,path,cancelled):
            if line:
                match = re.match(r'^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d) (\S+) (.*)$',line)
                values = {}
                if match:
                    fields = match[4].split()
                    values = {'timestamp_raw':match[1]+' '+match[2],'action':match[3]}
                    if match[3] == 'status' and len(fields) >= 2:
                        values.update(status=fields[0],package=fields[1],version=fields[2] if len(fields)>2 else None)
                    elif fields:
                        values.update(package=fields[0],old_version=fields[1] if len(fields)>1 else None,
                                      new_version=fields[2] if len(fields)>2 else None)
                yield entry('package_transaction',f'line:{number}',raw=line,timestamp_note='Original timestamp retained; timezone is not inferred.', **values)
