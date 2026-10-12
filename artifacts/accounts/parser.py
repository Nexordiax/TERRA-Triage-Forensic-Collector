from artifacts.parser_support import ParseError, entry, text_lines


def parse(parser, data, path, cancelled):
    lengths = {'passwd':7,'group':4,'shadow':9,'subids':3}
    for number,line in text_lines(data,path,cancelled):
        if not line or line.startswith('#'):
            continue
        fields = line.split(':')
        if len(fields) != lengths[parser]:
            raise ParseError(f'Malformed {parser} record at line {number}.')
        if parser == 'passwd':
            name,password,uid,gid,description,home,shell = fields
            yield entry('user_account',f'line:{number}',username=name,uid=int(uid),gid=int(gid),description=description,
                        home=home,shell=shell,password_marker=password if password in ('x','*','!','') else 'hash present')
        elif parser == 'group':
            name,password,gid,members = fields
            yield entry('user_group',f'line:{number}',name=name,gid=int(gid),members=members.split(',') if members else [])
        elif parser == 'shadow':
            yield entry('account_security',f'line:{number}',username=fields[0],locked=fields[1].startswith(('!','*')),
                        password_hash_present=bool(fields[1].lstrip('!') and not fields[1].lstrip('!').startswith('*')),
                        last_change_days=fields[2],minimum_days=fields[3],maximum_days=fields[4],warning_days=fields[5],
                        inactive_days=fields[6],expiration_days=fields[7])
        else:
            yield entry('subordinate_ids',f'line:{number}',username=fields[0],start=int(fields[1]),count=int(fields[2]))
