import io
import re
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from datetime import timezone

from artifacts.parser_support import ParseError, check_cancelled, entry, utc_time
from artifacts.sqlite_snapshot import table_rows


def message_entry(data,locator):
    message = BytesParser(policy=policy.default).parsebytes(data)
    if not any(message.get(key) for key in ('From','To','Subject','Message-ID','Date')):
        raise ParseError('No recognizable RFC email headers.')
    date = message.get('Date')
    timestamp = None
    try:
        parsed = parsedate_to_datetime(str(date)) if date else None
        if parsed and parsed.tzinfo is not None:
            timestamp = parsed.astimezone(timezone.utc).isoformat()
    except (ValueError,TypeError,OverflowError):
        pass
    attachments = []
    body = []
    for part in message.walk():
        if part.is_multipart():
            continue
        if part.get_filename() or part.get_content_disposition() == 'attachment':
            attachments.append({'filename':part.get_filename(),'content_type':part.get_content_type()})
        elif part.get_content_type() == 'text/plain':
            decoded = part.get_payload(decode=True)
            if decoded:
                body.append(decoded.decode(part.get_content_charset() or 'utf-8',errors='replace'))
    return entry('email_message',locator,**{'from':str(message.get('From','')),'to':str(message.get('To','')),
                'cc':str(message.get('Cc','')),'subject':str(message.get('Subject','')),
                'message_id':str(message.get('Message-ID','')),'date_raw':str(date) if date else None,
                'timestamp_utc':timestamp,'attachments':attachments,'text_body':'\n'.join(body),
                'defects':[str(defect) for defect in message.defects]})


def parse(parser,data,path,cancelled):
    if not data and (parser == 'thunderbird_mail' or str(path).endswith('.mbox')):
        return
    if parser == 'thunderbird_mail' and str(path).endswith(('.msf','.dat','.sqlite','.json')):
        raise ParseError('Thunderbird index/settings file; raw collection only.')
    if data.startswith(b'From '):
        pending = bytearray()
        start = 0
        offset = 0
        for line in io.BytesIO(data):
            check_cancelled(cancelled)
            if line.startswith(b'From ') and re.match(br'^From \S+ .+',line):
                if pending:
                    yield message_entry(bytes(pending),f'offset:{start}')
                pending = bytearray()
                start = offset
            else:
                pending.extend(line[1:] if line.startswith(b'>From ') else line)
            offset += len(line)
        if pending:
            yield message_entry(bytes(pending),f'offset:{start}')
    else:
        check_cancelled(cancelled)
        yield message_entry(data,'message:0')


def thunderbird_index(connection,cancelled):
    rows = table_rows(connection,'messages',('id','date','headerMessageID'))
    if rows is None:
        raise ParseError('Thunderbird messages index missing.')
    for row in rows:
        check_cancelled(cancelled)
        row = dict(row)
        yield entry('email_index',f"messages:{row['id']}",message_id=row['headerMessageID'],timestamp_raw=row['date'],timestamp_utc=utc_time(row['date'],1000000),
                    timestamp_note='Gloda stores microseconds since Unix epoch.',subject=row.get('subject'),
                    folder_id=row.get('folderID'),message_key=row.get('messageKey'))
