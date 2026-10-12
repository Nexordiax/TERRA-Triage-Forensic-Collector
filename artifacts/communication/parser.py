import json
from artifacts.parser_support import ParseError, check_cancelled, entry, utc_time
from artifacts.sqlite_snapshot import table_rows


def skype(connection,cancelled):
    rows = table_rows(connection,'Messages',('id','author','timestamp','body_xml'))
    if rows is None:
        raise ParseError('Legacy Skype Messages table missing.')
    for row in rows:
        check_cancelled(cancelled)
        row = dict(row)
        yield entry('chat_message',f"Messages:{row['id']}",author=row['author'],timestamp_utc=utc_time(row['timestamp']),
                    conversation_id=row.get('convo_id'),body_xml=row['body_xml'],timestamp_raw=row['timestamp'])


def telegram_export(data,cancelled):
    document = json.loads(data)
    chats = document.get('chats',{}).get('list') if isinstance(document,dict) else None
    if chats is None and isinstance(document,dict) and isinstance(document.get('messages'),list):
        chats = [document]
    if not isinstance(chats,list):
        raise ParseError('Unsupported Telegram exported JSON schema.')
    for chat_index,chat in enumerate(chats):
        for message_index,message in enumerate(chat.get('messages',[])):
            check_cancelled(cancelled)
            text = message.get('text','')
            if isinstance(text,list):
                text = ''.join(value if isinstance(value,str) else str(value.get('text','')) for value in text)
            yield entry('chat_message',f'chats[{chat_index}].messages[{message_index}]',chat_name=chat.get('name'),
                        chat_id=chat.get('id'),message_id=message.get('id'),author=message.get('from'),
                        timestamp_utc=utc_time(message.get('date_unixtime')),date_raw=message.get('date'),text=text,
                        file=message.get('file'),photo=message.get('photo'),source_kind='user export, not native Telegram storage')
