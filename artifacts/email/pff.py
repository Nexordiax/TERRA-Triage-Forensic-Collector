"""PST/OST interpretation using optional libpff against a RAM snapshot only."""
import importlib
import io
import struct
import hashlib
from datetime import timezone

from artifacts.parser_support import ParseError, check_cancelled, entry


def header(data):
    if len(data) < 12 or data[:4] != b'!BDN':
        raise ParseError('PST/OST PFF signature missing.')
    version = struct.unpack_from('<H', data, 10)[0]
    minimum = 512 if version in (14, 15) else 564
    if version not in (14, 15, 21, 23, 36) or len(data) < minimum:
        raise ParseError('Unsupported/truncated PST/OST header.')
    offset = 461 if version in (14, 15) else 513
    return entry('mail_store_header', 'offset:0', version=version,
                 client_signature_hex=data[8:10].hex(), encoding_method=data[offset],
                 note='Header identification alone does not validate store integrity or recover messages.')


def _text(value):
    return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value


def _time(value):
    if value is None:
        return None
    # libpff FILETIME conversions return naive UTC datetime objects.
    return value.replace(tzinfo=timezone.utc).isoformat() if value.tzinfo is None else value.astimezone(timezone.utc).isoformat()


def _properties(item, cancelled, attachment=False):
    records = []
    for record_index in range(item.number_of_record_sets):
        check_cancelled(cancelled)
        record = item.get_record_set(record_index)
        for index in range(record.number_of_entries):
            check_cancelled(cancelled)
            value = record.get_entry(index)
            if attachment and value.entry_type == 0x3701:
                continue  # Payload is read once, below, within the extraction budget.
            decoded = None
            if value.value_type in (0x001e, 0x001f):
                decoded = value.data_as_string
            raw = value.data
            records.append({'record_set': record_index, 'entry_index': index,
                            'property_id': value.entry_type, 'value_type': value.value_type,
                            'data_hex': raw.hex() if raw is not None else None, 'text': decoded})
    return records


def attachments(message, locator, cancelled, remaining):
    rows, warnings = [], []
    count = message.number_of_attachments
    if count > 10000:
        raise ParseError('PST/OST message attachment count exceeds the safety limit.')
    for index in range(count):
        check_cancelled(cancelled)
        row = entry('email_attachment', f'{locator}/attachment:{index}', extraction_status='unavailable')
        try:
            attachment = message.get_attachment(index)
            properties = _properties(attachment, cancelled, attachment=True) if hasattr(attachment, 'number_of_record_sets') else []
            by_id = {value['property_id']: value for value in properties}
            row.update(filename=attachment.long_filename, size=attachment.size,
                       mime_type=by_id.get(0x370e, {}).get('text'), properties=properties)
            if isinstance(row['size'], bool) or not isinstance(row['size'], int) or row['size'] < 0 or row['size'] > remaining:
                raise ParseError('PST/OST attachment extraction RAM budget reached (32 MiB per store).')
            attachment.seek_offset(0)
            payload = bytearray()
            while len(payload) < row['size']:
                check_cancelled(cancelled)
                chunk = attachment.read_buffer(min(1024 * 1024, row['size'] - len(payload)))
                if not chunk or len(chunk) > row['size'] - len(payload):
                    raise ParseError('PST/OST attachment payload is truncated or exceeds its recorded size.')
                payload.extend(chunk)
            remaining -= len(payload)
            row.update(extraction_status='extracted', payload_hex=payload.hex(),
                       payload_sha256=hashlib.sha256(payload).hexdigest(),
                       note='Derived attachment bytes from the unchanged RAM-resident mail store; not executed.')
        except Exception:
            check_cancelled(cancelled)
            row['extraction_error'] = 'Attachment unavailable, unsupported embedded object, corrupt payload or extraction budget exceeded; raw mail store retained.'
            warnings.append(row['extraction_error'])
        rows.append(row)
    return rows, list(dict.fromkeys(warnings)), remaining


def parse(data, cancelled):
    store_header = header(data)
    check_cancelled(cancelled)
    try:
        backend = importlib.import_module('pypff')
    except ImportError:
        return [store_header], ['pypff/libpff is unavailable: header metadata only; messages and attachments remain in the raw source.'], 'partial'
    archive = backend.file()
    source = io.BytesIO(data)
    opened = False
    rows = [store_header]
    warnings = []
    attachment_budget = 32 * 1024 * 1024
    try:
        archive.open_file_object(source, mode='r')
        opened = True
        root = archive.get_root_folder()
        if root is None:
            raise ParseError('PST/OST root folder unavailable.')
        pending = [('root', root, 0)]
        seen = set()
        while pending:
            check_cancelled(cancelled)
            locator, folder, depth = pending.pop()
            identifier = folder.identifier
            if identifier in seen or depth > 256:
                raise ParseError('Cyclic or excessively deep PST/OST folder tree.')
            seen.add(identifier)
            rows.append(entry('mail_folder', locator, identifier=identifier, name=folder.name))
            for index in range(folder.number_of_sub_messages):
                check_cancelled(cancelled)
                message = folder.get_sub_message(index)
                properties = _properties(message, cancelled) if hasattr(message, 'number_of_record_sets') else []
                message_class = next((value['text'] for value in properties if value['property_id'] == 0x001a), None)
                if not hasattr(type(message), 'subject') and not hasattr(message, 'subject'):
                    rows.append(entry('mail_store_item', f'{locator}/item:{index}', identifier=message.identifier,
                                      message_class=message_class, properties=properties,
                                      note='Generic/non-message MAPI item; retained properties are not labelled as recovered email.'))
                    continue
                kind = 'email_message' if message_class and message_class.startswith('IPM.Note') else 'mail_store_item'
                message_locator = f'{locator}/message:{index}'
                rows.append(entry(kind, message_locator, identifier=message.identifier,
                                  message_class=message_class, properties=properties,
                                  subject=message.subject, sender_name=message.sender_name,
                                  transport_headers=_text(message.transport_headers),
                                  text_body=_text(message.plain_text_body), html_body=_text(message.html_body),
                                  delivery_time_utc=_time(message.delivery_time),
                                  submit_time_utc=_time(message.client_submit_time),
                                  creation_time_utc=_time(message.creation_time),
                                  modification_time_utc=_time(message.modification_time),
                                  attachment_count=message.number_of_attachments,
                                  note='HTML retained as text; derived attachments are source-linked to this unchanged raw store.'))
                extracted, limitations, attachment_budget = attachments(message, message_locator, cancelled, attachment_budget)
                rows.extend(extracted)
                warnings.extend(limitations)
            for index in reversed(range(folder.number_of_sub_folders)):
                check_cancelled(cancelled)
                pending.append((f'{locator}/folder:{index}', folder.get_sub_folder(index), depth + 1))
        return rows, list(dict.fromkeys(warnings)) + ['Deleted-item recovery and nested embedded-message interpretation are not performed.'], 'partial' if warnings else 'parsed'
    finally:
        if opened:
            archive.close()
        source.close()
