"""Bounded legacy Office stored-text readers. No macros or external programs."""
import io
import struct

MAX_STREAM = 64 * 1024 * 1024
MAX_TEXT = 2_000_000
MAX_RECORDS = 100_000


def part(data, offset, length):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ValueError('Truncated or invalid legacy Office structure')
    return data[offset:offset + length]


def integer(data, offset, size=4):
    return int.from_bytes(part(data, offset, size), 'little')


def stream(ole, name):
    if not ole.exists(name):
        raise ValueError('Expected legacy Office stream missing: ' + name)
    if ole.get_size(name) > MAX_STREAM:
        raise ValueError('Legacy Office stream exceeds analysis bound')
    with ole.openstream(name) as source:
        value = source.read(MAX_STREAM + 1)
    if len(value) > MAX_STREAM:
        raise ValueError('Legacy Office stream exceeds analysis bound')
    return value


def word(ole):
    data = stream(ole, 'WordDocument')
    if integer(data, 0, 2) != 0xA5EC or not 0x00C1 <= integer(data, 2, 2) <= 0x0112:
        raise ValueError('Unsupported Word binary version; Word 97–2007 binary FIB required')
    flags = integer(data, 10, 2)
    if flags & (0x0100 | 0x8000):
        raise ValueError('Encrypted/obfuscated binary Word text requires a supported decryption key')
    table_name = '1Table' if flags & 0x0200 else '0Table'
    table = stream(ole, table_name)
    offset = 34 + integer(data, 32, 2) * 2
    long_count = integer(data, offset, 2)
    offset += 2 + long_count * 4
    pair_count = integer(data, offset, 2)
    if pair_count <= 33:
        raise ValueError('Word FIB has no supported CLX text locator')
    offset += 2
    clx_offset, clx_length = struct.unpack('<II', part(data, offset + 33 * 8, 8))
    clx = part(table, clx_offset, clx_length)
    position = 0
    records = 0
    while position < len(clx) and clx[position] == 1:
        records += 1
        if records > MAX_RECORDS:
            raise ValueError('Word property-group count exceeds bound')
        length = integer(clx, position + 1, 2)
        part(clx, position, 3 + length)
        position += 3 + length
    if position >= len(clx) or clx[position] != 2:
        raise ValueError('Word CLX piece table was not found')
    plc = part(clx, position + 5, integer(clx, position + 1))
    if len(plc) < 4 or (len(plc) - 4) % 12:
        raise ValueError('Invalid Word piece-table length')
    count = (len(plc) - 4) // 12
    if count > MAX_RECORDS:
        raise ValueError('Word text-piece count exceeds bound')
    cps = [integer(plc, index * 4) for index in range(count + 1)]
    if cps[0] != 0 or cps[-1] > MAX_TEXT or any(a > b for a, b in zip(cps, cps[1:])):
        raise ValueError('Invalid or oversized Word character positions')
    output = []
    for index in range(count):
        encoded = integer(plc, (count + 1) * 4 + index * 8 + 2)
        if encoded & 0x80000000:
            raise ValueError('Invalid Word text-piece offset flags')
        compressed = bool(encoded & 0x40000000)
        file_offset = encoded & 0x3FFFFFFF
        characters = cps[index + 1] - cps[index]
        if compressed:
            if file_offset % 2:
                raise ValueError('Invalid compressed Word text offset')
            chunk = part(data, file_offset // 2, characters)
            text = chunk.decode('cp1252', errors='replace')
        else:
            text = part(data, file_offset, characters * 2).decode('utf-16-le', errors='surrogatepass')
        output.append(text)
    text = ''.join(output).encode('utf-16-le', errors='surrogatepass').decode('utf-16-le', errors='replace')
    text = text.replace('\r', '\n').replace('\x07', '\t').replace('\x0b', '\n').replace('\x0c', '\n')
    return [dict(type='document_text', locator=f'stream:WordDocument/clx:{table_name}@{clx_offset}', format='doc', text=text,
                 note='Logical text from the Word CLX piece table, including stored document stories. Unicode and CP1252 compressed pieces; layout, field evaluation, macros and embedded objects are not executed')]


def powerpoint(ole):
    if ole.exists('Current User'):
        current = stream(ole, 'Current User')
        if integer(current, 2, 2) != 0x0FF6 or integer(current, 12) != 0xE391C05F:
            raise ValueError('Encrypted or unsupported PowerPoint Current User header')
    data = stream(ole, 'PowerPoint Document')
    entries = []
    total = records = 0
    def visit(start, end, depth=0):
        nonlocal total, records
        if depth > 32:
            raise ValueError('PowerPoint container nesting exceeds bound')
        while start < end:
            if end - start < 8:
                raise ValueError('Truncated PowerPoint record header')
            version, kind, length = struct.unpack('<HHI', part(data, start, 8))
            payload = start + 8
            if payload + length > end:
                raise ValueError('PowerPoint record exceeds its enclosing container')
            records += 1
            if records > MAX_RECORDS:
                raise ValueError('PowerPoint record count exceeds bound')
            if kind == 0x2F14:  # CryptSession10Container
                raise ValueError('Encrypted PowerPoint stream requires supported decryption')
            if version & 0xF == 0xF:
                visit(payload, payload + length, depth + 1)
            elif kind in (0x0FA0, 0x0FA8):
                raw = part(data, payload, length)
                if kind == 0x0FA0 and length % 2:
                    raise ValueError('Invalid Unicode PowerPoint text atom')
                text = raw.decode('utf-16-le' if kind == 0x0FA0 else 'latin-1', errors='strict').replace('\r', '\n')
                total += len(text)
                if total > MAX_TEXT or len(entries) >= 10000:
                    raise ValueError('PowerPoint extracted text exceeds bound')
                entries.append(dict(type='document_text', locator=f'stream:PowerPoint Document/offset:{start}',
                                    format='ppt', text=text, record_type='TextCharsAtom' if kind == 0x0FA0 else 'TextBytesAtom',
                                    note='Stored PowerPoint text atom; may include historical edit records, masters and notes. Not a reconstructed current slide view. Macros and embedded objects are not executed'))
            start = payload + length
    visit(0, len(data))
    return entries


def excel(data):
    try:
        import xlrd
    except ImportError:
        raise ValueError('Legacy Excel decoder unavailable: xlrd') from None
    book = xlrd.open_workbook(file_contents=data, on_demand=True, logfile=io.StringIO())
    entries, total, cells = [], 0, 0
    try:
        for index in range(book.nsheets):
            sheet = book.sheet_by_index(index)
            cells += sheet.nrows * sheet.ncols
            if cells > 500000 or len(entries) >= 10000:
                raise ValueError('Legacy Excel cell/sheet count exceeds bound')
            rows = []
            for number in range(sheet.nrows):
                values = []
                for cell in sheet.row(number):
                    if cell.ctype == xlrd.XL_CELL_DATE:
                        value = xlrd.xldate_as_datetime(cell.value, book.datemode).isoformat()
                    elif cell.ctype == xlrd.XL_CELL_BOOLEAN:
                        value = 'TRUE' if cell.value else 'FALSE'
                    elif cell.ctype == xlrd.XL_CELL_ERROR:
                        value = xlrd.biffh.error_text_from_code.get(cell.value, '#ERROR')
                    elif cell.ctype in (xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK):
                        value = ''
                    elif cell.ctype == xlrd.XL_CELL_NUMBER:
                        value = format(cell.value, '.15g')
                    else:
                        value = str(cell.value)
                    total += len(value) + 1
                    if total > MAX_TEXT:
                        raise ValueError('Legacy Excel text exceeds bound')
                    values.append(value)
                rows.append('\t'.join(values))
            total += len(sheet.name) + 1
            if total > MAX_TEXT:
                raise ValueError('Legacy Excel text exceeds bound')
            entries.append(dict(type='document_text', locator=f'worksheet:{index + 1}:{sheet.name}', format='xls',
                                text=sheet.name + '\n' + '\n'.join(rows), sheet_name=sheet.name,
                                hidden=bool(sheet.visibility), rows=sheet.nrows, columns=sheet.ncols,
                                note='Stored BIFF cell values, including cached formula results and hidden sheets; formulas, macros and external references are not evaluated'))
            book.unload_sheet(index)
    finally:
        book.release_resources()
    return entries


def extract(data, suffix):
    if len(data) > MAX_STREAM:
        raise ValueError('Legacy Office input exceeds 64 MiB bound')
    if suffix == '.xls':
        return excel(data)
    if not data.startswith(bytes.fromhex('d0cf11e0a1b11ae1')):
        raise ValueError('Legacy Word/PowerPoint input is not an OLE compound document')
    try:
        import olefile
    except ImportError:
        raise ValueError('Legacy Office container decoder unavailable: olefile') from None
    with olefile.OleFileIO(io.BytesIO(data), raise_defects=olefile.DEFECT_INCORRECT) as ole:
        if len(ole.listdir()) > 10000:
            raise ValueError('Legacy Office stream count exceeds bound')
        if ole.exists('EncryptedPackage') or ole.exists('EncryptionInfo'):
            raise ValueError('Encrypted Office container requires supported decryption')
        return word(ole) if suffix == '.doc' else powerpoint(ole)
