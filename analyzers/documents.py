"""Bounded text extraction from acquired bytes; never launch Office or macros."""
import io
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_XML_BYTES = 32 * 1024 * 1024
MAX_TEXT = 2_000_000


def xml_text(data, kind):
    probe = data.replace(b'\x00', b'').upper()
    if b'<!DOCTYPE' in probe or b'<!ENTITY' in probe:
        raise ValueError('Document XML DTD/entity declarations are not accepted')
    root = ET.fromstring(data)
    output = []
    count = 0
    def append(value):
        nonlocal count
        count += len(value)
        if count > MAX_TEXT:
            raise ValueError('Document text exceeds analysis bound')
        output.append(value)
    def visit(node, depth=0):
        if depth > 128:
            raise ValueError('Document XML nesting exceeds analysis bound')
        tag = node.tag.rsplit('}', 1)[-1]
        if kind == 'ooxml':
            if tag in ('t', 'v') and node.text:
                append(node.text)
            if tag == 'tab':
                append('\t')
            if tag in ('br',):
                append('\n')
        else:
            if node.text:
                append(node.text)
            if tag == 's':
                repeat = next((value for key, value in node.attrib.items() if key.rsplit('}', 1)[-1] == 'c'), '1')
                append(' ' * min(int(repeat), MAX_TEXT + 1))
            elif tag == 'tab':
                append('\t')
            elif tag == 'line-break':
                append('\n')
        for child in node:
            visit(child, depth + 1)
            if kind != 'ooxml' and child.tail:
                append(child.tail)
        if tag in ('p', 'h', 'table-row', 'row'):
            append('\n')
        elif kind == 'ooxml' and tag in ('c', 'si'):
            append('\t')
    visit(root)
    text = ''.join(output)
    if len(text) > MAX_TEXT:
        raise ValueError('Document text exceeds analysis bound')
    return text


def office(data, suffix):
    entries = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > 10000:
            raise ValueError('Office archive has too many members')
        if suffix in ('.odt', '.ods', '.odp'):
            selected = [item for item in infos if item.filename == 'content.xml']
            kind = 'opendocument'
        elif suffix == '.docx':
            selected = [item for item in infos if re.fullmatch(r'word/(document|footnotes|endnotes|comments|header\d*|footer\d*)\.xml', item.filename)]
            kind = 'ooxml'
        elif suffix == '.pptx':
            selected = [item for item in infos if re.fullmatch(r'ppt/(slides/slide\d+|notesSlides/notesSlide\d+)\.xml', item.filename)]
            kind = 'ooxml'
        else:
            selected = [item for item in infos if item.filename == 'xl/sharedStrings.xml' or
                        re.fullmatch(r'xl/worksheets/sheet\d+\.xml', item.filename)]
            kind = 'ooxml'
        if not selected:
            raise ValueError('Expected document text members were not found')
        if sum(item.file_size for item in selected) > MAX_XML_BYTES:
            raise ValueError('Expanded Office XML exceeds analysis bound')
        if len({item.filename for item in selected}) != len(selected):
            raise ValueError('Duplicate Office text members are ambiguous')
        total = 0
        for item in sorted(selected, key=lambda member: member.filename):
            if item.flag_bits & 1:
                raise ValueError('Encrypted Office member cannot be decoded without a supported key')
            with archive.open(item) as source:
                expanded = source.read(item.file_size + 1)
            if len(expanded) != item.file_size:
                raise ValueError('Office member size mismatch')
            text = xml_text(expanded, kind)
            total += len(text)
            if total > MAX_TEXT:
                raise ValueError('Document text exceeds analysis bound')
            entries.append(dict(type='document_text', locator='member:' + item.filename,
                                format=suffix.lstrip('.'), text=text,
                                note='Stored XML text only; macros, formulas, external references and embedded programs are not executed'))
    return entries


def rtf(data):
    if not data.lstrip().startswith(b'{\\rtf'):
        raise ValueError('Invalid RTF header')
    # Bounded parser for text, Unicode fallback counts and ignorable destinations.
    text = data.decode('latin-1')
    stack, ignored, fallback, skip, output = [], False, 1, 0, []
    tokens = re.finditer(r"\\([a-zA-Z]+)(-?\d+)? ?|\\'([0-9a-fA-F]{2})|\\([^a-zA-Z])|([{}])|([^\\{}])", text)
    for token in tokens:
        word, number, hexbyte, escaped, brace, character = token.groups()
        if brace == '{':
            stack.append((ignored, fallback))
            if len(stack) > 128:
                raise ValueError('RTF nesting exceeds analysis bound')
        elif brace == '}':
            if not stack:
                raise ValueError('Unbalanced RTF groups')
            ignored, fallback = stack.pop()
        elif escaped == '*':
            ignored = True
        elif word:
            if word in ('mac', 'pc', 'pca') or word == 'ansicpg' and number not in (None, '1252'):
                raise ValueError('Unsupported RTF legacy code page; original bytes remain available')
            if word in ('fonttbl', 'colortbl', 'stylesheet', 'info', 'pict', 'object', 'fldinst', 'datastore'):
                ignored = True
            elif word == 'bin':
                raise ValueError('RTF binary objects are unsupported for text extraction')
            elif word == 'uc':
                fallback = max(0, min(int(number or 1), 16))
            elif word == 'u' and not ignored:
                output.append(chr(int(number or 0) % 65536))
                skip = fallback
            elif not ignored and word in ('par', 'line', 'tab'):
                output.append('\t' if word == 'tab' else '\n')
        elif not ignored:
            value = bytes.fromhex(hexbyte).decode('cp1252', errors='replace') if hexbyte else escaped or character
            if skip:
                skip -= 1
            elif value not in ('\r', '\n'):
                output.append(value.encode('latin-1').decode('cp1252', errors='replace') if character else value)
        if len(output) > MAX_TEXT:
            raise ValueError('RTF text exceeds analysis bound')
    if stack:
        raise ValueError('Unbalanced RTF groups')
    extracted = ''.join(output).encode('utf-16-le', errors='surrogatepass').decode('utf-16-le', errors='replace')
    return [dict(type='document_text', locator='rtf:body', format='rtf', text=extracted,
                 note='Supported RTF text controls; embedded objects are not decoded or executed')]


def extract(data, path):
    suffix = Path(path).suffix.lower()
    if suffix in ('.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp'):
        return office(data, suffix)
    if suffix == '.rtf':
        return rtf(data)
    if suffix in ('.doc', '.xls', '.ppt'):
        if suffix == '.doc' and data.lstrip().startswith(b'{\\rtf'):
            return rtf(data)
        from analyzers.legacy_office import extract as legacy
        return legacy(data, suffix)
    raise ValueError('Document text extraction does not support this format')
