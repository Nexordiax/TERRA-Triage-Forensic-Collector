"""Tesseract stdin/stdout OCR: no target paths, uploads or image temp files."""
import csv
import io
import os
import re
import subprocess
import sys
from pathlib import Path


def installation():
    local = Path(sys.prefix) / 'ocr'
    binary = local / 'usr/bin/tesseract'
    if binary.is_file():
        return binary, local / 'usr/share/tesseract-ocr/5/tessdata', local / 'usr/lib/x86_64-linux-gnu'
    # Use known installed tool locations, never an executable from evidence/PATH.
    for path in ('/usr/bin/tesseract', '/usr/local/bin/tesseract'):
        if Path(path).is_file():
            return Path(path), None, None
    raise ValueError('Tesseract OCR is unavailable; install Tesseract and requested language data on the acquisition tool')


def installed_languages():
    """Query the trusted local OCR binary without reading evidence or downloading data."""
    binary, tessdata, library_path = installation()
    command = [str(binary), '--list-langs']
    if tessdata is not None:
        command.extend(['--tessdata-dir', str(tessdata)])
    environment = {key: value for key, value in os.environ.items() if key not in (
        'TESSDATA_PREFIX', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES')}
    environment['OMP_THREAD_LIMIT'] = '1'
    if library_path is not None:
        environment['LD_LIBRARY_PATH'] = str(library_path)
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=environment, timeout=5, check=False)
    except subprocess.TimeoutExpired:
        raise ValueError('OCR language query timed out') from None
    if result.returncode:
        raise ValueError('Cannot query installed OCR languages: ' + result.stderr.decode('utf-8', errors='replace')[-1000:])
    return sorted(line.strip() for line in result.stdout.decode('utf-8', errors='replace').splitlines()
                  if re.fullmatch(r'[A-Za-z0-9_]+', line.strip()))


def recognize(image, languages='eng'):
    if not re.fullmatch(r'[A-Za-z0-9_]+(?:\+[A-Za-z0-9_]+)*', languages):
        raise ValueError('Unsupported OCR language selection')
    binary, tessdata, library_path = installation()
    command = [str(binary), 'stdin', 'stdout', '-l', languages, '--psm', '3', '--dpi', '200']
    if tessdata is not None:
        for language in languages.split('+'):
            if not (tessdata / (language + '.traineddata')).is_file():
                raise ValueError(f'OCR language data unavailable: {language}')
        command.extend(['--tessdata-dir', str(tessdata)])
    # Explicit output flags avoid relying on locally packaged config files.
    command.extend(['-c', 'tessedit_create_tsv=1', '-c', 'tessedit_create_txt=0'])
    environment = {key: value for key, value in os.environ.items() if key not in (
        'TESSDATA_PREFIX', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES')}
    environment.update(OMP_THREAD_LIMIT='1')
    if library_path is not None:
        environment['LD_LIBRARY_PATH'] = str(library_path)
    stream = io.BytesIO()
    image.save(stream, format='PNG')
    try:
        result = subprocess.run(command, input=stream.getvalue(), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=environment, timeout=40, check=False)
    except subprocess.TimeoutExpired as error:
        raise ValueError('OCR page timeout reached') from error
    if result.returncode:
        raise ValueError('Tesseract failed: ' + result.stderr.decode('utf-8', errors='replace')[-1000:])
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError('OCR output exceeds analysis bound')
    words, lines, current = [], [], None
    for row in csv.DictReader(io.StringIO(result.stdout.decode('utf-8', errors='strict')), delimiter='\t'):
        if row.get('level') != '5' or not row.get('text', '').strip():
            continue
        key = tuple(row[name] for name in ('page_num', 'block_num', 'par_num', 'line_num'))
        if current != key:
            lines.append([])
            current = key
        text = row['text']
        lines[-1].append(text)
        words.append(dict(text=text, confidence=float(row['conf']),
                          box=[int(row[field]) for field in ('left', 'top', 'width', 'height')]))
        if len(words) > 50000:
            raise ValueError('OCR word count exceeds analysis bound')
    return dict(type='ocr_text', text='\n'.join(' '.join(line) for line in lines), words=words,
                languages=languages, engine='Tesseract',
                dpi_hint=200,
                mean_word_confidence=round(sum(word['confidence'] for word in words) / len(words), 3) if words else None,
                note='Derived OCR transcription; errors and omissions are possible; confidence is an OCR engine score')
