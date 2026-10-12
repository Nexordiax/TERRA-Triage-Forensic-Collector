"""Cancelable isolated analysis of verified acquired document/image bytes."""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from artifacts.parser_support import check_cancelled, read_verified
from analyzers.video import VIDEOS, video_enabled, open_source, verify_source
from analyzers.containers import ARCHIVES, OFFICE
from analyzers.image_formats import IMAGES

DOCUMENTS = {'.pdf', '.doc', '.xls', '.ppt', '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp', '.rtf'}
SOURCES = ['https://pypdfium2-team.github.io/pypdfium2/python_api.html',
           'https://tesseract-ocr.github.io/tessdoc/Command-Line-Usage.html',
           'https://arxiv.org/abs/1708.02694']


def eligible(path, options):
    suffix = Path(path).suffix.lower()
    return (suffix in ARCHIVES | OFFICE or suffix in DOCUMENTS and (options.get('extract_documents') or suffix == '.pdf' and options.get('document_images') and (options.get('_inventory_embedded') or options.get('ocr') and options.get('ocr_pdf', True) or any(options.get(key) for key in ('skin_tone', 'image_references')))) or
            suffix in IMAGES and (options.get('ocr') or options.get('skin_tone') or options.get('image_references')) or
            suffix in VIDEOS and video_enabled(options))


def analyze(path, metadata, data, directory_fd, options, cancelled, timeout=120, max_result_bytes=16 * 1024 * 1024):
    result = dict(artifact_id='document_image_analysis', parser='local_content_analysis', parser_version=1,
                  status='failed', entries=[], record_count=0, limitations=[], sources=list(SOURCES),
                  inputs=[dict(path=path, sha256=metadata['sha256'], size=metadata['size'])])
    if Path(path).suffix.lower() in ARCHIVES | OFFICE:
        result['sources'].extend(['https://github.com/Changaco/python-libarchive-c', 'https://www.rarlab.com/rar_add.htm',
                                  'https://github.com/danifus/pyzipper', 'https://py7zr.readthedocs.io/en/latest/advanced.html'])
    if Path(path).suffix.lower() in {'.doc', '.xls', '.ppt'}:
        result['sources'].extend(['https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/01d5d8c4-cf9c-4ef9-80fd-439e763cfe01',
                                 'https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/a3c5c8d5-e530-4167-a242-7743bc99aeac',
                                 'https://xlrd.readthedocs.io/en/stable/'])
    if options.get('image_references'):
        result['sources'].append('https://www.phash.org/docs/design.html')
    if options.get('skin_method') == 'semantic':
        result['sources'].append('https://developers.google.com/edge/mediapipe/solutions/vision/image_segmenter')
    check_cancelled(cancelled)
    if max_result_bytes <= 0:
        result['limitations'].append('Scan derived-analysis result budget reached; original acquisition and hash matching continue')
        return result
    suffix = Path(path).suffix.lower()
    video = suffix in VIDEOS and video_enabled(options)
    archive_stream = suffix in ARCHIVES | OFFICE and (metadata['size'] > 64 * 1024 * 1024 or not metadata.get('content_retained', True))
    streamed = video or archive_stream
    if metadata['size'] > 64 * 1024 * 1024 and not streamed:
        result['limitations'].append('File exceeds the 64 MiB derived-analysis input bound; full acquisition and hash matching remain available')
        return result
    if not metadata.get('content_retained', True) and not streamed:
        data, _ = read_verified(path, metadata, directory_fd, cancelled)
    command = [sys.executable, '-m', 'analyzers.content_worker', '@stdin', suffix]
    source = None
    if streamed:
        try:
            source = open_source(path, metadata, directory_fd)
            command.append(str(source.fileno()))
        except (OSError, ValueError) as error:
            if archive_stream:
                raise
            result['limitations'].append(str(error))
            return result
    environment = {key: value for key, value in os.environ.items() if key not in (
        'PYTHONPATH', 'PYTHONHOME', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES')}
    environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', OMP_THREAD_LIMIT='1', OPENBLAS_NUM_THREADS='1', ORT_DISABLE_TELEMETRY='1')
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=Path(__file__).resolve().parent.parent, env=environment, start_new_session=True,
                                   pass_fds=(source.fileno(),) if source else ())
    except OSError as error:
        if source:
            source.close()
        result['limitations'].append(f'Cannot start local analysis worker: {error}')
        return result
    started = time.monotonic()
    encoded_options = json.dumps(options, ensure_ascii=True).encode('utf-8')
    payload = len(encoded_options).to_bytes(8, 'big') + encoded_options + (b'' if streamed else data)
    try:
        while True:
            check_cancelled(cancelled)
            if time.monotonic() - started > timeout:
                raise ValueError('Document/image analysis timeout reached')
            try:
                output, error = process.communicate(input=payload, timeout=0.15)
                break
            except subprocess.TimeoutExpired:
                payload = None
        if process.returncode:
            result['worker_exit_code'] = process.returncode
            detail = error.decode('utf-8', errors='replace').strip()[-2000:]
            if process.returncode < 0:
                try:
                    detail = signal.Signals(-process.returncode).name + (' · ' + detail if detail else '')
                except ValueError:
                    pass
            raise ValueError(f'Analysis worker failed ({process.returncode}); original evidence retained' +
                             (f'. Worker diagnostic: {detail}' if detail else '. No worker diagnostic was available.'))
        if len(output) > min(16 * 1024 * 1024, max_result_bytes):
            raise ValueError('Analysis result exceeds the remaining derived-analysis budget; original evidence retained')
        parsed = json.loads(output)
        if source:
            verify_source(source, path, metadata, directory_fd, cancelled)
        result.update(parsed, record_count=len(parsed['entries']))
    except (OSError, ValueError) as error:
        result['limitations'].append(str(error))
    finally:
        if process.poll() is None:
            if os.name == 'posix':
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
        process.communicate()
        if source:
            source.close()
    return result
