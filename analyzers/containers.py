"""Bounded streaming archive traversal; member paths are never extracted."""
import bz2
import gzip
import hashlib
import io
import lzma
from pathlib import PurePosixPath
import tarfile

from analyzers.archive_readers import zip_members, native_members, sevenzip_members

ARCHIVES = {'.zip', '.tar', '.tgz', '.gz', '.bz2', '.xz', '.tbz', '.tbz2', '.txz', '.rar', '.7z'}
OFFICE = {'.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp'}
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_MEMBER_ANALYSIS = 32 * 1024 * 1024
MAX_DEPTH = 5
MAX_MEMBERS = 10000


def search(data, suffix, options, analyze, budget=None, prefix='', depth=0, steps=None):
    if suffix in OFFICE:
        options = dict(options, _document_context=True)
    from analyzers.matching.keyword_matcher import KeywordMatcher
    from analyzers.video import VIDEOS, video_enabled
    from analyzers.content import DOCUMENTS, IMAGES
    budget = budget if budget is not None else {'bytes': MAX_EXPANDED, 'members': MAX_MEMBERS}
    result = dict(entries=[], limitations=[], status='parsed', archive_coverage={
        'members_searched': 0, 'expanded_bytes_searched': 0, 'skipped_members': 0,
        'needs_credentials': False, 'format': suffix})
    if depth >= MAX_DEPTH:
        return dict(result, limitations=[prefix + ': archive nesting limit reached'], status='failed')
    keywords = KeywordMatcher(options.get('container_keywords', []))
    names = KeywordMatcher(options.get('container_name_keywords', []))
    hashes = set(options.get('container_hashes', []))
    algorithms = {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}
    passwords = options.get('_archive_passwords', [])[:32]
    source = io.BytesIO(data) if isinstance(data, (bytes, bytearray)) else data
    steps = steps or []

    def limitation(message):
        for candidate in passwords:
            message = message.replace(candidate['secret'], '[redacted]')
        result['limitations'].append(message)
        result['archive_coverage']['skipped_members'] += 1
        if any(word in message.lower() for word in ('encrypted', 'credential', 'passphrase', 'password')):
            result['archive_coverage']['needs_credentials'] = True

    def member(name, blocks, size=None, index=0, credential=None):
        locator = prefix + 'member:' + name
        if budget['members'] <= 0:
            raise ValueError('Archive member count limit reached')
        if size is not None and size > budget['bytes']:
            limitation(locator + ': expanded member exceeds remaining byte bound')
            return
        budget['members'] -= 1
        child_suffix = PurePosixPath(name).suffix.lower()
        analyzable = child_suffix in ARCHIVES | OFFICE | DOCUMENTS | IMAGES or child_suffix in VIDEOS and video_enabled(options)
        if options.get('_document_context') and not options.get('document_images') and child_suffix in IMAGES | VIDEOS:
            analyzable = False
        payload = bytearray() if analyzable and (size is None or size <= MAX_MEMBER_ANALYSIS) else None
        digests = {algorithm: hashlib.new(algorithm, usedforsecurity=False)
                   for algorithm in {'sha256'} | {algorithms[len(value)] for value in hashes if len(value) in algorithms}}
        matcher = keywords.stream()
        count = 0
        for chunk in blocks:
            count += len(chunk)
            if len(chunk) > budget['bytes']:
                raise ValueError(locator + ': expanded byte limit reached')
            budget['bytes'] -= len(chunk)
            if size is not None and count > size:
                raise ValueError(locator + ': member exceeds declared size')
            for digest in digests.values(): digest.update(chunk)
            matcher.update(chunk)
            if payload is not None:
                if count <= MAX_MEMBER_ANALYSIS: payload.extend(chunk)
                else: payload = None
        if size is not None and count != size:
            raise ValueError(locator + ': truncated member; results discarded')
        digest = digests['sha256'].hexdigest()
        path_steps = steps + [dict(kind='archive_member', name=name, index=index, sha256=digest, suffix=suffix)]
        row = dict(type='archive_member', locator=locator, member_name=name, size=count, sha256=digest,
                   matched_hashes={algorithm: value.hexdigest() for algorithm, value in digests.items() if value.hexdigest() in hashes},
                   matched_content=matcher.matches(), matched_names=names.match_name(name) if options.get('container_file_names') else [],
                   note='Complete member bytes searched in memory; unchanged enclosing container retained')
        if child_suffix in IMAGES:
            row['preview'] = dict(steps=path_steps + [dict(kind='image_frame', index=0)], label=name)
        if credential:
            row['decryption'] = {key: value for key, value in credential.items() if key != 'secret'}
        result['entries'].append(row)
        result['archive_coverage']['members_searched'] += 1
        result['archive_coverage']['expanded_bytes_searched'] += count
        if not analyzable:
            return
        if payload is None:
            limitation(locator + ': full member hashes/keywords searched; nested/media decoding exceeds 32 MiB bound')
            return
        child_options = dict(options, _embedded_context=True,
                             container_compressed_tar=name.lower().endswith(('.tar.gz', '.tar.bz2', '.tar.xz')),
                             container_stream_name=str(PurePosixPath(name).with_suffix('')))
        if child_suffix in ARCHIVES | OFFICE:
            child = search(bytes(payload), child_suffix, child_options, analyze, budget, locator + '/', depth + 1, path_steps)
            if child_suffix in OFFICE and options.get('extract_documents'):
                try:
                    from analyzers.documents import extract
                    text_rows = extract(bytes(payload), name)
                    for entry in text_rows: entry['locator'] = locator + '/' + entry['locator']
                    child['entries'] = list(text_rows) + child['entries']
                except Exception as error:
                    child['limitations'].append('Embedded Office text: ' + str(error))
        else:
            child = analyze(bytes(payload), child_suffix, child_options)
        for entry in child['entries']:
            if child_suffix not in ARCHIVES | OFFICE:
                entry['locator'] = locator + '/' + entry.get('locator', '')
                if entry.get('preview'):
                    entry['preview'] = dict(entry['preview'], steps=path_steps + entry['preview']['steps'])
            entry['container_member_sha256'] = digest
            result['entries'].append(entry)
        if child.get('archive_coverage'):
            for key in ('members_searched', 'expanded_bytes_searched', 'skipped_members'):
                result['archive_coverage'][key] += child['archive_coverage'].get(key, 0)
        if child.get('archive_coverage', {}).get('needs_credentials'):
            result['archive_coverage']['needs_credentials'] = True
        result['limitations'].extend(locator + ': ' + note for note in child['limitations'])

    try:
        if suffix in {'.zip'} | OFFICE:
            zip_members(source, passwords, member, limitation, budget['members'])
        elif suffix == '.rar':
            initial = list(result['entries']), dict(budget), dict(result['archive_coverage'])
            try:
                native_members(source, suffix, passwords, member, limitation, budget['members'])
            except Exception:
                partial = list(result['entries']), dict(budget), dict(result['archive_coverage'])
                result['entries'] = initial[0]
                budget.update(initial[1]); result['archive_coverage'] = initial[2]
                try:
                    from analyzers.rar_native import members as rar_members
                    source.seek(0)
                    rar_members(source, passwords, member, limitation, budget['members'], min(budget['bytes'], 64 * 1024 * 1024))
                except Exception:
                    result['entries'] = partial[0]
                    budget.update(partial[1]); result['archive_coverage'] = partial[2]
                    raise
        elif suffix == '.7z':
            before = len(result['entries']), dict(budget), dict(result['archive_coverage'])
            try:
                native_members(source, suffix, passwords, member, limitation, budget['members'])
            except Exception:
                del result['entries'][before[0]:]
                budget.update(before[1]); result['archive_coverage'] = before[2]
                source.seek(0)
                sevenzip_members(source, passwords, member, limitation, budget['members'], min(budget['bytes'], 64 * 1024 * 1024))
        elif suffix in {'.gz', '.bz2', '.xz'}:
            opener = {'.gz': gzip.GzipFile, '.bz2': bz2.BZ2File, '.xz': lzma.LZMAFile}[suffix]
            with opener(source) as stream:
                name = 'decompressed.tar' if options.get('container_compressed_tar') else options.get('container_stream_name', 'decompressed')
                member(name, iter(lambda: stream.read(1024 * 1024), b''))
        else:
            with tarfile.open(fileobj=source, mode='r|*') as archive:
                seen = set()
                for index, info in enumerate(archive):
                    if index >= MAX_MEMBERS:
                        limitation('Archive entry limit reached'); break
                    if not info.isfile():
                        if not info.isdir(): limitation(info.name + ': nonregular member skipped')
                        continue
                    if info.name in seen:
                        limitation('Duplicate member name skipped: ' + info.name); continue
                    seen.add(info.name)
                    with archive.extractfile(info) as stream:
                        member(info.name, iter(lambda: stream.read(1024 * 1024), b''), info.size, index)
    except Exception as error:
        limitation(f'{type(error).__name__}: {error}')
    if result['limitations']:
        result['status'] = 'partial' if result['entries'] else 'failed'
    return result
