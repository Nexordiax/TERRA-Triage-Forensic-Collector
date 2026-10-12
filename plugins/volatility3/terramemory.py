"""Offline analysis of TERRA non-root process-memory ZIPs, without symbols."""
import hashlib
import json
import logging
import zipfile

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.terra_support.capture import Capture, search, strings

LOG = logging.getLogger(__name__)
HEX = format_hints.Hex


def text(value):
    return '' if value is None else str(value)


class CaptureOptions:
    """Requirements shared by concrete plugins; not a discoverable plugin."""
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.StringRequirement(name='capture', description='Local TERRA process-memory ZIP or extracted capture directory'),
                requirements.ListRequirement(name='pid', element_type=int, optional=True,
                                             description='Only these PIDs', default=[])]

    def capture(self):
        return Capture(self.config['capture'])

    def selected(self, capture):
        return capture.processes(self.config.get('pid', []))


class Processes(CaptureOptions, interfaces.plugins.PluginInterface):
    """List captured and inaccessible processes with context and change checks."""
    def _generator(self):
        with self.capture() as capture:
            groups = [('captured', capture.manifest['processes']),
                      ('unavailable', capture.manifest.get('unavailable_processes', [])),
                      ('excluded', capture.manifest.get('excluded_processes', []))]
            for status, processes in groups:
                for process in processes:
                    if self.config.get('pid') and process['pid'] not in self.config['pid']:
                        continue
                    executable = process.get('executable', {})
                    command = process.get('command_line', {})
                    checks = {key: process[key] for key in process if 'changed_during_capture' in key or key.startswith('identity_')}
                    yield 0, (process['pid'], process.get('access_status', status),
                              text(executable.get('path')), text(executable.get('device')), text(executable.get('inode')),
                              json.dumps(command.get('argv', []), ensure_ascii=True),
                              text(process.get('start_time', {}).get('utc')), text(process.get('starttime_ticks')),
                              process.get('captured_bytes', 0), text(process.get('acquired_at')),
                              text(process.get('completed_at')), json.dumps(checks, sort_keys=True),
                              json.dumps({key: process[key] for key in ('access_error', 'access_errno', 'failed_operation', 'reason') if key in process}),
                              json.dumps({key: process.get(key) for key in ('executable', 'command_line', 'start_time')}, sort_keys=True))

    def run(self):
        return renderers.TreeGrid([('PID', int), ('Status', str), ('Executable', str), ('Device', str), ('Inode', str),
                                   ('Argv', str), ('StartUTC', str), ('StartTicks', str), ('CapturedBytes', int),
                                   ('AcquiredUTC', str), ('CompletedUTC', str), ('ChangeChecks', str),
                                   ('AccessFailure', str), ('ContextJSON', str)], self._generator())


class Maps(CaptureOptions, interfaces.plugins.PluginInterface):
    """List mappings, captured segments, unreadable gaps and unattempted ranges."""
    def _generator(self):
        with self.capture() as capture:
            for process in self.selected(capture):
                for mapped in process.get('mappings', []):
                    yield 0, (process['pid'], 'mapping', HEX(mapped['start']), HEX(mapped['end_exclusive']),
                              mapped['permissions'], mapped.get('capture_status', ''), '',
                              json.dumps(mapped, sort_keys=True))
                for region in process['regions']:
                    yield 0, (process['pid'], 'region', HEX(region['start']), HEX(region['end_exclusive']),
                              region['permissions'], 'complete' if region['complete'] else 'partial',
                              region['archive_path'], json.dumps({key: value for key, value in region.items() if key not in ('segments', 'gaps')}, sort_keys=True))
                    cursor = region['start']
                    for segment in region['segments']:
                        if segment['virtual_start'] > cursor:
                            yield self._gap(process, region, cursor, segment['virtual_start'])
                        end = segment['virtual_start'] + segment['length']
                        yield 0, (process['pid'], 'segment', HEX(segment['virtual_start']), HEX(end),
                                  region['permissions'], 'captured', region['archive_path'], json.dumps(segment, sort_keys=True))
                        cursor = end
                    if cursor < region['end_exclusive']:
                        yield self._gap(process, region, cursor, region['end_exclusive'])

    @staticmethod
    def _gap(process, region, start, end):
        details = [gap for gap in region.get('gaps', []) + region.get('not_attempted_ranges', [])
                   if gap['virtual_start'] < end and gap['virtual_start'] + gap['length'] > start]
        return 0, (process['pid'], 'gap', HEX(start), HEX(end), region['permissions'], 'not_captured',
                   region['archive_path'], json.dumps(details) if details else 'Reason unavailable in this manifest; bytes are absent, not zero')

    def run(self):
        return renderers.TreeGrid([('PID', int), ('Kind', str), ('Start', HEX), ('EndExclusive', HEX),
                                   ('Permissions', str), ('Status', str), ('Member', str), ('Details', str)], self._generator())


class Strings(CaptureOptions, interfaces.plugins.PluginInterface):
    """Extract printable ASCII/ASCII-range UTF-16 strings at virtual addresses."""
    @classmethod
    def get_requirements(cls):
        return super().get_requirements() + [
            requirements.IntRequirement(name='minimum', description='Minimum characters (1–4096)', optional=True, default=6),
            requirements.StringRequirement(name='encoding', description='ascii, utf-16-le or utf-16-be', optional=True, default='ascii'),
            requirements.IntRequirement(name='limit', description='Maximum rows; 0 for unlimited', optional=True, default=10000)]

    def _generator(self):
        minimum, encoding, limit = self.config['minimum'], self.config['encoding'], self.config['limit']
        if not 1 <= minimum <= 4096 or encoding not in ('ascii', 'utf-16-le', 'utf-16-be') or limit < 0:
            raise ValueError('Invalid strings options')
        count = 0
        with self.capture() as capture:
            for process in self.selected(capture):
                for region in process['regions']:
                    for address, value in strings(capture, region, minimum, encoding):
                        if limit and count >= limit:
                            LOG.warning('Strings row limit reached; use --limit 0 for all results')
                            return
                        count += 1
                        yield 0, (process['pid'], HEX(address), encoding, value, region['archive_path'])

    def run(self):
        return renderers.TreeGrid([('PID', int), ('VirtualAddress', HEX), ('Encoding', str), ('String', str), ('Member', str)], self._generator())


class Search(CaptureOptions, interfaces.plugins.PluginInterface):
    """Search captured bytes for an offline literal term, never across gaps."""
    @classmethod
    def get_requirements(cls):
        return super().get_requirements() + [
            requirements.StringRequirement(name='needle', description='Literal text to find'),
            requirements.StringRequirement(name='encoding', description='utf-8, utf-16-le, utf-16-be or hex', optional=True, default='utf-8'),
            requirements.BooleanRequirement(name='ignore-case', description='ASCII case-insensitive bytes (UTF-8/hex only)', optional=True, default=False),
            requirements.IntRequirement(name='limit', description='Maximum rows; 0 for unlimited', optional=True, default=10000)]

    def _generator(self):
        encoding = self.config['encoding']
        if encoding not in ('utf-8', 'utf-16-le', 'utf-16-be', 'hex'):
            raise ValueError('Invalid search encoding')
        if self.config['ignore-case'] and encoding.startswith('utf-16'):
            raise ValueError('UTF-16 ignore-case is unsupported; use exact case')
        needle = bytes.fromhex(self.config['needle']) if encoding == 'hex' else self.config['needle'].encode(encoding)
        if not 1 <= len(needle) <= 65536 or self.config['limit'] < 0:
            raise ValueError('Invalid search length or row limit')
        count = 0
        with self.capture() as capture:
            for process in self.selected(capture):
                for region in process['regions']:
                    for address in search(capture, region, needle, self.config['ignore-case']):
                        if self.config['limit'] and count >= self.config['limit']:
                            LOG.warning('Search row limit reached; use --limit 0 for all results')
                            return
                        count += 1
                        yield 0, (process['pid'], HEX(address), len(needle), region['archive_path'])

    def run(self):
        return renderers.TreeGrid([('PID', int), ('VirtualAddress', HEX), ('MatchBytes', int), ('Member', str)], self._generator())


class Verify(CaptureOptions, interfaces.plugins.PluginInterface):
    """Stream each selected region and compare its SHA-256 with the manifest."""
    def _generator(self):
        with self.capture() as capture:
            for process in self.selected(capture):
                for region in process['regions']:
                    try:
                        actual = capture.digest(region)
                        status = 'MATCH' if actual.lower() == region['sha256'].lower() else 'MISMATCH'
                    except (OSError, ValueError, zipfile.BadZipFile) as error:
                        actual, status = '', f'ERROR: {error}'
                    yield 0, (process['pid'], region['archive_path'], region['captured_bytes'], region['sha256'], actual, status)

    def run(self):
        return renderers.TreeGrid([('PID', int), ('Member', str), ('Bytes', int), ('ExpectedSHA256', str), ('ActualSHA256', str), ('Status', str)], self._generator())


class Dump(CaptureOptions, interfaces.plugins.PluginInterface):
    """Export verified compact region bytes and JSON virtual-address/context sidecars."""
    def _generator(self):
        with self.capture() as capture:
            for process in self.selected(capture):
                for index, region in enumerate(process['regions']):
                    if capture.digest(region).lower() != region['sha256'].lower():
                        raise ValueError('Refusing to export a region with a SHA-256 mismatch')
                    name = f"terra-pid-{process['pid']}-{index:06d}-{region['start']:x}-{region['end_exclusive']:x}"
                    digest = hashlib.sha256()
                    with self.open(name + '.bin') as output:
                        with capture.open(region['archive_path']) as source:
                            while data := source.read(1024 * 1024):
                                digest.update(data)
                                output.write(data)
                        if digest.hexdigest().lower() != region['sha256'].lower():
                            raise ValueError('Evidence changed during export; exported bytes are unverified')
                        output_name = output.preferred_filename
                    sidecar = dict(format='terra-process-region', source_capture=str(capture.path),
                                   dumped_file=output_name,
                                   memory_scope='accessible_process_memory', complete_physical_ram=False,
                                   source_format_version=capture.manifest['format_version'],
                                   process={key: value for key, value in process.items() if key != 'regions'},
                                   region=region, sha256_verified=True,
                                   note='Compact captured bytes only. Use segments for virtual addresses; absent bytes are not zero.')
                    with self.open(name + '.json') as output:
                        output.write(json.dumps(sidecar, indent=2).encode('utf-8'))
                        sidecar_name = output.preferred_filename
                    yield 0, (process['pid'], HEX(region['start']), region['captured_bytes'], output_name, sidecar_name)

    def run(self):
        return renderers.TreeGrid([('PID', int), ('VirtualStart', HEX), ('Bytes', int), ('File', str), ('AddressMapJSON', str)], self._generator())
