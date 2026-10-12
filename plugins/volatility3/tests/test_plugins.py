"""Standalone tests; run with a Python environment containing Volatility 3."""
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import volatility3.plugins
from volatility3.framework import contexts

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
volatility3.plugins.__path__.insert(0, str(PLUGIN_ROOT))
plugins = importlib.import_module('volatility3.plugins.terramemory')
reader = importlib.import_module('volatility3.plugins.terra_support.capture')


def fixture(path, version=2, data=b'HELLO secret\0TAIL'):
    member = 'processes/42/regions/000000-1000-3000.bin'
    region = dict(start=0x1000, end_exclusive=0x3000, permissions='r--p', complete=False,
                  archive_path=member, captured_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                  acquired_at='2026-10-11T10:00:00+00:00', completed_at='2026-10-11T10:00:01+00:00',
                  segments=[dict(virtual_start=0x1000, file_offset=0, length=len(data) - 4),
                            dict(virtual_start=0x2000, file_offset=len(data) - 4, length=4)])
    manifest = dict(format='terra-process-memory', format_version=version, complete_physical_ram=False,
                    processes=[dict(pid=42, regions=[region], captured_bytes=len(data),
                                    command_line=dict(status='available', argv=['example', '--test']))],
                    unavailable_processes=[dict(pid=43, access_status='denied', access_errno=13)])
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr(member, data)
        archive.writestr('manifest.json', json.dumps(manifest))
    return manifest, member


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'capture.zip'
        self.manifest, self.member = fixture(self.path)

    def rewrite(self, manifest=None, data=b'HELLO secret\0TAIL'):
        with zipfile.ZipFile(self.path, 'w') as archive:
            archive.writestr(self.member, data)
            archive.writestr('manifest.json', json.dumps(manifest or self.manifest))

    def test_v1_v2_and_directory(self):
        for version in (1, 2):
            fixture(self.path, version)
            with reader.Capture(self.path) as capture:
                self.assertEqual(list(capture.processes())[0]['pid'], 42)
                region = capture.manifest['processes'][0]['regions'][0]
                self.assertEqual(capture.digest(region), region['sha256'])
        directory = self.root / 'extracted'
        directory.mkdir()
        with zipfile.ZipFile(self.path) as archive:
            archive.extractall(directory)  # only this test's trusted synthetic fixture
        with reader.Capture(directory) as capture:
            self.assertEqual(capture.size(self.member), 17)

    def test_boundary_search_and_gap_never_joined(self):
        with reader.Capture(self.path) as capture:
            region = self.manifest['processes'][0]['regions'][0]
            self.assertEqual(list(reader.search(capture, region, b'secret', chunk_size=3)), [0x1006])
            self.assertEqual(list(reader.search(capture, region, b'SECRET', True, chunk_size=2)), [0x1006])
            self.assertEqual(list(reader.search(capture, region, b'\0TAIL', chunk_size=3)), [])
            self.assertEqual(list(reader.search(capture, region, b'TAIL', chunk_size=2)), [0x2000])

    def test_ascii_strings_streamed_without_gap_joining(self):
        with reader.Capture(self.path) as capture:
            region = self.manifest['processes'][0]['regions'][0]
            self.assertEqual(list(reader.strings(capture, region, minimum=4, chunk_size=3)),
                             [(0x1000, 'HELLO secret'), (0x2000, 'TAIL')])

    def test_utf16_both_alignments_and_odd_chunk_boundaries(self):
        for encoding in ('utf-16-le', 'utf-16-be'):
            for prefix in (b'', b'\xff'):
                data = prefix + 'evidence'.encode(encoding) + b'\0\0' + b'LAST'
                manifest, unused = fixture(self.path, data=data)
                with reader.Capture(self.path) as capture:
                    values = list(reader.strings(capture, manifest['processes'][0]['regions'][0], 6, encoding, 3))
                    self.assertIn((0x1000 + len(prefix), 'evidence'), values)

    def test_tampered_hash_detected(self):
        self.rewrite(data=b'WRONG secret\0TAIL')
        with reader.Capture(self.path) as capture:
            region = self.manifest['processes'][0]['regions'][0]
            self.assertNotEqual(capture.digest(region), region['sha256'])

    def test_zip_crc_failure_reported_by_verify(self):
        with zipfile.ZipFile(self.path) as archive:
            offset = archive.getinfo(self.member).header_offset
        with self.path.open('r+b') as output:
            output.seek(offset + 26)
            import struct
            name_length, extra_length = struct.unpack('<HH', output.read(4))
            output.seek(offset + 30 + name_length + extra_length)
            output.write(b'!')
        result = list(self.plugin(plugins.Verify)._generator())
        self.assertTrue(result[0][1][-1].startswith('ERROR:'))
        self.assertIn('CRC', result[0][1][-1])

    def test_invalid_segment_and_member_size_rejected(self):
        self.manifest['processes'][0]['regions'][0]['segments'][1]['file_offset'] = 0
        self.rewrite()
        with self.assertRaisesRegex(ValueError, 'segment'):
            reader.Capture(self.path)
        self.manifest, unused = fixture(self.path)
        self.rewrite(data=b'few')
        with self.assertRaisesRegex(ValueError, 'size'):
            reader.Capture(self.path)

    def test_traversal_duplicate_and_non_capture_rejected(self):
        self.manifest['processes'][0]['regions'][0]['archive_path'] = '../escape'
        self.rewrite()
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            reader.Capture(self.path)
        self.manifest, unused = fixture(self.path)
        with zipfile.ZipFile(self.path, 'a') as archive:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                archive.writestr(self.member, b'other')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            reader.Capture(self.path)
        self.manifest['format'] = 'other'
        self.rewrite()
        with self.assertRaisesRegex(ValueError, 'Expected'):
            reader.Capture(self.path)

    def test_symlink_outside_extracted_capture_rejected(self):
        directory = self.root / 'extracted'
        directory.mkdir()
        (directory / 'manifest.json').symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'escapes'):
            reader.Capture(directory)

    def plugin(self, cls, **options):
        context = contexts.Context()
        context.config['test.capture'] = str(self.path)
        for key, value in options.items():
            context.config[f'test.{key}'] = value
        return cls(context, 'test')

    def test_plugin_treegrids_and_denied_metadata(self):
        for cls in (plugins.Processes, plugins.Maps, plugins.Strings, plugins.Verify):
            plugin = self.plugin(cls)
            grid = plugin.run()
            rows = []
            grid.populate(lambda node, accumulator: accumulator.append(node.values) or accumulator, rows)
            self.assertTrue(rows)
        rows = list(self.plugin(plugins.Processes)._generator())
        self.assertEqual(rows[1][1][0:2], (43, 'denied'))
        rows = list(self.plugin(plugins.Search, needle='secret')._generator())
        self.assertEqual(rows[0][1][1], 0x1006)
        self.assertEqual(list(self.plugin(plugins.Processes, pid=[999])._generator()), [])

    def test_verify_mismatch_and_dump_refusal(self):
        self.rewrite(data=b'WRONG secret\0TAIL')
        self.assertEqual(list(self.plugin(plugins.Verify)._generator())[0][1][-1], 'MISMATCH')
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            list(self.plugin(plugins.Dump)._generator())

    def test_limits_and_invalid_options(self):
        self.assertEqual(len(list(self.plugin(plugins.Strings, minimum=4, limit=1)._generator())), 1)
        with self.assertRaises(ValueError):
            list(self.plugin(plugins.Search, needle='')._generator())
        with self.assertRaises(ValueError):
            list(self.plugin(plugins.Strings, minimum=0)._generator())

    @unittest.skipUnless(os.environ.get('TERRA_VOL3_CLI'), 'Set TERRA_VOL3_CLI to vol.py for CLI integration tests')
    def test_real_cli_discovery_analysis_and_dump(self):
        (self.root / 'cache').mkdir()
        base = [sys.executable, os.environ['TERRA_VOL3_CLI'], '--offline', '--cache-path', str(self.root / 'cache'),
                '-p', str(PLUGIN_ROOT), '-q']
        for name, options in [('Processes', []), ('Maps', []), ('Strings', ['--minimum', '4']),
                              ('Search', ['--needle', 'secret']), ('Verify', []), ('Dump', [])]:
            command = base + ['-o', str(self.root), f'terramemory.{name}', '--capture', str(self.path)] + options
            result = subprocess.run(command, capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn('42', result.stdout)
        raw = next(self.root.glob('terra-pid-42-*.bin'))
        sidecar = next(self.root.glob('terra-pid-42-*.json'))
        self.assertEqual(raw.read_bytes(), b'HELLO secret\0TAIL')
        metadata = json.loads(sidecar.read_text())
        self.assertTrue(metadata['sha256_verified'])
        self.assertEqual(metadata['dumped_file'], raw.name)
        self.assertEqual(metadata['region']['segments'][1]['virtual_start'], 0x2000)
        with zipfile.ZipFile(self.path) as archive:
            self.assertEqual(archive.read(self.member), raw.read_bytes())


if __name__ == '__main__':
    unittest.main()
