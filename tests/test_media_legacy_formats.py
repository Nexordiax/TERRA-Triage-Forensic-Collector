"""Real offline codecs and independent binary Office fixtures."""
import hashlib
import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import numpy as np
from PIL import Image, TiffImagePlugin
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from analyzers.content import analyze as isolated, eligible
from analyzers.content_worker import analyze
from analyzers.documents import extract
from analyzers.image_formats import open_image, RAW_IMAGES, PICTURE_FILTER
from analyzers.image_similarity import read_reference
from analyzers.video import analyze_video
from artifacts.file_collector import FileCollector
from artifacts.pictures.collector import classify
from controllers.scan_controller import ScanEngine
from interface.main_window import MainWindow
from interface.widgets.embedded_preview import EmbeddedPreview
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


def compound(streams):
    """Independent minimal OLE v3 file with regular 4096-byte test streams."""
    header = bytearray(512)
    header[:8] = bytes.fromhex('d0cf11e0a1b11ae1')
    struct.pack_into('<HHHHH', header, 24, 0x3e, 3, 0xfffe, 9, 6)
    struct.pack_into('<IIIIIIIII', header, 40, 0, 1, 1, 0, 4096, 0xfffffffe, 0, 0xfffffffe, 0)
    struct.pack_into('<109I', header, 76, 0, *([0xffffffff] * 108))
    fat = [0xffffffff] * 128
    fat[0], fat[1] = 0xfffffffd, 0xfffffffe
    directory = bytearray(512)
    def entry(index, name, kind, child, right, start, size):
        offset = index * 128
        encoded = (name + '\0').encode('utf-16-le')
        directory[offset:offset + len(encoded)] = encoded
        struct.pack_into('<HBBIII', directory, offset + 64, len(encoded), kind, 1, 0xffffffff, right, child)
        struct.pack_into('<IQ', directory, offset + 116, start, size)
    entry(0, 'Root Entry', 5, 1, 0xffffffff, 0xfffffffe, 0)
    bodies = []
    for index, (name, data) in enumerate(streams.items(), 1):
        assert len(data) <= 4096 and index <= 3
        start = 2 + (index - 1) * 8
        for sector in range(start, start + 8):
            fat[sector] = sector + 1 if sector != start + 7 else 0xfffffffe
        entry(index, name, 2, 0xffffffff, index + 1 if index < len(streams) else 0xffffffff, start, 4096)
        bodies.append(data.ljust(4096, b'\0'))
    return bytes(header) + struct.pack('<128I', *fat) + bytes(directory) + b''.join(bodies)


def word_document(encrypted=False):
    data = bytearray(4096)
    struct.pack_into('<HH', data, 0, 0xa5ec, 0xc1)
    struct.pack_into('<H', data, 10, 0x0200 | (0x0100 if encrypted else 0))
    struct.pack_into('<H', data, 32, 14)
    struct.pack_into('<H', data, 62, 22)
    struct.pack_into('<H', data, 152, 93)
    first, second = b'nee', 'dle שלום\r'.encode('utf-16-le')
    data[1800:1800 + len(first)] = first
    data[2200:2200 + len(second)] = second
    cps = [0, len(first), len(first) + len(second) // 2]
    plc = struct.pack('<3I', *cps) + struct.pack('<HIH', 0, 0x40000000 | 3600, 0) + struct.pack('<HIH', 0, 2200, 0)
    table = b'\x02' + struct.pack('<I', len(plc)) + plc
    struct.pack_into('<II', data, 154 + 33 * 8, 0, len(table))
    return compound({'WordDocument': data, '1Table': table})


def powerpoint_document(encrypted=False):
    def atom(kind, payload, version=0):
        return struct.pack('<HHI', version, kind, len(payload)) + payload
    text = atom(0xfa0, 'needle שלום\r'.encode('utf-16-le')) + atom(0xfa8, b'legacy caf\xe9')
    document = atom(0x3e8, text, 0xf)
    document += atom(0, bytes(4096 - len(document) - 8))
    current = atom(0xff6, struct.pack('<III', 20, 0xf3d1c4df if encrypted else 0xe391c05f, 0) + bytes(12))
    return compound({'PowerPoint Document': document, 'Current User': current})


def raw_dng():
    tags = TiffImagePlugin.ImageFileDirectory_v2()
    tags[262], tags[33421], tags[33422] = 32803, (2, 2), bytes([0, 1, 1, 2])
    tags[50706], tags[50707], tags[50708] = bytes([1, 4, 0, 0]), bytes([1, 1, 0, 0]), 'TERRA Synthetic Camera'
    tags[50717], tags[50721], tags[50728], tags[50778] = 4095, (1, 0, 0, 0, 1, 0, 0, 0, 1), (1, 1, 1), 21
    output = io.BytesIO()
    with Image.fromarray(np.full((64, 64), 2048, dtype=np.uint16)) as image:
        image.save(output, format='TIFF', tiffinfo=tags)
    return output.getvalue()


class MediaLegacyFormatsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def picture(self, format):
        import pillow_heif
        pillow_heif.register_heif_opener()
        output = io.BytesIO()
        with Image.new('RGB', (64, 48), (180, 130, 100)) as image:
            image.save(output, format=format)
        return output.getvalue()

    def test_heif_avif_and_raw_native_decoding_screening_and_reference_import(self):
        for suffix, data in (('.heic', self.picture('HEIF')), ('.avif', self.picture('AVIF')), ('.dng', raw_dng())):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / ('picture' + suffix)
                path.write_bytes(data)
                self.assertEqual(classify(str(path)), 'Pictures')
                self.assertTrue(eligible(str(path), {'skin_tone': True}))
                metadata = dict(size=len(data), sha256=hashlib.sha256(data).hexdigest(), content_retained=True)
                result = isolated(str(path), metadata, data, None, {'skin_tone': True, 'skin_method': 'colour'}, lambda: False)
                self.assertEqual(result['status'], 'parsed', result['limitations'])
                self.assertEqual(result['entries'][0]['type'], 'skin_colour_screen')
                reference = read_reference(path)
                self.assertEqual(reference['sha256'], metadata['sha256'])
                self.assertEqual(len(reference['fingerprint']), 64)
                self.assertIn('*' + suffix, PICTURE_FILTER)
                preview = isolated(str(path), metadata, data, None, {'_preview_spec': {'steps': [dict(kind='image_frame', index=0)]}}, lambda: False)
                self.assertEqual(preview['status'], 'parsed', preview['limitations'])
                self.assertTrue(preview['preview_png'])
                if suffix == '.dng':
                    self.assertEqual(preview['original_dimensions'], [32, 32])
                    self.assertTrue(result['entries'][0]['image_transform']['decode_details']['half_size'])

    def test_raw_aliases_and_video_extensions_are_classified_and_optional(self):
        for suffix in RAW_IMAGES | {'.heif', '.hif', '.avif'}:
            self.assertEqual(classify('camera' + suffix), 'Pictures')
        for suffix in ('.wmv', '.asf', '.flv', '.ts', '.mts', '.m2ts', '.m2t', '.3gp', '.3g2', '.ogv'):
            self.assertEqual(classify('movie' + suffix), 'Videos')
            self.assertFalse(eligible('movie' + suffix, {'skin_tone': True}))
            self.assertTrue(eligible('movie' + suffix, {'skin_videos': True}))

    def test_flv_asf_and_transport_stream_decode_offline(self):
        import av
        for format, codec, suffix in (('flv', 'flv1', '.flv'), ('asf', 'wmv2', '.wmv'), ('mpegts', 'mpeg2video', '.mts')):
            with self.subTest(format=format):
                output = io.BytesIO()
                with av.open(output, 'w', format=format) as container:
                    stream = container.add_stream(codec, rate=5)
                    stream.width, stream.height, stream.pix_fmt = 64, 48, 'yuv420p'
                    stream.codec_context.thread_count = 1
                    for index in range(10):
                        frame = av.VideoFrame.from_ndarray(np.full((48, 64, 3), [180, 130, 100], dtype=np.uint8), format='rgb24')
                        for packet in stream.encode(frame): container.mux(packet)
                    for packet in stream.encode(): container.mux(packet)
                result = analyze_video(io.BytesIO(output.getvalue()), {'skin_videos': True, 'skin_method': 'colour', 'video_skin_interval': 1})
                self.assertTrue(result['entries'], result['limitations'])
                self.assertEqual(result['entries'][0]['media_kind'], 'video')

    def test_binary_word_and_powerpoint_stored_unicode_text(self):
        doc_rows = extract(word_document(), 'evidence.doc')
        self.assertIn('needle שלום', doc_rows[0]['text'])
        self.assertIn('clx:', doc_rows[0]['locator'])
        ppt_rows = extract(powerpoint_document(), 'evidence.ppt')
        self.assertEqual([row['text'] for row in ppt_rows], ['needle שלום\n', 'legacy café'])
        self.assertTrue(all('historical' in row['note'] for row in ppt_rows))

    def test_native_legacy_excel_cells_and_hidden_sheet(self):
        import xlwt
        book = xlwt.Workbook()
        sheet = book.add_sheet('Evidence')
        sheet.write(0, 0, 'needle שלום')
        sheet.write(0, 1, 42)
        hidden = book.add_sheet('Hidden')
        hidden.visibility = 1
        hidden.write(0, 0, 'secret')
        output = io.BytesIO()
        book.save(output)
        rows = extract(output.getvalue(), 'evidence.xls')
        self.assertIn('needle שלום\t42', rows[0]['text'])
        self.assertTrue(rows[1]['hidden'])

    def test_encrypted_and_malformed_legacy_documents_are_not_claimed_decoded(self):
        for suffix, data in (('.doc', word_document(True)), ('.ppt', powerpoint_document(True)), ('.xls', b'invalid')):
            result = analyze(data, suffix, {'extract_documents': True})
            self.assertEqual(result['status'], 'failed')
            self.assertFalse(result['entries'])
            self.assertTrue(result['limitations'])

    def test_legacy_text_matches_across_word_pieces_and_preserves_export_bytes(self):
        from controllers.export_controller import ZipExporter
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as destination:
            path = Path(directory) / 'evidence.doc'
            original = word_document()
            path.write_bytes(original)
            config = configuration('matches_only', keywords=['needle שלום'], file_contents=True)
            config['analysis_options'] = {'extract_documents': True}
            store = MemoryStore()
            summary = ScanEngine({'paths': [directory]}, config, store).run()
            self.assertEqual(summary['status'], 'completed')
            self.assertEqual(len(store.records), 1)
            self.assertIn('needle שלום', store.records[0]['matches']['file_contents'])
            self.assertEqual(store.records[0]['data'], original)
            records, logs, count = store.snapshot()
            target = Path(destination) / 'results.zip'
            ZipExporter(records, logs, count, {'targets': {'paths': [directory]}}).save(target)
            with zipfile.ZipFile(target) as archive:
                paths = [name for name in archive.namelist() if name.endswith('/evidence.doc')]
                self.assertEqual(len(paths), 1)
                self.assertEqual(archive.read(paths[0]), original)

    def test_gui_extended_picture_preview_uses_isolated_decoder(self):
        from shiboken6 import delete
        previous = self.app.quitOnLastWindowClosed()
        self.app.setQuitOnLastWindowClosed(False)
        self.addCleanup(self.app.setQuitOnLastWindowClosed, previous)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'picture.avif'
            path.write_bytes(self.picture('AVIF'))
            data, metadata = FileCollector().collect(str(path), lambda: False)
            window = MainWindow()
            window.scan_controller.store.add(dict(metadata, path=str(path), kind='file', category='Pictures', matches={}), data)
            window.preview_media(0)
            dialog = window.findChild(EmbeddedPreview)
            self.assertIsNotNone(dialog)
            loop = QEventLoop()
            dialog.worker.finished.connect(loop.quit)
            QTimer.singleShot(5000, loop.quit)
            loop.exec()
            self.app.processEvents()
            self.assertTrue(hasattr(dialog, 'picture'), dialog.message.text())
            self.assertEqual(dialog.picture.original_pixmap.width(), 64)
            dialog.close()
            delete(window)
