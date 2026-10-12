"""Offline tiling, semantic skin and opt-in video screening integration."""
import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch
from unittest.mock import Mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ['ORT_DISABLE_TELEMETRY'] = '1'
import numpy as np
from PIL import Image
from PySide6.QtWidgets import QApplication
from shiboken6 import delete

from analyzers.content import analyze, eligible
from analyzers.image_classification.analyzer import screen as colour_screen
from analyzers.image_classification.semantic import screen, skin_areas, _model
from analyzers.video import analyze_video, sample_times, open_source, verify_source
from artifacts.file_collector import FileCollector, CollectionCancelled
from controllers.scan_controller import ScanEngine
from controllers.export_controller import ZipExporter
from interface.widgets.content_options import ContentOptions
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


class MediaEnhancementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def video(self):
        import av
        output = io.BytesIO()
        with av.open(output, 'w', format='mp4') as container:
            stream = container.add_stream('mpeg4', rate=10)
            stream.width, stream.height, stream.pix_fmt = 96, 64, 'yuv420p'
            for index in range(20):
                with Image.new('RGB', (96, 64), (200, 150, 120)) as image:
                    frame = av.VideoFrame.from_image(image)
                for packet in stream.encode(frame):
                    container.mux(packet)
            for packet in stream.encode():
                container.mux(packet)
        return output.getvalue()

    def test_video_opt_in_independent_of_picture_skin(self):
        controls = ContentOptions()
        self.addCleanup(delete, controls)
        self.assertEqual(controls.values()['skin_method'], 'semantic')
        self.assertFalse(controls.values()['skin_videos'])
        self.assertFalse(eligible('video.mp4', controls.values()))
        self.assertFalse(controls.video_interval.isEnabled())
        controls.skin.setChecked(False)
        controls.skin_videos.setChecked(True)
        controls.video_interval.setValue(2)
        self.assertTrue(controls.video_interval.isEnabled())
        self.assertTrue(eligible('video.MP4', controls.values()))
        self.assertEqual(controls.values()['video_skin_interval'], 2)



    def test_semantic_classes_confidence_and_transparency(self):
        logits = np.zeros((1, 256, 256, 6), dtype=np.float32)
        logits[..., 0] = 10
        logits[:, :64, :, 0] = 0
        logits[:, :64, :, 2] = 10
        logits[:, 64:128, :, 0] = 0
        logits[:, 64:128, :, 3] = 10
        eligible_pixels = np.ones((256, 256), dtype=bool)
        areas = skin_areas(logits, eligible_pixels)
        self.assertEqual(areas['body_skin_percent'], 25)
        self.assertEqual(areas['face_skin_percent'], 25)
        self.assertEqual(areas['skin_like_percent'], 50)
        eligible_pixels[:64] = False
        self.assertEqual(skin_areas(logits, eligible_pixels)['body_skin_percent'], 0)
        logits[:] = 0
        self.assertEqual(skin_areas(logits, eligible_pixels)['skin_like_percent'], 0)
        logits[0, 0, 0, 0] = np.nan
        with self.assertRaises(ValueError):
            skin_areas(logits, eligible_pixels)
        with self.assertRaises(ValueError):
            skin_areas(np.zeros_like(logits), np.zeros_like(eligible_pixels))


    def test_native_semantic_rejects_plain_skin_coloured_background(self):
        with Image.new('RGB', (100, 60), (200, 150, 120)) as image:
            self.assertTrue(colour_screen(image)['review_candidate'])
            result = screen(image)
            self.assertEqual(result['type'], 'skin_semantic_screen')
            self.assertFalse(result['review_candidate'])
            self.assertEqual(result['skin_like_percent'], 0)
            self.assertEqual(result['model_license'], 'Apache-2.0')

    def test_semantic_corrupted_model_rejected(self):
        manifest = json.loads(Path('assets/models/skin-segmentation.json').read_text())
        (self.root / 'skin-segmentation.json').write_text(json.dumps(dict(manifest, size=3)))
        (self.root / manifest['filename']).write_bytes(b'bad')
        _model.cache_clear()
        try:
            with patch('analyzers.image_classification.semantic.MODEL_DIRECTORY', self.root), self.assertRaisesRegex(ValueError, 'checksum'):
                _model()
        finally:
            _model.cache_clear()

    def test_native_semantic_positive_portrait_worker_and_category(self):
        fixture = Path(__file__).with_name('fixtures') / 'skin-reference-public-domain.png'
        payload = fixture.read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), '88431cd9653ccd539741b555fb0a46b61558b301d4110412b5bc28b5e3ea6cb5')
        target = self.root / 'portrait.png'
        target.write_bytes(payload)
        config = configuration()
        config['analysis_options'] = dict(skin_tone=True, skin_method='semantic', skin_threshold=1)
        store = MemoryStore()
        summary = ScanEngine({'paths': [str(self.root)]}, config, store).run()
        self.assertEqual(summary['status'], 'completed')
        row = store.records[0]['parsed_artifact']['entries'][0]
        self.assertEqual(row['type'], 'skin_semantic_screen')
        self.assertGreater(row['face_skin_percent'], 1)
        self.assertTrue(row['review_candidate'])
        self.assertIn('Skin-colour Review', store.records[0]['additional_categories'])
        self.assertEqual(store.records[0]['sha256'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(set(item.name for item in self.root.iterdir()), {'portrait.png'})

    def test_video_disabled_does_not_load_decoder(self):
        with patch.dict('sys.modules', {'av': None}):
            result = analyze_video(io.BytesIO(b'invalid'), {})
        self.assertEqual(result['entries'], [])
        self.assertEqual(result['status'], 'parsed')

    def test_video_sample_times_spread_across_long_video(self):
        times, interval = sample_times(3600, 5)
        self.assertEqual(len(times), 120)
        self.assertEqual(interval, 30)
        self.assertEqual(times[-1], 3570)
        for duration in (float('nan'), 0, -1):
            with self.assertRaises(ValueError):
                sample_times(duration, 5)

    def test_video_ocr_is_independent_opt_in(self):
        controls = ContentOptions()
        self.assertFalse(controls.values()['ocr_videos'])
        self.assertNotIn('weapon_videos', controls.values())
        controls.ocr_videos.setChecked(True)
        self.assertTrue(controls.video_interval.isEnabled())
        controls.deleteLater()
        payload = self.video()
        for key, module, row_type in (
                ('ocr_videos', 'analyzers.ocr.analyzer.recognize', 'ocr_text'),):
            with self.subTest(key=key), patch(module, return_value={'type': row_type, 'text': 'sample', 'review_candidate': True}) as operation, patch('analyzers.image_classification.analyzer.screen_selected') as skin:
                self.assertTrue(eligible('clip.mp4', {key: True}))
                result = analyze_video(io.BytesIO(payload), {key: True, 'video_skin_interval': 1})
                rows = [row for row in result['entries'] if row['type'] == row_type]
                self.assertEqual([row['timestamp_seconds'] for row in rows], [0, 1])
                self.assertTrue(all(row['media_kind'] == 'video' for row in rows))
                self.assertEqual(operation.call_count, 2)
                skin.assert_not_called()

    def test_native_video_timestamps_categories_original_and_export(self):
        payload = self.video()
        target = self.root / 'target'
        target.mkdir()
        path = target / 'clip.mp4'
        path.write_bytes(payload)
        config = configuration()
        config['analysis_options'] = dict(skin_videos=True, skin_tone=False, skin_method='colour',
                                          video_skin_interval=1, ocr=True, weapon_detection=True)
        store = MemoryStore()
        summary = ScanEngine({'paths': [str(target)]}, config, store).run()
        self.assertEqual(summary['status'], 'completed')
        record = store.records[0]
        self.assertIn('Video Skin Review', record['additional_categories'])
        rows = record['parsed_artifact']['entries']
        screens = [row for row in rows if row['type'] == 'skin_colour_screen']
        self.assertEqual([row['timestamp_seconds'] for row in screens], [0, 1])
        self.assertTrue(all(row['media_kind'] == 'video' for row in screens))
        self.assertFalse(any(row['type'] in ('ocr_text', 'weapon_screen') for row in rows))
        self.assertEqual(path.read_bytes(), payload)
        records, diagnostics, count = store.snapshot()
        output = self.root / 'export.zip'
        ZipExporter(records, diagnostics, count, {'targets': {'paths': [str(target)]}}).save(output)
        with zipfile.ZipFile(output) as archive:
            evidence = next(name for name in archive.namelist() if name.startswith('evidence/') and name.endswith('clip.mp4'))
            self.assertEqual(archive.read(evidence), payload)
            derived = next(name for name in archive.namelist() if name.endswith('/records.jsonl'))
            entries = [json.loads(line) for line in archive.read(derived).splitlines()]
            self.assertTrue(any(row.get('timestamp_seconds') == 1 for row in entries))
        self.assertEqual(set(item.name for item in target.iterdir()), {'clip.mp4'})

    def test_large_video_uses_bounded_descriptor_input(self):
        path = self.root / 'large.mp4'
        path.write_bytes(self.video())
        with path.open('r+b') as output:
            output.truncate(65 * 1024 * 1024)
        data, metadata = FileCollector().collect(str(path), lambda: False)
        self.assertFalse(metadata['content_retained'])
        result = analyze(str(path), metadata, data, None,
                         dict(skin_videos=True, skin_method='semantic', video_skin_interval=1), lambda: False)
        self.assertEqual(result['status'], 'parsed', result['limitations'])
        self.assertEqual(len([row for row in result['entries'] if row['type'] == 'skin_semantic_screen']), 2)

    def test_video_changed_source_and_cancellation_discard_analysis(self):
        path = self.root / 'clip.mp4'
        path.write_bytes(self.video())
        data, metadata = FileCollector().collect(str(path), lambda: False)
        with open_source(str(path), metadata, None) as source:
            with self.assertRaises(CollectionCancelled):
                verify_source(source, str(path), metadata, None, lambda: True)
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                verify_source(source, str(path), metadata, None, lambda: False)
        result = analyze(str(path), metadata, data, None, dict(skin_videos=True), lambda: False)
        self.assertEqual(result['entries'], [])
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(result['limitations'])

    def test_corrupt_video_has_diagnostic(self):
        result = analyze_video(io.BytesIO(b'not video'), dict(skin_videos=True))
        self.assertEqual(result['status'], 'failed')
        self.assertIn('Video frame analysis', result['limitations'][0])

    def test_video_manifest_cannot_open_external_resource(self):
        manifest = b'#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXTINF:1,\nfile:///etc/passwd\n#EXT-X-ENDLIST\n'
        result = analyze_video(io.BytesIO(manifest), dict(skin_videos=True))
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['entries'], [])

    def test_worker_results_discarded_if_video_changes_during_screening(self):
        path = self.root / 'clip.mp4'
        path.write_bytes(self.video())
        data, metadata = FileCollector().collect(str(path), lambda: False)
        process = Mock(returncode=0)
        process.poll.return_value = 0
        def communicate(**kwargs):
            path.write_bytes(b'changed while worker ran')
            return json.dumps(dict(status='parsed', entries=[dict(type='skin_semantic_screen', review_candidate=True)], limitations=[])).encode(), b''
        process.communicate.side_effect = communicate
        with patch('analyzers.content.subprocess.Popen', return_value=process):
            result = analyze(str(path), metadata, data, None, dict(skin_videos=True), lambda: False)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['entries'], [])
        self.assertIn('changed', result['limitations'][0])

    def test_video_worker_cancel_preserves_cancel_signal(self):
        path = self.root / 'clip.mp4'
        path.write_bytes(self.video())
        data, metadata = FileCollector().collect(str(path), lambda: False)
        cancel = Event()
        process = Mock(returncode=0)
        process.poll.return_value = 0
        def communicate(**kwargs):
            cancel.set()
            return b'{"status":"parsed","entries":[],"limitations":[]}', b''
        process.communicate.side_effect = communicate
        with patch('analyzers.content.subprocess.Popen', return_value=process), self.assertRaises(CollectionCancelled):
            analyze(str(path), metadata, data, None, dict(skin_videos=True), cancel.is_set)
