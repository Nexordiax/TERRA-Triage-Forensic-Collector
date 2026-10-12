"""Reference import, transformed-image matching and live/export integration."""
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PIL import Image
from PySide6.QtWidgets import QApplication
from shiboken6 import delete

from analyzers.image_similarity import compare, read_reference, fingerprint
from analyzers.content import eligible
from analyzers.content_worker import analyze
from controllers.configuration_controller import ConfigurationController, ConfigurationError
from controllers.scan_controller import ScanEngine
from interface.pages.configuration import ConfigurationPage
from interface.pages.analysis import AnalysisPage
from storage.memory_store import MemoryStore


class ImageSimilarityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.reference = self.root / 'reference.jpg'
        self.reference.write_bytes((Path(__file__).parent / 'fixtures' / 'weapon-reference-public-domain.jpg').read_bytes())
        self.targets = self.root / 'targets'
        self.targets.mkdir()
        self.options = dict(folder_names=False, file_names=False, file_contents=False, hash_matches=False)

    def prepare(self, mode='matches_only'):
        return ConfigurationController().prepare([], [], self.options, mode,
                                                  image_files=[str(self.reference)])

    def test_threshold_defaults_adjustment_validation_and_worker_propagation(self):
        self.assertEqual(self.prepare()['analysis_options']['image_similarity_threshold'], 70)
        page = ConfigurationPage()
        self.addCleanup(delete, page)
        self.assertEqual(page.content_analysis.similarity_threshold.value(), 70)
        page.content_analysis.similarity_threshold.setValue(85)
        self.assertEqual(page.content_analysis.values()['image_similarity_threshold'], 85)
        for invalid in (True, 0, 101, '70'):
            with self.assertRaises(ConfigurationError):
                ConfigurationController().prepare([], [], self.options, 'all_supported',
                                                   analysis_options={'image_similarity_threshold': invalid})
        descriptor = read_reference(self.reference)
        with Image.open(self.reference) as original:
            # A synthetic fingerprint at ~80% isolates threshold behavior.
            modified = dict(descriptor, fingerprint=f'{int(descriptor["fingerprint"],16) ^ ((1 << 50) - 1):064x}')
            matches = compare(original, [modified], 70)
            self.assertTrue(matches)
            self.assertEqual(matches[0]['minimum_similarity_percent'], 70)
            self.assertEqual(compare(original, [modified], 90), [])
            output = io.BytesIO()
            original.save(output, format='PNG')
        result = analyze(output.getvalue(), '.png', {'image_references': [modified], 'image_similarity_threshold': 90})
        self.assertFalse(any(row['type'] == 'image_similarity_match' for row in result['entries']))
        result = analyze(output.getvalue(), '.png', {'image_references': [modified], 'image_similarity_threshold': 70})
        self.assertTrue(any(row['type'] == 'image_similarity_match' for row in result['entries']))

    def test_resized_recompressed_and_rotated_copy_matches_without_file_hash(self):
        descriptor = read_reference(self.reference)
        with Image.open(self.reference) as original:
            with original.resize((240, 180)) as small:
                output = io.BytesIO()
                small.save(output, format='JPEG', quality=65)
            with Image.open(io.BytesIO(output.getvalue())) as modified:
                matches = compare(modified, [descriptor])
            self.assertTrue(matches)
            self.assertGreaterEqual(matches[0]['similarity_percent'], 90)
            self.assertNotEqual(hashlib.sha256(output.getvalue()).hexdigest(), descriptor['sha256'])
            with original.transpose(Image.Transpose.ROTATE_90) as rotated:
                match = compare(rotated, [descriptor])[0]
                self.assertEqual(match['similarity_percent'], 100)
                self.assertEqual(match['candidate_rotation_degrees'], 270)
        self.assertEqual(matches[0]['reference_sha256'], descriptor['sha256'])

    def test_unrelated_picture_does_not_match(self):
        import numpy as np
        array = np.random.default_rng(19).integers(0, 256, (300, 300, 3), dtype=np.uint8)
        with Image.fromarray(array) as unrelated:
            self.assertEqual(compare(unrelated, [read_reference(self.reference)]), [])

    def test_reference_validation_and_reread_at_start(self):
        page = ConfigurationPage()
        self.addCleanup(delete, page)
        page.image_lists.add_files([str(self.reference), str(self.reference)])
        self.assertEqual(len(page.image_lists.paths()), 1)
        invalid = self.root / 'bad.png'
        invalid.write_bytes(b'not an image')
        page.image_lists.add_files([str(invalid)])
        self.assertIn('Cannot import reference picture', page.image_lists.error.text())
        self.assertEqual(len(page.image_lists.paths()), 1)
        for box in page.options.values():
            box.setChecked(False)
        page.matches_only.setChecked(True)
        emitted = []
        page.start_requested.connect(emitted.append)
        page.submit()
        self.assertEqual(len(emitted), 1)
        self.assertTrue(emitted[0]['analysis_options']['image_references'])
        self.reference.unlink()
        page.submit()
        self.assertEqual(len(emitted), 1)
        self.assertIn('Cannot import reference picture', page.error.text())

    def test_reference_count_and_dimensions_limits_are_explicit(self):
        with self.assertRaisesRegex(ConfigurationError, 'at most 256'):
            ConfigurationController().prepare([], [], self.options, 'matches_only',
                                              image_files=[f'{index}.png' for index in range(257)])
        with patch('analyzers.image_similarity.MAX_PIXELS', 1):
            with self.assertRaisesRegex(ConfigurationError, 'megapixel'):
                self.prepare()

    def test_worker_matches_even_with_other_analysis_disabled(self):
        options = self.prepare()['analysis_options']
        self.assertTrue(eligible('image.jpg', options))
        self.assertFalse(eligible('document.pdf', options))
        self.assertTrue(eligible('document.pdf', dict(options, document_images=True)))
        result = analyze(self.reference.read_bytes(), '.jpg', options)
        self.assertEqual(result['status'], 'parsed')
        self.assertEqual(result['entries'][0]['type'], 'image_similarity_match')
        self.assertEqual(result['entries'][0]['locator'], 'frame:1')

    def test_live_matches_only_category_and_metadata_survive_export(self):
        from controllers.export_controller import ZipExporter
        import zipfile
        candidate = self.targets / 'copy.jpg'
        candidate.write_bytes(self.reference.read_bytes())
        unrelated = self.targets / 'unmatched.txt'
        unrelated.write_bytes(b'not an image')
        config = self.prepare()
        store = MemoryStore()
        page = AnalysisPage()
        self.addCleanup(delete, page)
        targets = {'paths': [str(self.targets)]}
        summary = ScanEngine(targets, config, store, on_finding=page.add_finding).run()
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(len(store.records), 1)
        record = store.records[0]
        self.assertTrue(record['matches']['image_similarity'])
        category = page.categories['Image Similarity Matches']
        self.assertFalse(category.isExpanded())
        self.assertEqual(category.childCount(), 1)
        self.assertEqual(record['sha256'], hashlib.sha256(candidate.read_bytes()).hexdigest())
        # Match and derived-analysis dictionaries are the export payload.
        self.assertIn(str(self.reference), json.dumps(record['matches']))
        self.assertEqual(record['parsed_artifact']['entries'][0]['reference_sha256'], record['sha256'])
        records, diagnostics, count = store.snapshot()
        destination = self.root / 'result.zip'
        result = ZipExporter(records, diagnostics, count,
                             {'targets': targets, 'configuration': config, 'scan_summary': summary}).save(destination)
        self.assertEqual(result['status'], 'saved')
        with zipfile.ZipFile(destination) as archive:
            manifest = json.loads(archive.read('terra/manifest.json'))
            self.assertEqual(manifest['entries'][0]['matches']['image_similarity'], record['matches']['image_similarity'])
            analysis_files = [name for name in archive.namelist() if name.endswith('/records.jsonl')]
            self.assertEqual(len(analysis_files), 1)
            exported = json.loads(archive.read(analysis_files[0]).splitlines()[0])
            self.assertEqual(exported['type'], 'image_similarity_match')
            self.assertEqual(exported['reference_sha256'], record['sha256'])
            self.assertEqual(exported['similarity_percent'], 100)

    def test_ocr_failure_preserves_independent_similarity_results(self):
        options = dict(self.prepare()['analysis_options'], ocr=True)
        with patch('analyzers.ocr.analyzer.recognize', side_effect=ValueError('OCR unavailable')):
            result = analyze(self.reference.read_bytes(), '.jpg', options)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['entries'][0]['type'], 'image_similarity_match')
        self.assertIn('OCR unavailable', result['limitations'])

    def test_uncached_file_matching_and_reference_exclusion(self):
        from artifacts.file_collector import FileCollector
        copy = self.targets / 'copy.jpg'
        copy.write_bytes(self.reference.read_bytes())
        config = self.prepare()
        store = MemoryStore()
        summary = ScanEngine({'paths': [str(self.root)]}, config, store,
                             collector=FileCollector(max_file_bytes=1)).run()
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(len(store.records), 1)
        self.assertEqual(store.records[0]['path'], str(copy))
        self.assertFalse(store.records[0]['content_retained'])
        self.assertTrue(store.records[0]['matches']['image_similarity'])

    def test_analysis_budget_failure_is_logged_without_a_match(self):
        copy = self.targets / 'copy.jpg'
        copy.write_bytes(self.reference.read_bytes())
        store = MemoryStore()
        engine = ScanEngine({'paths': [str(self.targets)]}, self.prepare(), store)
        engine.analysis_max_bytes = 0
        summary = engine.run()
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(store.records, [])
        self.assertTrue(any('budget reached' in row['message'] for row in store.diagnostics))
