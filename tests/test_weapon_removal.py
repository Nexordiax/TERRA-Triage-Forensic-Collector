"""Removed weapon options cannot activate inference in legacy configurations."""
import io
import unittest
from pathlib import Path
from PIL import Image
from analyzers.content import eligible
from analyzers.content_worker import analyze
from analyzers.video import video_enabled

class WeaponRemovalTests(unittest.TestCase):
    def test_legacy_weapon_flags_are_inert_and_skin_still_runs(self):
        options = dict(weapon_detection=True, weapon_videos=True, weapon_threshold=1)
        self.assertFalse(eligible('image.png', options))
        self.assertFalse(video_enabled(options))
        with Image.new('RGB', (20, 20), 'white') as image:
            payload = io.BytesIO()
            image.save(payload, format='PNG')
        rows = analyze(payload.getvalue(), '.png', dict(options, skin_tone=True))
        self.assertEqual(rows['status'], 'parsed')
        self.assertEqual([row['type'] for row in rows['entries']], ['skin_colour_screen'])

    def test_disputed_detector_and_model_are_absent(self):
        root = Path(__file__).resolve().parents[1]
        for name in ('analyzers/weapons.py', 'assets/models/weapon-reference.onnx',
                     'assets/models/weapon-reference.json'):
            self.assertFalse((root / name).exists(), name)
