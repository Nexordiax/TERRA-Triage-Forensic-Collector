"""Synthetic offline media benchmark: python -m tests.benchmark_media_scan."""
import argparse
import json
import statistics
import tempfile
import time
from pathlib import Path

from PIL import Image, ImageDraw

from controllers.scan_controller import ScanEngine
from storage.memory_store import MemoryStore
from tests.test_scan import configuration


def benchmark(ocr=False):
    reports = []
    expected = None
    with tempfile.TemporaryDirectory(prefix='terra-media-benchmark-') as temporary:
        root = Path(temporary)
        for index in range(12):
            image = Image.new('RGB', (1024, 768), (185, 135, 105))
            draw = ImageDraw.Draw(image)
            draw.rectangle((0, 0, 512 + index * 10, 768), fill=(30, 80, 150))
            draw.text((80, 80), 'TERRA synthetic fixture needle', fill='white')
            image.save(root / f'fixture-{index}.png')
        config = configuration()
        config.update(scan_workers=1, analysis_options=dict(skin_tone=True, skin_threshold=30,
                                                          ocr=ocr))
        for requested in (1, 2, 4):
            elapsed = []
            observed_workers = []
            for _ in range(3):
                store = MemoryStore()
                engine = ScanEngine({'paths': [str(root)]}, dict(config, analysis_workers=requested), store)
                started = time.perf_counter()
                summary = engine.run()
                summary = {key: value for key, value in summary.items() if key != 'volume_metadata'}
                elapsed.append(time.perf_counter() - started)
                observed_workers.append(engine.analysis_workers)
                observations = sorted([{key: value for key, value in row.items() if key not in ('acquired_at', 'id', 'atime_ns')} for row in store.records],
                                      key=lambda row: row['path'])
                if expected is None:
                    expected = summary, observations
                assert (summary, observations) == expected, 'Serial/parallel media evidence differs'
            reports.append(dict(requested_workers=requested, actual_workers=observed_workers,
                                median_seconds=round(statistics.median(elapsed), 4), files=summary['examined'],
                                status=summary['status'], ocr=ocr))
    baseline = reports[0]['median_seconds']
    for report in reports:
        report['speedup_vs_serial'] = round(baseline / report['median_seconds'], 2)
    print(json.dumps(reports, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ocr', action='store_true', help='Also exercise installed offline OCR')
    arguments = parser.parse_args()
    benchmark(arguments.ocr)
