"""Offline skin-area screening with checksum-pinned semantic segmentation."""
import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path

MODEL_DIRECTORY = Path(__file__).resolve().parents[2] / 'assets/models'


@lru_cache(maxsize=1)
def _model():
    os.environ['ORT_DISABLE_TELEMETRY'] = '1'
    try:
        import onnxruntime as ort
    except ImportError:
        raise ValueError('Semantic skin runtime unavailable; install requirements-forensics.txt on the acquisition tool') from None
    ort.disable_telemetry_events()
    manifest = json.loads((MODEL_DIRECTORY / 'skin-segmentation.json').read_text())
    path = MODEL_DIRECTORY / manifest['filename']
    if path.parent != MODEL_DIRECTORY or path.suffix != '.onnx' or path.is_symlink():
        raise ValueError('Invalid trusted skin-model location')
    if path.stat().st_size != manifest['size'] or manifest['size'] > 64 * 1024 * 1024:
        raise ValueError('Skin model missing or unexpected size')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest['sha256']:
        raise ValueError('Skin-model checksum mismatch; inference was not performed')
    options = ort.SessionOptions()
    options.intra_op_num_threads = options.inter_op_num_threads = 1
    options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    options.enable_profiling = False
    options.log_severity_level = 3
    session = ort.InferenceSession(data, sess_options=options, providers=['CPUExecutionProvider'])
    inputs, outputs = session.get_inputs(), session.get_outputs()
    if len(inputs) != 1 or inputs[0].shape != [1, 256, 256, 3] or inputs[0].type != 'tensor(float)':
        raise ValueError('Unsupported skin-model input schema')
    if len(outputs) != 1 or outputs[0].shape != [1, 256, 256, 6]:
        raise ValueError('Unsupported skin-model output schema')
    return session, manifest, inputs[0].name


def skin_areas(logits, eligible):
    import numpy as np
    logits = np.asarray(logits)
    eligible = np.asarray(eligible, dtype=bool)
    if logits.shape != (1, 256, 256, 6) or eligible.shape != (256, 256) or not np.isfinite(logits).all():
        raise ValueError('Invalid skin segmentation output')
    if not eligible.any():
        raise ValueError('Image has no sufficiently opaque pixels to screen')
    values = logits[0]
    exponents = np.exp(values - values.max(axis=-1, keepdims=True))
    probabilities = exponents / exponents.sum(axis=-1, keepdims=True)
    classes = probabilities.argmax(axis=-1)
    confident = probabilities.max(axis=-1) >= .5
    count = int(eligible.sum())
    body = int(((classes == 2) & confident & eligible).sum())
    face = int(((classes == 3) & confident & eligible).sum())
    return dict(eligible_pixels=count, candidate_pixels=body + face,
                body_skin_percent=round(100 * body / count, 4),
                face_skin_percent=round(100 * face / count, 4),
                skin_like_percent=round(100 * (body + face) / count, 4))


def screen(image, threshold=30):
    import numpy as np
    from PIL import Image
    if isinstance(threshold, bool) or not isinstance(threshold, int) or not 1 <= threshold <= 100:
        raise ValueError('Skin threshold must be between 1 and 100 percent')
    session, manifest, input_name = _model()
    with image.convert('RGBA') as rgba, rgba.resize((256, 256), Image.Resampling.BILINEAR) as resized:
        with resized.getchannel('A') as alpha, Image.new('RGB', resized.size, (0, 0, 0)) as rgb:
            eligible = np.asarray(alpha) >= 128
            rgb.paste(resized, mask=alpha)
            tensor = np.asarray(rgb, dtype=np.float32)[None] / 255
        areas = skin_areas(session.run(None, {input_name: tensor})[0], eligible)
    return dict(areas, type='skin_semantic_screen', model=manifest['name'],
                model_sha256=manifest['sha256'], model_source=manifest['source'],
                model_revision=manifest['revision'], model_license=manifest['license'],
                engine='ONNX Runtime CPU', threshold_percent=threshold,
                review_candidate=100 * areas['candidate_pixels'] >= threshold * areas['eligible_pixels'],
                sampled_width=256, sampled_height=256, minimum_pixel_model_score=.5,
                sampling='RGB stretched to 256 x 256, [0,1]; argmax body/face skin with score >=0.5; alpha >=128',
                interpretation='Experimental semantic skin-area estimate for manual review; not proof of nudity, age, identity or illegality. No detection does not establish absence.')
