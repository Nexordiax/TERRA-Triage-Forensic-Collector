"""Offline reference-picture matching; descriptors and results stay in RAM.

DCT perceptual fingerprints follow the approach described at
https://www.phash.org/docs/design.html (independent implementation).
This is near-duplicate screening, not semantic or identity recognition.
"""
import hashlib
import io
import os
import stat
import warnings
from pathlib import Path

ALGORITHM = 'terra-dct256-v1'
THRESHOLD = 70
MAX_REFERENCES = 256
MAX_BYTES = 64 * 1024 * 1024
MAX_PIXELS = 20_000_000


def fingerprint(image):
    import numpy as np
    from PIL import Image
    # A fixed luminance grid removes source resolution/encoding differences.
    with image.convert('L') as grey:
        with grey.resize((64, 64), Image.Resampling.LANCZOS) as small:
            pixels = np.asarray(small, dtype=np.float64)
    basis = np.cos(np.pi / 64 * (np.arange(64) + 0.5)[None, :] * np.arange(16)[:, None])
    coefficients = (basis @ pixels @ basis.T).flatten()
    # Remove numerically insignificant coefficients, especially for plain images.
    coefficients[np.abs(coefficients) < 1e-7] = 0
    bits = coefficients > np.median(coefficients[1:])
    bits[0] = False  # Exclude mean brightness (DC).
    return np.packbits(bits).tobytes().hex()


def read_reference(filename):
    from PIL import Image, ImageOps
    path = Path(filename)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) |
                         getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(descriptor, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('Reference pictures must be regular files')
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Reference picture exceeds the 64 MiB analysis limit')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            from analyzers.image_formats import open_image
            with open_image(data, path.suffix) as original:
                if original.width * original.height > MAX_PIXELS:
                    raise ValueError('Reference picture exceeds the 20 megapixel analysis limit')
                with ImageOps.exif_transpose(original) as image:
                    digest = fingerprint(image)
    except (Image.DecompressionBombWarning, Image.DecompressionBombError) as error:
        raise ValueError('Reference picture exceeds safe decoder dimensions') from error
    return dict(path=str(path.resolve()), sha256=hashlib.sha256(data).hexdigest(),
                fingerprint=digest, algorithm=ALGORITHM, reference_frame=1)


def compare(image, references, threshold=THRESHOLD):
    if isinstance(threshold, bool) or not isinstance(threshold, int) or not 1 <= threshold <= 100:
        raise ValueError('Image similarity threshold must be between 1 and 100 percent')
    from PIL import Image
    variants = [(0, fingerprint(image))]
    for angle, method in ((90, Image.Transpose.ROTATE_90), (180, Image.Transpose.ROTATE_180),
                          (270, Image.Transpose.ROTATE_270)):
        with image.transpose(method) as rotated:
            variants.append((angle, fingerprint(rotated)))
    matches = []
    for reference in references:
        if reference['algorithm'] != ALGORITHM:
            raise ValueError('Unsupported reference-picture fingerprint version')
        number = int(reference['fingerprint'], 16)
        distance, angle = min(((int(digest, 16) ^ number).bit_count(), angle) for angle, digest in variants)
        score = 100 * (1 - distance / 255)
        if score >= threshold:
            matches.append(dict(type='image_similarity_match', reference_path=reference['path'],
                                reference_sha256=reference['sha256'], reference_frame=reference['reference_frame'],
                                algorithm=ALGORITHM, similarity_percent=round(score, 2),
                                distance=distance, compared_bits=255, minimum_similarity_percent=threshold,
                                candidate_rotation_degrees=angle,
                                note='Perceptual similarity score, not a probability or proof of identity. '
                                     'Grayscale near-duplicate screening; colour changes can match. '
                                     'Crops and substantial edits may be missed. Manual review required.'))
    return sorted(matches, key=lambda row: (-row['similarity_percent'], row['reference_path']))
