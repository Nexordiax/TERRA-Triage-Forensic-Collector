"""Shared offline picture decoding from acquired bytes or read-only streams."""
import io
from contextlib import contextmanager

RAW_IMAGES = {'.dng', '.cr2', '.cr3', '.nef', '.nrw', '.arw', '.sr2', '.srf',
              '.orf', '.rw2', '.raf', '.pef', '.srw', '.raw'}
HEIF_IMAGES = {'.heic', '.heif', '.hif', '.heics', '.heifs'}
EXTENDED_IMAGES = RAW_IMAGES | HEIF_IMAGES | {'.avif', '.avifs'}
IMAGES = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff', '.webp'} | EXTENDED_IMAGES
PICTURE_FILTER = 'Pictures (' + ' '.join('*' + suffix for suffix in sorted(IMAGES)) + ')'
MAX_PIXELS = 20_000_000
MAX_RAW_PIXELS = 80_000_000


@contextmanager
def open_image(source, suffix='', max_pixels=MAX_PIXELS):
    from PIL import Image
    if isinstance(source, (bytes, bytearray)):
        source = io.BytesIO(source)
    suffix = suffix.lower()
    if suffix in RAW_IMAGES:
        try:
            import rawpy
        except ImportError:
            raise ValueError('Camera RAW decoder unavailable: rawpy/LibRaw') from None
        with rawpy.imread(source) as raw:
            width, height = raw.sizes.raw_width, raw.sizes.raw_height
            if width <= 0 or height <= 0 or width * height > MAX_RAW_PIXELS:
                raise ValueError('Camera RAW sensor dimensions exceed the 80 megapixel bound')
            rgb = raw.postprocess(half_size=True, output_bps=8, use_camera_wb=True)
            if rgb.shape[0] * rgb.shape[1] > max_pixels:
                raise ValueError('Rendered RAW dimensions exceed the image pixel bound')
            with Image.fromarray(rgb) as image:
                image.info['_terra_decode'] = dict(decoder='rawpy/LibRaw', raw_dimensions=[width, height],
                                                  half_size=True, output_bits=8, camera_white_balance=True,
                                                  note='Derived half-resolution RGB rendering; original RAW bytes are retained')
                yield image
        return
    if suffix in HEIF_IMAGES:
        try:
            import pillow_heif
        except ImportError:
            raise ValueError('HEIF/HEIC decoder unavailable: pillow-heif/libheif') from None
        pillow_heif.options.DECODE_THREADS = 1
        pillow_heif.register_heif_opener()
    Image.MAX_IMAGE_PIXELS = max_pixels
    with Image.open(source) as image:
        if image.width <= 0 or image.height <= 0 or image.width * image.height > max_pixels:
            raise ValueError('Image dimensions exceed the decoding pixel bound')
        yield image
