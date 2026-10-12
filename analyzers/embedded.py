"""Generate a bounded derived PNG from an explicit, verified evidence locator."""
import base64
from contextlib import closing
import hashlib
import io
from pathlib import PurePosixPath
import warnings

from analyzers.archive_readers import zip_members, native_members, sevenzip_members
from analyzers.containers import OFFICE, MAX_MEMBERS, MAX_MEMBER_ANALYSIS, MAX_DEPTH


def render_preview(source, suffix, options):
    from PIL import Image, ImageOps
    spec = options['_preview_spec']
    steps = spec.get('steps', [])
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_DEPTH + 2:
        raise ValueError('Invalid contained-picture locator')
    image = None
    passwords = options.get('_archive_passwords', [])[:32]
    for position, step in enumerate(steps):
        kind = step.get('kind')
        if kind == 'archive_member':
            if step.get('suffix') != suffix:
                raise ValueError('Archive locator format mismatch')
            found = []
            limitations = []
            def consume(name, blocks, size, index, credential):
                if name != step.get('name') or index != step.get('index'):
                    return
                if size is not None and size > MAX_MEMBER_ANALYSIS:
                    raise ValueError('Contained-picture preview exceeds 32 MiB member bound')
                payload = bytearray()
                for block in blocks:
                    if len(payload) + len(block) > MAX_MEMBER_ANALYSIS:
                        raise ValueError('Contained-picture preview exceeds 32 MiB member bound')
                    payload.extend(block)
                if hashlib.sha256(payload).hexdigest() != step.get('sha256'):
                    raise ValueError('Contained member changed; preview discarded')
                found.append(bytes(payload))
            if suffix == '.zip' or suffix in OFFICE:
                zip_members(source, passwords, consume, limitations.append, MAX_MEMBERS)
            elif suffix == '.7z':
                try:
                    native_members(source, suffix, passwords, consume, limitations.append, MAX_MEMBERS)
                except Exception:
                    source.seek(0)
                    sevenzip_members(source, passwords, consume, limitations.append, MAX_MEMBERS, 64 * 1024 * 1024)
            elif suffix == '.rar':
                try:
                    native_members(source, suffix, passwords, consume, limitations.append, MAX_MEMBERS)
                except Exception:
                    from analyzers.rar_native import members as rar_members
                    found.clear()
                    source.seek(0)
                    rar_members(source, passwords, consume, limitations.append, MAX_MEMBERS)
            elif suffix in ('.gz', '.bz2', '.xz'):
                import gzip, bz2, lzma
                opener = {'.gz': gzip.GzipFile, '.bz2': bz2.BZ2File, '.xz': lzma.LZMAFile}[suffix]
                with opener(source) as member:
                    consume(step['name'], iter(lambda: member.read(1024 * 1024), b''), None, 0, None)
            else:
                import tarfile
                with tarfile.open(fileobj=source, mode='r|*') as archive:
                    for index, info in enumerate(archive):
                        if index >= MAX_MEMBERS: break
                        if info.isfile() and info.name == step.get('name') and index == step.get('index'):
                            with archive.extractfile(info) as member:
                                consume(info.name, iter(lambda: member.read(1024 * 1024), b''), info.size, index, None)
                            break
            if len(found) != 1:
                raise ValueError('Verified contained member was not available; it may be encrypted or unsupported')
            source = io.BytesIO(found[0])
            suffix = PurePosixPath(step['name']).suffix.lower()
        elif kind == 'image_frame' and position == len(steps) - 1:
            index = step.get('index')
            if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < 20:
                raise ValueError('Invalid image frame locator')
            Image.MAX_IMAGE_PIXELS = 20_000_000
            with warnings.catch_warnings():
                warnings.simplefilter('error', Image.DecompressionBombWarning)
                from analyzers.image_formats import open_image
                with open_image(source, suffix) as original:
                    original.seek(index)
                    if original.width * original.height > 20_000_000:
                        raise ValueError('Preview image pixel bound exceeded')
                    image = ImageOps.exif_transpose(original).copy()
        elif kind == 'pdf_image' and position == len(steps) - 1:
            import pypdfium2 as pdfium
            import pypdfium2.raw as raw
            page_number, index = step.get('page'), step.get('index')
            if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (page_number, index)) or page_number >= 200 or index >= 100:
                raise ValueError('Invalid PDF image locator')
            with pdfium.PdfDocument(source) as document, closing(document[page_number]) as page:
                for object_index, obj in enumerate(page.get_objects(filter=[raw.FPDF_PAGEOBJ_IMAGE])):
                    if object_index != index: continue
                    width, height = obj.get_px_size()
                    if width * height > 20_000_000:
                        raise ValueError('PDF image pixel bound exceeded')
                    with closing(obj.get_bitmap(render=True)) as bitmap:
                        bitmap.warn_on_close = False
                        view = bitmap.to_pil()
                        image = view.copy()
                        view.close()
                    break
        else:
            raise ValueError('Unsupported contained-picture locator step')
    if image is None:
        raise ValueError('Contained picture was not found')
    try:
        original_size = [image.width, image.height]
        image.thumbnail((2400, 2400))
        output = io.BytesIO()
        image.save(output, 'PNG')
        payload = output.getvalue()
        if len(payload) > 8 * 1024 * 1024:
            raise ValueError('Derived preview output exceeds 8 MiB bound')
        return dict(entries=[], limitations=[], status='parsed', preview_png=base64.b64encode(payload).decode('ascii'),
                    preview_sha256=hashlib.sha256(payload).hexdigest(), original_dimensions=original_size,
                    preview_dimensions=[image.width, image.height], preview_note='Derived PNG preview; original enclosing evidence remains unchanged')
    finally:
        image.close()
