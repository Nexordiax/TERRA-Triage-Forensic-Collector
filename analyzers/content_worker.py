"""Disposable analysis process: receives bytes, never an examined pathname."""
import io
import json
import sys
import warnings
from contextlib import closing


def analyze(data, suffix, options):
    try:
        from PIL import Image, ImageOps
    except ImportError as error:
        return dict(entries=[], limitations=[f'Image-analysis dependency unavailable: Pillow ({error}); install requirements-forensics.txt on the acquisition tool'], status='failed')
    from analyzers.documents import extract, MAX_TEXT
    from analyzers.image_classification.analyzer import screen_selected
    from analyzers.ocr.analyzer import recognize
    from analyzers.video import VIDEOS, video_enabled
    result = dict(entries=[], limitations=[], status='parsed')
    total_text = 0
    def add(row):
        nonlocal total_text
        total_text += len(row.get('text', ''))
        if total_text > MAX_TEXT:
            raise ValueError('Derived text exceeds per-file analysis bound')
        result['entries'].append(row)
    def page_analysis(image, locator, skin=False, transform=None, preview=None, ocr_allowed=True):
        first = len(result['entries'])
        if skin and options.get('image_references'):
            try:
                from analyzers.image_similarity import compare
                for row in compare(image, options['image_references'], options.get('image_similarity_threshold', 70)):
                    row.update(locator=locator, image_transform=transform)
                    add(row)
            except Exception as error:
                result['limitations'].append('Image similarity analysis: ' + str(error))
        if options.get('ocr') and ocr_allowed:
            try:
                row = recognize(image, options.get('ocr_languages', 'eng'))
                row['locator'] = locator
                row.update(analysis_image_width=image.width, analysis_image_height=image.height,
                           word_box_coordinates='Analysis image pixels', image_transform=transform)
                add(row)
            except Exception as error:
                result['limitations'].append(str(error))
        if skin and options.get('skin_tone'):
            try:
                row = screen_selected(image, options.get('skin_threshold', 30), options.get('skin_method', 'colour'))
                row['locator'] = locator
                row.update(analysis_image_width=image.width, analysis_image_height=image.height, image_transform=transform)
                add(row)
            except Exception as error:
                result['limitations'].append(str(error))
        if preview:
            for row in result['entries'][first:]:
                row['preview'] = preview
            add(dict(type='embedded_image', locator=locator, preview=preview,
                     analysis_image_width=image.width, analysis_image_height=image.height,
                     note='Derived preview opens verified enclosing evidence in an isolated decoder'))
    try:
        from analyzers.containers import ARCHIVES, OFFICE, search
        if suffix in ARCHIVES | OFFICE:
            result = search(data, suffix, options, analyze)
            if suffix in OFFICE and options.get('extract_documents'):
                rows = extract(data, 'document' + suffix)
                result['entries'] = list(rows) + result['entries']
        elif suffix == '.pdf':
            pdf_ocr = options.get('document_images') and options.get('ocr') and options.get('ocr_pdf', True)
            embedded = options.get('document_images') and (options.get('_inventory_embedded') or options.get('_embedded_context') or options.get('ocr') and not pdf_ocr or any(options.get(key) for key in ('skin_tone', 'image_references')))
            if not options.get('extract_documents') and not pdf_ocr and not embedded:
                return result
            import pypdfium2 as pdfium
            with pdfium.PdfDocument(data) as document:
                if len(document) > 200:
                    result['limitations'].append('PDF page limit reached; only the first 200 pages were analyzed')
                for index in range(min(len(document), 200)):
                    with closing(document[index]) as page:
                        locator = f'page:{index + 1}'
                        text = ''
                        if options.get('extract_documents') or pdf_ocr:
                            with closing(page.get_textpage()) as textpage:
                                if textpage.count_chars() > MAX_TEXT - total_text:
                                    raise ValueError('PDF text exceeds analysis bound')
                                text = textpage.get_text_range()
                            if options.get('extract_documents') and text.strip():
                                add(dict(type='document_text', locator=locator, format='pdf', text=text,
                                         note='Stored PDF text layer; scripts, actions and attachments are not executed'))
                        if pdf_ocr and (options.get('ocr_all_pdf_pages') or not text.strip()):
                            width, height = page.get_size()
                            if width <= 0 or height <= 0:
                                raise ValueError('Invalid PDF page dimensions')
                            scale = min(200 / 72, (8_000_000 / (width * height)) ** 0.5, 6000 / max(width, height))
                            if scale <= 0:
                                raise ValueError('Invalid PDF rendering scale')
                            with closing(page.render(scale=scale, may_draw_forms=False)) as bitmap:
                                image = bitmap.to_pil()
                                try:
                                    page_analysis(image, locator, transform=dict(
                                        type='pdf_render', page_size_points=[width, height], scale=scale,
                                        effective_render_dpi=scale * 72))
                                finally:
                                    image.close()
                        if embedded:
                            import pypdfium2.raw as raw
                            for object_index, obj in enumerate(page.get_objects(filter=[raw.FPDF_PAGEOBJ_IMAGE])):
                                if object_index >= 100:
                                    result['limitations'].append(locator + ': embedded image count limit reached')
                                    break
                                width, height = obj.get_px_size()
                                if width * height > 20_000_000:
                                    result['limitations'].append(locator + ': embedded image pixel bound exceeded')
                                    continue
                                with closing(obj.get_bitmap(render=True)) as bitmap:
                                    # The PIL view is closed before its foreign bitmap buffer.
                                    bitmap.warn_on_close = False
                                    image = bitmap.to_pil()
                                    try:
                                        page_analysis(image, locator + f'/image:{object_index + 1}', skin=True, transform={'type': 'pdf_embedded_image'},
                                                      preview={'steps': [dict(kind='pdf_image', page=index, index=object_index)], 'label': locator + f'/image:{object_index + 1}'}, ocr_allowed=not pdf_ocr)
                                    finally:
                                        image.close()
        elif suffix in ('.doc', '.xls', '.ppt', '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp', '.rtf'):
            if options.get('extract_documents'):
                for row in extract(data, 'document' + suffix):
                    add(row)
        elif suffix in VIDEOS:
            if video_enabled(options):
                from analyzers.video import analyze_video
                result = analyze_video(io.BytesIO(data), options)
        else:
            Image.MAX_IMAGE_PIXELS = 20_000_000
            with warnings.catch_warnings():
                warnings.simplefilter('error', Image.DecompressionBombWarning)
                from analyzers.image_formats import open_image
                with open_image(data, suffix) as original:
                    frames = getattr(original, 'n_frames', 1)
                    if frames > 20:
                        result['limitations'].append('Image frame limit reached; only the first 20 frames were analyzed')
                    for index in range(min(frames, 20)):
                        original.seek(index)
                        if original.width * original.height > 20_000_000:
                            raise ValueError('Image pixel bound exceeded')
                        image = ImageOps.exif_transpose(original)
                        try:
                            transform = dict(type='exif_transpose', source_frame_size=[original.width, original.height])
                            if original.info.get('_terra_decode'):
                                transform['decode_details'] = original.info['_terra_decode']
                            page_analysis(image, f'frame:{index + 1}', skin=True,
                                          transform=transform,
                                          preview={'steps': [dict(kind='image_frame', index=index)], 'label': f'frame:{index + 1}'} if options.get('_embedded_context') else None)
                        finally:
                            image.close()
    except Exception as error:
        result['limitations'].append(f'{type(error).__name__}: {error}')
    if result['limitations']:
        result['status'] = 'partial' if result['entries'] else 'failed'
    return result


def main():
    try:
        result = run()
    except Exception as error:
        detail = ('Analysis worker memory limit reached' if isinstance(error, MemoryError) else
                  f'Analysis worker setup failed: {type(error).__name__}: {error}')
        result = dict(entries=[], limitations=[detail], status='failed')
    try:
        encoded = json.dumps(result, ensure_ascii=True).encode()
        if len(encoded) > 16 * 1024 * 1024:
            encoded = json.dumps(dict(entries=[], limitations=['Derived output exceeds analysis bound'], status='failed')).encode()
    except (MemoryError, ValueError):
        encoded = b'{"entries": [], "limitations": ["Analysis result serialization failed or exceeded memory limits"], "status": "failed"}'
    sys.stdout.buffer.write(encoded)


def run():
    # Limits apply only to derived analysis, never file acquisition/hashing.
    try:
        import resource
        for name, maximum in ((resource.RLIMIT_AS, 1536 * 1024 * 1024), (resource.RLIMIT_CPU, 90)):
            soft, hard = resource.getrlimit(name)
            bounded_hard = maximum if hard == resource.RLIM_INFINITY else min(hard, maximum)
            bounded_soft = bounded_hard if soft == resource.RLIM_INFINITY else min(soft, bounded_hard)
            resource.setrlimit(name, (bounded_soft, bounded_hard))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except ImportError:
        pass
    if sys.argv[1] == '@stdin':
        length = int.from_bytes(sys.stdin.buffer.read(8), 'big')
        if not 0 < length <= 4 * 1024 * 1024:
            raise ValueError('Invalid worker configuration length')
        options = json.loads(sys.stdin.buffer.read(length))
    else:
        options = json.loads(sys.argv[1])
    if len(sys.argv) == 4:
        import os
        from analyzers.video import analyze_video
        with os.fdopen(int(sys.argv[3]), 'rb') as source:
            from analyzers.containers import ARCHIVES, OFFICE, search
            if options.get('_preview_spec'):
                from analyzers.embedded import render_preview
                return render_preview(source, sys.argv[2], options)
            if sys.argv[2] in ARCHIVES | OFFICE:
                return search(source, sys.argv[2], options, analyze)
            return analyze_video(source, options)
    data = sys.stdin.buffer.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024:
        result = dict(entries=[], limitations=['Analysis input exceeds 64 MiB bound'], status='failed')
    else:
        if options.get('_preview_spec'):
            from analyzers.embedded import render_preview
            result = render_preview(io.BytesIO(data), sys.argv[2], options)
        else:
            result = analyze(data, sys.argv[2], options)
    return result


if __name__ == '__main__':
    main()
