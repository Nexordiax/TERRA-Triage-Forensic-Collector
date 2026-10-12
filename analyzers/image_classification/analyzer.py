"""Explainable colour heuristic, never a semantic/biometric classification."""
from PIL import ImageChops

MODEL = 'ycbcr_chroma_v1'


def screen_selected(image, threshold=30, method='colour'):
    if method == 'semantic':
        from analyzers.image_classification.semantic import screen as semantic_screen
        return semantic_screen(image, threshold)
    if method != 'colour':
        raise ValueError('Unknown skin screening method')
    return screen(image, threshold)


def screen(image, threshold=30):
    if not 1 <= threshold <= 100:
        raise ValueError('Skin-colour threshold must be between 1 and 100')
    sample = image.convert('RGBA')
    try:
        sample.thumbnail((512, 512))
        alpha = sample.getchannel('A').point(lambda value: 255 if value >= 128 else 0)
        rgb = sample.convert('RGB')
        y, cb, cr = rgb.convert('YCbCr').split()
        masks = [y.point(lambda v: 255 if 20 <= v <= 245 else 0),
                 cb.point(lambda v: 255 if 77 <= v <= 127 else 0),
                 cr.point(lambda v: 255 if 133 <= v <= 173 else 0)]
        mask = alpha
        for component in masks:
            mask = ImageChops.multiply(mask, component)
        valid = alpha.histogram()[255]
        if not valid:
            raise ValueError('Image has no sufficiently opaque pixels to screen')
        candidates = mask.histogram()[255]
        percent = candidates * 100.0 / valid
        return dict(type='skin_colour_screen', model=MODEL, skin_like_percent=round(percent, 4),
                    review_candidate=percent >= threshold, threshold_percent=threshold,
                    sampled_width=sample.width, sampled_height=sample.height,
                    sampling='RGBA thumbnail up to 512 x 512; percentage measures eligible sampled pixels',
                    eligible_pixels=valid, candidate_pixels=candidates,
                    colour_ranges=dict(Y=[20, 245], Cb=[77, 127], Cr=[133, 173], alpha_minimum=128),
                    interpretation='Colour heuristic only; not proof of skin, nudity, age, identity or illegality; lighting and skin-coloured objects affect results')
    finally:
        sample.close()
