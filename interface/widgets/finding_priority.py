"""Presentation priority only: collection scope, scheduling and evidence stay intact."""
PRIORITY_CATEGORIES = ('Hash Matches', 'File Content Matches', 'OCR Matches', 'Image Similarity Matches', 'Skin-colour Review')


def category_rank(category):
    if category == 'Video Skin Review':
        return 4
    return PRIORITY_CATEGORIES.index(category) if category in PRIORITY_CATEGORIES else 100


def finding_rank(record):
    matches = record.get('matches', {})
    if matches.get('archive_hashes'):
        return 0
    for rank, name in enumerate(('hashes', 'file_contents', 'ocr', 'image_similarity')):
        if matches.get(name):
            return rank
    categories = record.get('additional_categories', [])
    if 'Skin-colour Review' in categories or 'Video Skin Review' in categories:
        return 4
    return 100
