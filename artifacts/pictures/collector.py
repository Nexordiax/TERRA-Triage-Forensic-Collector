from pathlib import Path
from analyzers.image_formats import IMAGES
from analyzers.video import VIDEOS


def classify(path):
    extension = Path(path).suffix.lower()
    if extension in IMAGES:
        return 'Pictures'
    if extension in VIDEOS:
        return 'Videos'
    if extension in {'.mp3', '.wav', '.flac', '.ogg', '.m4a', '.aac', '.opus'}:
        return 'Audio'
