from artifacts.catalog import definition_for
from artifacts.browsers.collector import classify as browsers
from artifacts.communication.collector import classify as communication
from artifacts.device_info.collector import classify as device_info
from artifacts.documents.collector import classify as documents
from artifacts.os_activity.collector import classify as os_activity
from artifacts.pictures.collector import classify as media


COLLECTORS = (device_info, browsers, communication, os_activity, media, documents)


def category_for(path):
    """Classify indexed Linux artifacts, then use media/document fallback rules."""
    definition = definition_for(path)
    if definition:
        return definition['category']
    for collector in COLLECTORS:
        category = collector(path)
        if category:
            return category
