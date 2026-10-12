from pathlib import Path


def classify(path):
    parts = {part.lower() for part in Path(path).parts}
    name = Path(path).name.lower()
    browsers = {'.mozilla', 'firefox', 'chromium', 'google-chrome', 'brave-browser', 'microsoft-edge'}
    files = {'places.sqlite', 'cookies.sqlite', 'formhistory.sqlite', 'logins.json',
             'key4.db', 'history', 'cookies', 'login data', 'web data', 'bookmarks', 'preferences'}
    base = name.removesuffix('-wal').removesuffix('-shm')
    if parts & browsers and base in files:
        return 'Browsers'
