from pathlib import Path


def classify(path):
    parts = {part.lower() for part in Path(path).parts}
    extension = Path(path).suffix.lower()
    if extension in {'.eml', '.mbox', '.pst', '.ost'}:
        return 'Email'
    if parts & {'telegramdesktop', 'signal', 'skype', 'discord', 'thunderbird', '.thunderbird'}:
        if extension in {'.db', '.sqlite', '.sqlite3', '.json'} or Path(path).name.lower() in {'data', 'key_datas'}:
            return 'Communication'
