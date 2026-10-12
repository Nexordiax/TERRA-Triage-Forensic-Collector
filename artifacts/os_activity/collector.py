from pathlib import Path


def classify(path):
    normalized = Path(path).as_posix()
    if '/var/log/' in normalized or Path(path).name in {'.bash_history', '.zsh_history', '.python_history', '.recently-used.xbel'}:
        return 'OS Activity'
