"""Case export destinations next to the application, independent of RAM capture."""
import re
from datetime import datetime, timezone
from pathlib import Path

APPLICATION_DIRECTORY = Path(__file__).resolve().parents[1]


def cases_directory():
    directory = APPLICATION_DIRECTORY / 'cases'
    if directory.is_symlink():
        raise ValueError('The cases directory cannot be a symbolic link.')
    directory.mkdir(mode=0o700, exist_ok=True)
    if not directory.is_dir():
        raise ValueError('The cases path is not a directory.')
    return directory


def case_export_path(case, timestamp=None):
    def component(value, fallback):
        return re.sub(r'[^\w.-]+', '_', value or '', flags=re.ASCII).strip('._')[:80] or fallback
    stamp = (timestamp or datetime.now(timezone.utc)).strftime('%Y-%m-%d_%H-%M-%S-%f')
    return cases_directory() / (component(case.get('id'), 'No-ID') + '-'
                                + component(case.get('name'), 'Unnamed-Case') + '-' + stamp + '-.zip')
