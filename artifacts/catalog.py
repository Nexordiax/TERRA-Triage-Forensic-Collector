"""Data-only Linux path definitions; matching never searches outside selected targets."""
import json
import re
from pathlib import Path

CATALOG = json.loads(Path(__file__).with_name('linux_catalog.json').read_text())
DISTRO = json.loads(Path(__file__).with_name('linux_distribution_index.json').read_text())
CATALOG['sources'].update(DISTRO['sources'])
CATALOG['researched_on'] = DISTRO['researched_on']
for definition in CATALOG['artifacts']:
    expansion = DISTRO['path_expansions'].get(definition['id'])
    if expansion:
        definition['paths'] = list(dict.fromkeys(definition['paths'] + expansion['paths']))
        definition['sources'] = list(dict.fromkeys(definition['sources'] + expansion['sources']))
CATALOG['artifacts'] = DISTRO['artifacts'] + CATALOG['artifacts']
CRYPTO = json.loads((Path(__file__).parent / 'cryptocurrency/index.json').read_text())
CATALOG['sources'].update(CRYPTO['sources'])
CATALOG['artifacts'] = CRYPTO['artifacts'] + CATALOG['artifacts']
for group in ('cloud_storage', 'dark_web', 'anti_forensics', 'virtual_machines'):
    index = json.loads((Path(__file__).parent / group / 'index.json').read_text())
    CATALOG['sources'].update(index['sources'])
    CATALOG['artifacts'] = ([item for item in index['artifacts'] if not item.get('fallback_only')]
                            + CATALOG['artifacts']
                            + [item for item in index['artifacts'] if item.get('fallback_only')])


def pattern_regex(pattern):
    parts = []
    index = 0
    while index < len(pattern):
        if pattern[index:index + 3] == '**/':
            parts.append('(?:.*/)?')
            index += 3
        elif pattern[index:index + 2] == '**':
            parts.append('.*')
            index += 2
        elif pattern[index] == '*':
            parts.append('[^/]*')
            index += 1
        else:
            parts.append(re.escape(pattern[index]))
            index += 1
    return re.compile('(?:^|.*)' + ''.join(parts) + '$')


DEFINITIONS = [(definition, [pattern_regex(pattern) for pattern in definition['paths']])
               for definition in CATALOG['artifacts']]


def definition_for(path):
    normalized = Path(path).as_posix()
    for definition, patterns in DEFINITIONS:
        if any(pattern.fullmatch(normalized) for pattern in patterns):
            return definition
    return None


def source_links(definition):
    return [CATALOG['sources'][name] for name in definition['sources']]
