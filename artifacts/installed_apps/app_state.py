"""Snap and Flatpak inventory metadata; assertions remain raw evidence."""
import configparser
import json

from artifacts.parser_support import ParseError, check_cancelled, entry


def parse(parser, data, cancelled):
    if parser == 'flatpak_metadata':
        document = configparser.ConfigParser(interpolation=None, strict=False)
        document.optionxform = str
        document.read_string(data.decode('utf-8'))
        if not document.has_section('Application'):
            raise ParseError('Flatpak Application metadata missing.')
        check_cancelled(cancelled)
        yield entry('package_record', 'Application', manager='flatpak',
                    package=document.get('Application', 'name', fallback=None),
                    runtime=document.get('Application', 'runtime', fallback=None),
                    fields={name: dict(document[name]) for name in document.sections()},
                    note='Deployment metadata presence does not establish that this revision is active or running.')
        return
    document = json.loads(data)
    snaps = document.get('data', {}).get('snaps') if isinstance(document, dict) else None
    if not isinstance(snaps, dict):
        raise ParseError('Snap state data.snaps inventory missing.')
    for name, state in snaps.items():
        check_cancelled(cancelled)
        if not isinstance(state, dict):
            raise ParseError('Invalid Snap state record.')
        sequence = state.get('sequence', [])
        if not isinstance(sequence, list):
            raise ParseError('Unsupported Snap sequence schema.')
        yield entry('package_record', f'data.snaps:{name}', manager='snap', package=name,
                    active=state.get('active'), current_revision=state.get('current'),
                    tracking_channel=state.get('channel'), revisions=sequence,
                    note='Snap persisted inventory; active flag does not prove execution.')
