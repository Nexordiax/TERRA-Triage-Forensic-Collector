"""Read companion inputs only within selected targets, without following symlinks."""
import os
from contextlib import contextmanager

from artifacts.parser_support import ParseError, read_verified, verify_unchanged


@contextmanager
def selected_directory(directory, targets):
    directory = os.path.abspath(directory)
    if not any(os.path.commonpath((directory, os.path.abspath(root))) == os.path.abspath(root)
               for root in targets):
        raise ParseError('Required companion directory is outside the selected targets.')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in directory.split('/')[1:]:
            if not part:
                continue
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        yield descriptor
    finally:
        os.close(descriptor)


def companion_names(directory, targets):
    with selected_directory(directory, targets) as descriptor:
        # Bound enumeration before sorting an untrusted directory.
        names = []
        with os.scandir(descriptor) as entries:
            for item in entries:
                if len(names) >= 10000:
                    raise ParseError('Companion directory exceeds the 10000-entry safety limit.')
                names.append(item.name)
        return sorted(names)


def verify_companion(path, metadata, targets):
    with selected_directory(os.path.dirname(path), targets) as descriptor:
        verify_unchanged(path, metadata, descriptor)


def read_companion(path, targets, cancelled, max_size=None):
    path = os.path.abspath(path)
    if not any(os.path.commonpath((path, os.path.abspath(root))) == os.path.abspath(root)
               for root in targets):
        raise ParseError('Required companion is outside the selected targets.')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.split('/')[1:-1]:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        if max_size is not None and os.stat(os.path.basename(path), dir_fd=descriptor, follow_symlinks=False).st_size > max_size:
            raise ParseError('Companion exceeds the decoded-object snapshot safety limit.')
        data, metadata = read_verified(path, directory_fd=descriptor, cancelled=cancelled)
        verify_unchanged(path, metadata, descriptor)
        return data, metadata
    finally:
        os.close(descriptor)
