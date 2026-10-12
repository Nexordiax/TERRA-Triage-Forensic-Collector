import hashlib


class HashMatcher:
    algorithms = {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}

    def __init__(self, hashes):
        self.hashes = {value.strip().lower() for value in hashes}
        self.names = {self.algorithms[len(value)] for value in self.hashes}

    def match(self, data):
        stream = self.stream()
        stream.update(data)
        return stream.matches()

    def stream(self, integrity_sha256=False):
        return HashStream(self.names, self.hashes, integrity_sha256)


class HashStream:
    def __init__(self, names, hashes, integrity_sha256=False):
        self.reuse_sha256 = integrity_sha256 and 'sha256' in names
        self.integrity_sha256 = None
        self.digests = {name: hashlib.new(name, usedforsecurity=False) for name in sorted(names)
                        if not (name == 'sha256' and self.reuse_sha256)}
        self.hashes = hashes

    def update(self, chunk):
        for digest in self.digests.values():
            digest.update(chunk)

    def matches(self):
        return {name: value for name, value in self.calculated().items() if value in self.hashes}

    def calculated(self):
        result = {name: digest.hexdigest() for name, digest in self.digests.items()}
        if self.reuse_sha256:
            if self.integrity_sha256 is None:
                raise ValueError('Acquisition SHA256 must be finalized before matching.')
            result['sha256'] = self.integrity_sha256
        return result
