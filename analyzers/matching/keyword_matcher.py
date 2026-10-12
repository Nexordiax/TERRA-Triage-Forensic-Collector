import codecs


class KeywordMatcher:
    def __init__(self, keywords):
        self.keywords = [(value, value.casefold()) for value in keywords]

    def match_name(self, name):
        folded = name.casefold()
        return [original for original, value in self.keywords if value in folded]

    def match_content(self, data):
        stream = self.stream()
        stream.update(data)
        return stream.matches()

    def stream(self):
        return KeywordStream(self.keywords)


class KeywordStream:
    """Keep a UTF-8 decoder and overlap so keywords can span read boundaries."""
    def __init__(self, keywords):
        self.keywords = keywords
        self.decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
        self.overlap = max((len(value) for _, value in keywords), default=1) - 1
        self.tail = ''
        self.found = set()

    def update(self, chunk, final=False):
        text = self.tail + self.decoder.decode(chunk, final=final).casefold()
        for original, value in self.keywords:
            if value in text:
                self.found.add(original)
        self.tail = text[-self.overlap:] if self.overlap else ''

    def matches(self):
        self.update(b'', final=True)
        return [original for original, _ in self.keywords if original in self.found]
