"""Extend the forensic decoder for cyclic objects and non-scalar Map/Set keys."""
import datetime
import io
from dataclasses import dataclass, field

from artifacts.parser_support import ParseError, check_cancelled


@dataclass
class JSMap:
    entries: list = field(default_factory=list)


@dataclass
class JSSet:
    values: list = field(default_factory=list)


@dataclass
class JSSparseArray:
    length: int
    properties: dict = field(default_factory=dict)


@dataclass
class Hole:
    pass


@dataclass
class JSBigInt:
    value: int


@dataclass
class JSDate:
    milliseconds: float
    iso_utc: str | None


def decode(data, cancelled):
    from dfindexeddb.indexeddb.chromium import blink, v8, definitions
    from dfindexeddb.indexeddb import types
    tags = definitions.V8SerializationTag

    class Decoder(v8.ValueDeserializer):
        def __init__(self, stream, delegate):
            super().__init__(stream, delegate)
            self.depth = 0
            self.nodes = 0

        def _ReadObject(self):
            check_cancelled(cancelled)
            self.depth += 1
            self.nodes += 1
            try:
                if self.depth > 128 or self.nodes > 1_000_000:
                    raise ParseError('V8 object exceeds the nesting/node safety limit.')
                _, result = self._ReadObjectInternal()
                # Raw numeric fields follow strings in e.g. RegExp. Only buffers
                # can have a view tag; do not interpret those fields as tags.
                if isinstance(result, bytes):
                    stream = self.decoder.stream
                    position = stream.tell()
                    following = stream.read(1)
                    stream.seek(position)
                    if following == bytes([tags.ARRAY_BUFFER_VIEW]):
                        self._ConsumeTag(tags.ARRAY_BUFFER_VIEW)
                        result = self._ReadJSArrayBufferView(result)
                        self.objects[self._GetNextId()] = result
                return result
            finally:
                self.depth -= 1

        def _ReadJSObject(self):
            identity = self._GetNextId()
            value = {}
            self.objects[identity] = value  # References can occur before the object finishes.
            count = self._ReadJSObjectProperties(value, tags.END_JS_OBJECT)
            if self.decoder.DecodeUint32Varint()[1] != count:
                raise ParseError('V8 object property count mismatch.')
            return value

        def _ReadJSMap(self):
            identity = self._GetNextId()
            value = JSMap()
            self.objects[identity] = value
            while self._PeekTag() != tags.END_JS_MAP:
                value.entries.append((self._ReadObject(), self._ReadObject()))
            self._ConsumeTag(tags.END_JS_MAP)
            if self.decoder.DecodeUint32Varint()[1] != len(value.entries) * 2:
                raise ParseError('V8 Map entry count mismatch.')
            return value

        def _ReadJSSet(self):
            identity = self._GetNextId()
            value = JSSet()
            self.objects[identity] = value
            while self._PeekTag() != tags.END_JS_SET:
                value.values.append(self._ReadObject())
            self._ConsumeTag(tags.END_JS_SET)
            if self.decoder.DecodeUint32Varint()[1] != len(value.values):
                raise ParseError('V8 Set entry count mismatch.')
            return value

        def ReadSparseJSArray(self):
            identity = self._GetNextId()
            length = self.decoder.DecodeUint32Varint()[1]
            value = JSSparseArray(length)
            self.objects[identity] = value
            count = self._ReadJSObjectProperties(value, tags.END_SPARSE_JS_ARRAY)
            expected, expected_length = self.decoder.DecodeUint32Varint()[1], self.decoder.DecodeUint32Varint()[1]
            if count != expected or length != expected_length:
                raise ParseError('V8 sparse array length/property mismatch.')
            return value

        def ReadDenseJSArray(self):
            identity = self._GetNextId()
            length = self.decoder.DecodeUint32Varint()[1]
            if length > 1_000_000:
                raise ParseError('V8 dense array exceeds the node safety limit.')
            value = types.JSArray()
            self.objects[identity] = value
            for _ in range(length):
                if self._PeekTag() == tags.THE_HOLE:
                    self._ConsumeTag(tags.THE_HOLE)
                    value.values.append(Hole())
                else:
                    value.values.append(self._ReadObject())
            count = self._ReadJSObjectProperties(value, tags.END_DENSE_JS_ARRAY)
            expected, expected_length = self.decoder.DecodeUint32Varint()[1], self.decoder.DecodeUint32Varint()[1]
            if count != expected or length != expected_length:
                raise ParseError('V8 dense array length/property mismatch.')
            return value

        def ReadBigInt(self):
            return JSBigInt(super().ReadBigInt())

        def _ReadJSDate(self):
            identity = self._GetNextId()
            milliseconds = self.decoder.DecodeDouble()[1]
            try:
                iso = datetime.datetime.fromtimestamp(milliseconds / 1000, datetime.timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                iso = None
            value = JSDate(milliseconds, iso)
            self.objects[identity] = value
            return value

    delegate = blink.V8ScriptValueDecoder(data)
    start = delegate._ReadVersionEnvelope()
    end = len(data)
    if delegate.trailer_size:
        if not start <= delegate.trailer_offset <= len(data) or delegate.trailer_offset + delegate.trailer_size > len(data):
            raise ParseError('Blink trailer is outside the serialized value.')
        end = delegate.trailer_offset
    delegate.deserializer = Decoder(io.BytesIO(data[start:end]), delegate)
    if not delegate.deserializer.ReadHeader():
        raise ParseError('Unsupported V8 serialization version.')
    value = delegate.deserializer.ReadValue()
    stream = delegate.deserializer.decoder.stream
    if any(stream.read()):
        raise ParseError('Unsupported trailing serialized V8 data.')
    return value
