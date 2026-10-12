// Independent V8 serializer fixture, containing cycles and non-scalar Map/Set keys.
// Run with Node: node tests/fixtures/make_v8_object.js
const v8 = require('node:v8');
const fs = require('node:fs');
const shared = {body: 'fixture message'};
const value = {
  shared, alias: shared,
  map: new Map([[shared, 'object key'], ['counter', 7]]),
  set: new Set([shared, 'member']),
  array: [1, undefined, null, true],
  sparse: Object.assign(new Array(1000000000), {999999999: 'last'}),
  date: new Date('2024-01-02T03:04:05Z'),
  bigint: 123456789012345678901234567890n,
  pattern: /example/gi,
  bytes: new Uint8Array([1, 2, 255]),
};
value.self = value;
const serializer = new v8.Serializer();
serializer.writeHeader();
serializer.writeValue(value);
fs.writeFileSync('tests/fixtures/v8-object.bin', serializer.releaseBuffer());
