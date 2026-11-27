// Tests for pickPackage and makePackage with synthetic files only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crc32, makePackage, pickPackage } from '../src/package.js';

const fake = (rel, size = 3) => ({ webkitRelativePath: `pkg/${rel}`, size });
const paths = (files) => pickPackage(files).map((e) => e.path);

test('pickPackage keeps only textdb.ini and the whitelisted TEXTDB files', () => {
  const got = paths([
    fake('textdb.ini'), fake('TEXTDB/a.tsv'), fake('TEXTDB/sub/b.json'), fake('TEXTDB/cache/c.tsv'),
    fake('TEXTDB/readme.txt'), fake('other/x.tsv'), fake('notes.txt'),
  ]);
  assert.deepEqual(got, ['textdb.ini', 'TEXTDB/a.tsv', 'TEXTDB/sub/b.json']);
});

test('pickPackage refuses invalid names and says which file and the rule', () => {
  for (const bad of ['TEXTDB/players (copy).tsv', 'TEXTDB/-a.tsv', 'TEXTDB/a b.tsv', 'TEXTDB/ü.tsv', `TEXTDB/${'x'.repeat(230)}.tsv`]) {
    assert.throws(() => pickPackage([fake('textdb.ini'), fake(bad)]), (e) => {
      assert.match(e.message, /Invalid package path/);
      assert.ok(e.message.includes(bad));
      assert.match(e.message, /A-Z a-z 0-9/);
      return true;
    });
  }
});

test('pickPackage refuses case-insensitive duplicates', () => {
  assert.throws(() => pickPackage([fake('textdb.ini'), fake('TEXTDB/a.tsv'), fake('TEXTDB/A.tsv')]), /Duplicate package path/);
});

test('pickPackage requires textdb.ini and a TEXTDB file', () => {
  assert.throws(() => pickPackage([fake('TEXTDB/a.tsv')]), /textdb\.ini/);
  assert.throws(() => pickPackage([fake('textdb.ini')]), /textdb\.ini/);
});

test('pickPackage enforces the size and count limits', () => {
  assert.throws(() => pickPackage([fake('textdb.ini', 40 * 1024 * 1024), fake('TEXTDB/a.tsv', 40 * 1024 * 1024)]), /exceeds/);
  const many = [fake('textdb.ini')];
  for (let i = 0; i < 1100; i++) many.push(fake(`TEXTDB/f${i}.tsv`, 1));
  assert.throws(() => pickPackage(many), /exceeds/);
});

test('crc32 known vectors', () => {
  assert.equal(crc32(new Uint8Array(0)), 0);
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
});

// Tiny reader for the stored ZIP written by makePackage.
function readZip(buf) {
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const eocd = buf.length - 22;
  assert.equal(v.getUint32(eocd, true), 0x06054b50);
  const count = v.getUint16(eocd + 10, true);
  assert.equal(v.getUint16(eocd + 8, true), count);
  const dirSize = v.getUint32(eocd + 12, true);
  const dirOff = v.getUint32(eocd + 16, true);
  assert.equal(dirOff + dirSize, eocd);
  const out = [];
  let p = dirOff;
  for (let i = 0; i < count; i++) {
    assert.equal(v.getUint32(p, true), 0x02014b50);
    assert.equal(v.getUint16(p + 10, true), 0, 'stored');
    const crc = v.getUint32(p + 16, true);
    const csize = v.getUint32(p + 20, true);
    const usize = v.getUint32(p + 24, true);
    const nlen = v.getUint16(p + 28, true);
    const loff = v.getUint32(p + 42, true);
    const name = new TextDecoder().decode(buf.subarray(p + 46, p + 46 + nlen));
    assert.equal(v.getUint32(loff, true), 0x04034b50);
    assert.equal(v.getUint16(loff + 26, true), nlen);
    assert.equal(v.getUint32(loff + 14, true), crc);
    assert.equal(v.getUint32(loff + 22, true), usize);
    const dataStart = loff + 30 + nlen + v.getUint16(loff + 28, true);
    out.push({ name, crc, csize, usize, data: buf.subarray(dataStart, dataStart + usize) });
    p += 46 + nlen;
  }
  assert.equal(p, dirOff + dirSize);
  return out;
}

test('makePackage writes a stored ZIP whose names, sizes and crc32 read back', async () => {
  const enc = new TextEncoder();
  const input = [
    { path: 'DBDAT/A.FDI', bytes: enc.encode('hello world') },
    { path: 'calendar.pmc', bytes: new Uint8Array(0) },
    { path: 'DBDAT/B.FDI', bytes: Uint8Array.from({ length: 70000 }, (_, i) => (i * 7) & 255) },
  ];
  const blob = makePackage(input);
  assert.equal(blob.type, 'application/zip');
  const zip = readZip(new Uint8Array(await blob.arrayBuffer()));
  assert.deepEqual(zip.map((e) => e.name), input.map((e) => e.path));
  zip.forEach((e, i) => {
    assert.equal(e.usize, input[i].bytes.length);
    assert.equal(e.csize, e.usize);
    assert.equal(e.crc, crc32(input[i].bytes));
    assert.deepEqual(Array.from(e.data), Array.from(input[i].bytes));
  });
  assert.equal(zip[0].crc, 0x0d4a1185); // crc32("hello world")
});

test('makePackage refuses too many files', () => {
  const many = Array.from({ length: 1025 }, (_, i) => ({ path: `f${i}`, bytes: new Uint8Array(0) }));
  assert.throws(() => makePackage(many), /Too many/);
});
