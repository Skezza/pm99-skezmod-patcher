// Tests for the manifest, the checklist and the verdict. No game data: every
// "file" here is a fake object, and hashing is injected so a fake file can
// claim any digest.
//
// Run: npm test   (node:test, no dependencies)

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { MANIFEST, captureEntries } from '../src/manifest.js';
import {
  baseName,
  checkFiles,
  hashFile,
  pickWanted,
  sha256Hex,
  summarise,
  verdictFor,
} from '../src/verify.js';

const HEX64 = /^[0-9a-f]{64}$/;

// A fake file: a name plus the digest it "has" (used by the injected hash).
const fake = (name, fakeSha) => ({ name, fakeSha });
const hashFake = async (file) => file.fakeSha;

// Build a fake chosen set. `overrides` maps manifest id -> digest, or null to omit.
function fakeGameFolder(overrides = {}) {
  const files = [];
  for (const e of captureEntries()) {
    const sha = Object.prototype.hasOwnProperty.call(overrides, e.id) ? overrides[e.id] : e.sha256;
    if (sha === null) continue;
    files.push(fake(e.path, sha));
  }
  return files;
}

async function run(files) {
  const picked = pickWanted(files);
  const rows = await checkFiles(picked, { hash: hashFake });
  const summary = summarise(rows);
  return { picked, rows, summary, verdict: verdictFor(summary) };
}

// ---- helpers -------------------------------------------------------------------

test('sha256Hex matches the standard test vector for "abc"', async () => {
  const data = new TextEncoder().encode('abc');
  assert.equal(
    await sha256Hex(data),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
});

test('baseName accepts both separators', () => {
  assert.equal(baseName('Game/DBDAT/JUG98030.FDI'), 'JUG98030.FDI');
  assert.equal(baseName('Game\\DBDAT\\JUG98030.FDI'), 'JUG98030.FDI');
  assert.equal(baseName('MANAGPRE.EXE'), 'MANAGPRE.EXE');
});

test('hashFile streams a Blob with progress and matches sha256', async () => {
  const seen = [];
  const digest = await hashFile(new Blob(['abc']), {
    onProgress: (read, total) => seen.push([read, total]),
  });
  assert.equal(digest, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.ok(seen.length >= 1);
  assert.deepEqual(seen.at(-1), [3, 3]);
});

// ---- manifest ------------------------------------------------------------------

test('manifest ids are unique and paths are plain relative paths', () => {
  const ids = MANIFEST.map((e) => e.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate id');
  for (const e of MANIFEST) {
    assert.ok(!e.path.includes('\\'), `backslash in ${e.path}`);
    assert.ok(!e.path.startsWith('/') && !e.path.split('/').includes('..'), `unsafe path ${e.path}`);
  }
});

test('every captured input has a valid SHA-256 pin; nothing else does', () => {
  for (const e of captureEntries()) {
    assert.match(e.sha256, HEX64, `${e.path} lacks a 64-hex pin`);
  }
  for (const e of MANIFEST.filter((x) => x.kind !== 'input')) {
    if (e.sha256 !== null) assert.match(e.sha256, HEX64, `${e.path} has a bad pin`);
  }
});

test('required captures are exactly the five edition files, FECHCONV.30 is optional', () => {
  const required = captureEntries()
    .filter((e) => e.required)
    .map((e) => e.path)
    .sort();
  assert.deepEqual(required, [
    'DBDAT/ENT98030.FDI',
    'DBDAT/EQ98030.FDI',
    'DBDAT/JUG98030.FDI',
    'DBDAT/TEXTOS.PKF',
    'MANAGPRE.EXE',
  ]);
  const optional = captureEntries().filter((e) => !e.required).map((e) => e.path);
  assert.deepEqual(optional, ['DBDAT/FECHCONV.30']);
});

test('derived and out-of-scope entries are never captured', () => {
  const capturedPaths = captureEntries().map((e) => e.path);
  for (const e of MANIFEST.filter((x) => x.kind !== 'input')) {
    assert.ok(!capturedPaths.includes(e.path), `${e.path} must not be captured`);
  }
  assert.ok(MANIFEST.some((e) => e.kind === 'derived' && e.path === 'calendar.pmc'));
  assert.ok(MANIFEST.some((e) => e.kind === 'out-of-scope' && e.path === 'DBDAT/MINIFOTO.PKF'));
});

test('the FECHCONV.30 origin is marked as docs-only, with the unconfirmed part stated', () => {
  const fe = MANIFEST.find((e) => e.id === 'fechconv');
  assert.equal(fe.confirmed, 'docs');
  assert.match(fe.source, /UNCONFIRMED/);
});

// ---- picking files -------------------------------------------------------------

test('pickWanted matches nested paths case-insensitively and ignores other files', () => {
  const picked = pickWanted([
    fake('Game/dbdat/jug98030.fdi', 'x'),
    fake('Game\\DBDAT\\TEXTOS.PKF', 'x'),
    fake('Game/DBDAT/MINIFOTO.PKF', 'x'),
    fake('Game/calendar.pmc', 'x'),
    fake('Game/DBDAT/TEXTOS/PAISES.30', 'x'),
    fake('Game/readme.txt', 'x'),
  ]);
  assert.deepEqual([...picked.keys()].sort(), ['jug', 'textos']);
});

test('pickWanted keeps the first file when a name appears twice', () => {
  const a = fake('a/EQ98030.FDI', 'first');
  const b = fake('b/EQ98030.FDI', 'second');
  assert.equal(pickWanted([a, b]).get('eq'), a);
});

// ---- checklist and verdict -----------------------------------------------------

test('complete fake set: 6 of 6 captured, build enabled, supported', async () => {
  const { summary, verdict } = await run(fakeGameFolder());
  assert.equal(summary.capturedOk, 6);
  assert.equal(summary.capturedTotal, 6);
  assert.equal(summary.requiredOk, 5);
  assert.equal(summary.requiredTotal, 5);
  assert.equal(summary.canBuild, true);
  assert.equal(verdict.state, 'supported');
});

test('optional FECHCONV.30 absent: 5 of 6 captured, build still enabled', async () => {
  const { summary, rows, verdict } = await run(fakeGameFolder({ fechconv: null }));
  assert.equal(summary.capturedOk, 5);
  assert.equal(summary.canBuild, true);
  assert.equal(rows.find((r) => r.id === 'fechconv').status, 'not-provided');
  assert.equal(verdict.state, 'supported');
});

test('a missing required file blocks the build and is named', async () => {
  const { summary, rows, verdict } = await run(fakeGameFolder({ jug: null }));
  assert.equal(summary.canBuild, false);
  assert.equal(summary.requiredOk, 4);
  assert.deepEqual(
    summary.missing.map((r) => r.path),
    ['DBDAT/JUG98030.FDI'],
  );
  assert.equal(rows.find((r) => r.id === 'jug').status, 'missing');
  assert.equal(verdict.state, 'incomplete');
  assert.match(verdict.message, /DBDAT\/JUG98030\.FDI/);
});

test('a wrong-hash required file refuses the edition and blocks the build', async () => {
  const { summary, verdict } = await run(fakeGameFolder({ eq: '0'.repeat(64) }));
  assert.equal(summary.canBuild, false);
  assert.deepEqual(
    summary.wrong.map((r) => r.path),
    ['DBDAT/EQ98030.FDI'],
  );
  assert.equal(verdict.state, 'unsupported');
  assert.equal(verdict.title, 'This edition is not supported');
});

test('a wrong-hash optional file still blocks the build (it is the wrong edition)', async () => {
  const { summary, verdict } = await run(fakeGameFolder({ fechconv: 'f'.repeat(64) }));
  assert.equal(summary.canBuild, false);
  assert.equal(verdict.state, 'unsupported');
});

test('nothing chosen, or only out-of-scope and derived names chosen: no verdict yet', async () => {
  const none = await run([]);
  assert.equal(none.verdict.state, 'nothing');
  assert.equal(none.summary.canBuild, false);

  const notCaptured = await run([
    fake('DBDAT/MINIFOTO.PKF', 'x'),
    fake('calendar.pmc', '542f237822016e1a58a7c9ea3d08a7186063ea2f26b6cd7afc4c48f82a57a88c'),
    fake('DBDAT/TEXTOS/PAISES.30', 'x'),
  ]);
  assert.equal(notCaptured.verdict.state, 'nothing');
  assert.equal(notCaptured.summary.canBuild, false);
});

test('checkFiles hashes only the chosen files, in manifest order, and reports progress', async () => {
  const picked = pickWanted([
    fake('TEXTOS.PKF', 'x'),
    fake('MANAGPRE.EXE', '01b845f7dc728e3813968bed51ff24810fde556fab395e97ca7649c57ee53158'),
  ]);
  const hashed = [];
  const progress = [];
  const rows = await checkFiles(picked, {
    hash: async (f) => {
      hashed.push(f.name);
      return f.fakeSha;
    },
    onFile: (p) => progress.push(p.path),
  });
  assert.deepEqual(hashed, ['MANAGPRE.EXE', 'TEXTOS.PKF']);
  assert.deepEqual(progress, ['MANAGPRE.EXE', 'DBDAT/TEXTOS.PKF']);
  assert.equal(rows.length, 6);
});

// ---- size pre-check, per-file messages, Stars rewrite ------------------------------

import { rewriteStarsId } from '../src/stars.js';

test('wrong size is reported immediately: never read, never hashed', async () => {
  const eq = captureEntries().find((e) => e.id === 'eq');
  let reads = 0;
  let hashes = 0;
  const big = {
    name: 'DBDAT/EQ98030.FDI',
    size: eq.size + 1,
    arrayBuffer: async () => { reads += 1; return new ArrayBuffer(0); },
    stream: () => { reads += 1; },
  };
  const rows = await checkFiles(pickWanted([big]), { hash: async () => { hashes += 1; return 'x'; } });
  const row = rows.find((r) => r.id === 'eq');
  assert.equal(row.status, 'wrong-size');
  assert.match(row.reason, /wrong size: \d+ bytes, expected \d+ bytes/);
  assert.equal(reads, 0);
  assert.equal(hashes, 0);
  const summary = summarise(rows);
  assert.equal(summary.canBuild, false);
  assert.equal(verdictFor(summary).state, 'unsupported');
});

test('the verdict lists each failing file on its own line with its reason', async () => {
  const entries = captureEntries();
  const eq = entries.find((e) => e.id === 'eq');
  const jug = entries.find((e) => e.id === 'jug');
  const files = [
    { name: eq.path, size: eq.size + 5 },
    { name: jug.path, size: jug.size, fakeSha: '0'.repeat(64) },
  ];
  const rows = await checkFiles(pickWanted(files), { hash: hashFake });
  const verdict = verdictFor(summarise(rows));
  assert.equal(verdict.details.length, 2);
  assert.match(verdict.details[0], /^DBDAT\/JUG98030\.FDI: checksum differs/);
  assert.match(verdict.details[1], /^DBDAT\/EQ98030\.FDI: wrong size/);
});

function syntheticEq(ids, named = [9900]) {
  const payload = 20 + 16 * ids.length;
  const bytes = new Uint8Array(payload + 49 * ids.length);
  bytes.set(new TextEncoder().encode('DMFIv1.0'));
  const v = new DataView(bytes.buffer);
  v.setUint32(16, ids.length, true);
  ids.forEach((id, index) => {
    const off = 20 + index * 16;
    const start = payload + index * 49;
    v.setUint32(off, id, true);
    v.setUint8(off + 4, 3);
    v.setUint32(off + 8, start, true);
    v.setUint32(off + 12, 49, true);
    v.setUint16(start + 42, 5, true);
    bytes.set(Uint8Array.from(named.includes(id) ? 'Stars' : 'Other', c => c.charCodeAt(0) ^ 0x61), start + 44);
  });
  return bytes;
}

test('rewriteStarsId changes only the club id and is repeatable', () => {
  const bytes = syntheticEq([1, 9900, 7]);
  const expected = bytes.slice();
  new DataView(expected.buffer).setUint32(36, 9899, true);
  rewriteStarsId(bytes);
  assert.deepEqual(bytes, expected);
  rewriteStarsId(bytes);
  assert.deepEqual(bytes, expected);
});

test('rewriteStarsId refuses a collision, a different club, or a truncated directory', () => {
  assert.throws(() => rewriteStarsId(syntheticEq([9899, 9900])), /already in use/);
  assert.throws(() => rewriteStarsId(syntheticEq([9900], [])), /not a Stars record/);
  assert.throws(() => rewriteStarsId(new Uint8Array(4)), /valid club database/);
  const bad = syntheticEq([1]);
  new DataView(bad.buffer).setUint32(16, 5000, true);
  assert.throws(() => rewriteStarsId(bad), /truncated/);
});
