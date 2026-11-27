const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const { readFile } = require('node:fs/promises');
const test = require('node:test');
const { prepareDatabase } = require('../stars.js');

test('refuses files outside the supported edition', async () => {
  await assert.rejects(prepareDatabase(new Blob(['wrong file']), true, webcrypto.subtle), /English retail/);
  await assert.rejects(
    prepareDatabase(new Blob([new Uint8Array(1097585)]), true, webcrypto.subtle),
    /does not match/,
  );
});

test('retail patch changes one byte and opt-out preserves the selected file', {
  skip: !process.env.SKEZMOD_TEST_EQ,
}, async () => {
  const stock = await readFile(process.env.SKEZMOD_TEST_EQ);
  const prepare = (bytes, apply) => prepareDatabase(new Blob([bytes]), apply, webcrypto.subtle);
  const unchanged = await prepare(stock, false);
  assert.equal(unchanged.fixed, false);
  assert.deepEqual(Buffer.from(unchanged.bytes), stock);
  const fixed = await prepare(stock, true);
  const expected = Buffer.from(stock);
  assert.equal(expected.readUInt32LE(7040), 9900);
  expected.writeUInt32LE(9899, 7040);
  assert.equal(fixed.fixed, true);
  assert.deepEqual(Buffer.from(fixed.bytes), expected);
  for (const apply of [true, false]) {
    const repeat = await prepare(expected, apply);
    assert.equal(repeat.fixed, true);
    assert.deepEqual(Buffer.from(repeat.bytes), expected);
  }
});
