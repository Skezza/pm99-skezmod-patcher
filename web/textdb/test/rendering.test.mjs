import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pickRenderingFiles, collectRenderingFiles } from '../src/rendering.js';

function file(name, data) {
  return Object.assign(new Blob([data]), { name });
}

test('renderer collection validates the DLL and preserves the selected files', async () => {
  const dll = new Uint8Array(90);
  const pe = new DataView(dll.buffer);
  pe.setUint16(0, 0x5a4d, true);
  pe.setUint32(60, 64, true);
  pe.setUint32(64, 0x4550, true);
  pe.setUint16(68, 0x14c, true);
  pe.setUint16(86, 0x2000, true);
  pe.setUint16(88, 0x10b, true);
  const files = [file('DDRAW.DLL', dll), file('ddraw.ini', 'example')];
  const collected = await collectRenderingFiles(pickRenderingFiles(files));
  assert.deepEqual(collected.map(({ path }) => path), ['ddraw.dll', 'ddraw.ini']);
  assert.deepEqual(collected[0].bytes, dll);
  pe.setUint16(68, 0x8664, true);
  await assert.rejects(collectRenderingFiles(pickRenderingFiles([file('ddraw.dll', dll)])), /32-bit/);
  assert.throws(() => pickRenderingFiles([files[1]]), /with its configuration/);
  assert.throws(() => pickRenderingFiles([files[0], files[0]]), /one ddraw.dll/);
});
