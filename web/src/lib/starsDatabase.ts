const EQ_HASHES = Object.freeze({
  stock: 'e095cb47ffdb6c8edf384983545124eb514d044fa4f0ce7d924b6bfe13252a5c',
  fixed: 'e328c48794ae4b86933a09ae2581f08dadcf30412406cea2e00d2993250097ca',
});

export async function prepareDatabase(file: Blob, applyFix: boolean, subtle = globalThis.crypto?.subtle) {
  if (!subtle) throw new Error('Open the patcher from localhost or an HTTPS page.');
  if (file.size !== 1097585) throw new Error('Choose EQ98030.FDI from the English retail game.');

  const bytes = await file.arrayBuffer();
  const hash = async () => Array.from(new Uint8Array(await subtle.digest('SHA-256', bytes)),
    byte => byte.toString(16).padStart(2, '0')).join('');
  const original = await hash();
  if (original !== EQ_HASHES.stock && original !== EQ_HASHES.fixed) {
    throw new Error('This database does not match the supported English retail game.');
  }
  if (applyFix && original === EQ_HASHES.stock) {
    // Both hashes pin the exact retail layout and the output of the verified ID-only repair.
    const index = new DataView(bytes);
    if (index.getUint32(7040, true) !== 9900) throw new Error('The Stars record is missing.');
    index.setUint32(7040, 9899, true);
    if (await hash() !== EQ_HASHES.fixed) throw new Error('The Stars fix failed verification.');
  }
  return { bytes, fixed: applyFix || original === EQ_HASHES.fixed };
}
