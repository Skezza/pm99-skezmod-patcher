/** Change only the ID in a club database produced by the TextDB builder. */
export function rewriteStarsId(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 20 || new TextDecoder().decode(bytes.subarray(0, 8)) !== 'DMFIv1.0') {
    throw new Error('The build did not produce a valid club database.');
  }
  const count = view.getUint32(16, true);
  let offset = 20;
  let stars;
  let target;
  for (let i = 0; i < count; i++) {
    if (offset + 13 > bytes.length) throw new Error('The club directory is truncated.');
    const directory = offset + 5 + view.getUint8(offset + 4);
    if (directory + 8 > bytes.length) throw new Error('The club directory is truncated.');
    const id = view.getUint32(offset, true);
    if (id === 9900 || id === 9899) {
      const payload = view.getUint32(directory, true);
      const size = view.getUint32(directory + 4, true);
      // The EQ schema starts the XOR-encoded club name after the 42-byte fixed header.
      const name = payload + 44;
      const isStars = size >= 49 && payload + size <= bytes.length &&
        view.getUint16(payload + 42, true) === 5 &&
        String.fromCharCode(...bytes.subarray(name, name + 5).map(byte => byte ^ 0x61)).toLowerCase() === 'stars';
      if (id === 9900) stars = { offset, isStars };
      else target = { isStars };
    }
    offset = directory + 8;
  }
  if (!stars && target?.isStars) return;
  if (!stars?.isStars) throw new Error('Club ID 9900 is not a Stars record. Untick the fix to build this season as supplied.');
  if (target) throw new Error('Club ID 9899 is already in use. Untick the Stars fix to build this season as supplied.');
  view.setUint32(stars.offset, 9899, true);
}
