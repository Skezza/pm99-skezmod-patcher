const NAMES = new Map([
  ['ddraw.dll', 'ddraw.dll'],
  ['ddraw.ini', 'ddraw.ini'],
  ['dgvoodoo.conf', 'dgVoodoo.conf'],
]);

export function pickRenderingFiles(files) {
  const entries = new Map();
  for (const file of files) {
    const path = NAMES.get(file.name.toLowerCase());
    const max = path === 'ddraw.dll' ? 16 * 1024 * 1024 : 256 * 1024;
    if (!path || !file.size || file.size > max || entries.has(path)) {
      throw new Error('Choose one ddraw.dll and at most one copy of each supported configuration file.');
    }
    entries.set(path, { path, file });
  }
  if (entries.size && !entries.has('ddraw.dll')) throw new Error('Choose ddraw.dll with its configuration.');
  return [...entries.values()];
}

export async function collectRenderingFiles(entries) {
  const files = [];
  for (const { path, file } of pickRenderingFiles(entries.map(entry => entry.file))) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (path === 'ddraw.dll') {
      const view = new DataView(bytes.buffer);
      const pe = bytes.length >= 64 ? view.getUint32(60, true) : bytes.length;
      if (pe < 64 || pe > bytes.length - 26 || view.getUint16(0, true) !== 0x5a4d ||
          view.getUint32(pe, true) !== 0x4550 || view.getUint16(pe + 4, true) !== 0x14c ||
          !(view.getUint16(pe + 22, true) & 0x2000) || view.getUint16(pe + 24, true) !== 0x10b) {
        throw new Error('The rendering fix needs a 32-bit Windows ddraw.dll.');
      }
    }
    files.push({ path, bytes });
  }
  return files;
}
