const MAX_PACKAGE_BYTES = 64 * 1024 * 1024;
const MAX_FILES = 1024;
const SAFE_NAME = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;

export function pickPackage(files) {
  const entries = [];
  const paths = new Set();
  let size = 0;
  for (const file of files) {
    // webkitRelativePath includes the name of the selected folder.
    const path = file.webkitRelativePath.slice(file.webkitRelativePath.indexOf('/') + 1);
    if (path !== 'textdb.ini' && !path.startsWith('TEXTDB/')) continue;
    if (path.startsWith('TEXTDB/cache/') || !/\.(ini|tsv|json|pmc)$/.test(path)) continue;
    if (path.length > 220 || !path.split('/').every((part) => SAFE_NAME.test(part))) {
      throw new Error(
        `Invalid package path "${path}": every name must start with a letter or digit and use only ` +
          'A-Z a-z 0-9 . _ - (no spaces or other characters), and the whole path must be at most 220 characters. ' +
          'Rename or remove that file and choose the folder again.',
      );
    }
    const key = path.toLowerCase();
    if (paths.has(key)) throw new Error(`Duplicate package path: ${path}`);
    paths.add(key);
    size += file.size;
    if (entries.length >= MAX_FILES || size > MAX_PACKAGE_BYTES) {
      throw new Error('The package exceeds 1,024 files or 64 MiB.');
    }
    entries.push({ path, file });
  }
  if (!paths.has('textdb.ini') || !entries.some(({ path }) => path.startsWith('TEXTDB/'))) {
    throw new Error('Choose the extracted package folder that contains textdb.ini and TEXTDB.');
  }
  return entries;
}

const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, n) => {
  for (let bit = 0; bit < 8; bit++) n = (n >>> 1) ^ (n & 1 ? 0xedb88320 : 0);
  return n;
});

export function crc32(bytes) {
  const table = CRC_TABLE;
  let crc = 0xffffffff;
  for (let i = 0, n = bytes.length; i < n; i++) crc = (crc >>> 8) ^ table[(crc ^ bytes[i]) & 255];
  return (crc ^ 0xffffffff) >>> 0;
}

// ZIP32, stored entries. Only files created by the C core are archived.
export function makePackage(entries) {
  if (entries.length > MAX_FILES) throw new Error('Too many output files.');
  const encoder = new TextEncoder();
  const local = [];
  const directory = [];
  let offset = 0;
  let directorySize = 0;
  for (const { path, bytes } of entries) {
    const name = encoder.encode(path);
    const checksum = crc32(bytes);
    const header = new DataView(new ArrayBuffer(30));
    header.setUint32(0, 0x04034b50, true);
    header.setUint16(4, 20, true);
    writeEntry(header, 6, 10, 14, name.length, bytes.length, checksum);
    const record = new DataView(new ArrayBuffer(46));
    record.setUint32(0, 0x02014b50, true);
    record.setUint16(4, 20, true);
    record.setUint16(6, 20, true);
    writeEntry(record, 8, 12, 16, name.length, bytes.length, checksum);
    record.setUint32(42, offset, true);
    local.push(header.buffer, name, bytes);
    directory.push(record.buffer, name);
    offset += 30 + name.length + bytes.length;
    directorySize += 46 + name.length;
    if (offset + directorySize > MAX_PACKAGE_BYTES) throw new Error('The ZIP exceeds 64 MiB.');
  }
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, entries.length, true);
  end.setUint16(10, entries.length, true);
  end.setUint32(12, directorySize, true);
  end.setUint32(16, offset, true);
  return new Blob([...local, ...directory, end.buffer], { type: 'application/zip' });
}

function writeEntry(view, flags, time, crc, nameLength, size, checksum) {
  view.setUint16(flags, 0x0800, true); // UTF-8 names
  view.setUint16(time + 2, 0x0021, true); // 1980-01-01
  view.setUint32(crc, checksum, true);
  view.setUint32(crc + 4, size, true);
  view.setUint32(crc + 8, size, true);
  view.setUint16(crc + 12, nameLength, true);
}
