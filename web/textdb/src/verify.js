// Checks the user's chosen files against the manifest.
// Pure logic plus Web Crypto. Nothing here touches the network.

import { MANIFEST, captureEntries } from './manifest.js';

/** SHA-256 of an ArrayBuffer or typed array, as lowercase hex. */
export async function sha256Hex(data, subtle = globalThis.crypto.subtle) {
  const digest = await subtle.digest('SHA-256', data);
  let out = '';
  for (const b of new Uint8Array(digest)) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Base name of a path that may use / or \ separators. */
export function baseName(path) {
  return String(path).split(/[\\/]/).pop();
}

/**
 * Pick the captured files out of any list of File-like objects (anything with
 * `name`). Returns a Map from manifest id to the file. Matching is
 * case-insensitive on the base name; the first file found wins; other files
 * are ignored and never read.
 */
export function pickWanted(files, manifest = MANIFEST) {
  const wanted = new Map();
  const byUpper = new Map();
  for (const e of captureEntries(manifest)) byUpper.set(baseName(e.path).toUpperCase(), e.id);
  for (const file of files) {
    const id = byUpper.get(baseName(file.name).toUpperCase());
    if (id && !wanted.has(id)) wanted.set(id, file);
  }
  return wanted;
}

/**
 * Read a File-like object in one go and hash it. Web Crypto has no incremental
 * digest, so the whole file is held in memory exactly once (a single
 * arrayBuffer, no chunk list that would double it). Callers should check the
 * size against the manifest first (see checkFiles) so an oversize file is never
 * read. `onProgress(bytesRead, totalBytes)` is called once the read is done.
 */
export async function hashFile(file, { onProgress, subtle } = {}) {
  const total = file.size ?? 0;
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (onProgress) onProgress(bytes.byteLength, total || bytes.byteLength);
  return sha256Hex(bytes, subtle);
}

/**
 * Compare every captured entry in the manifest with what the user chose.
 * `hash(file, onProgress)` is injectable for tests. Files are hashed one at a
 * time, in manifest order.
 *
 * Each row: { id, path, role, required, expected, actual, status }
 * status:
 *   'match'         present and identical to the stock file
 *   'wrong-hash'    present but different (other edition, patched or damaged)
 *   'missing'       required and not chosen
 *   'not-provided'  optional and not chosen (fine)
 */
export async function checkFiles(
  picked,
  { manifest = MANIFEST, hash = hashFile, onFile = () => {}, onBytes = () => {} } = {},
) {
  const entries = captureEntries(manifest);
  const rows = [];
  for (const [i, e] of entries.entries()) {
    const file = picked.get(e.id);
    const row = {
      id: e.id,
      path: e.path,
      role: e.role,
      required: e.required,
      expected: e.sha256,
      actual: null,
      status: null,
      reason: null,
    };
    if (!file) {
      row.status = e.required ? 'missing' : 'not-provided';
    } else {
      if (typeof e.size === 'number' && typeof file.size === 'number' && file.size !== e.size) {
        row.status = 'wrong-size';
        row.reason = `wrong size: ${file.size} bytes, expected ${e.size} bytes`;
        rows.push(row);
        continue;
      }
      onFile({ index: i, count: entries.length, path: e.path, file });
      row.actual = await hash(file, {
        onProgress: (read, total) => onBytes({ path: e.path, read, total }),
      });
      row.status = row.actual === e.sha256 ? 'match' : 'wrong-hash';
      if (row.status === 'wrong-hash') row.reason = 'checksum differs from the English retail file';
    }
    rows.push(row);
  }
  return rows;
}

/**
 * Summarise the rows for the page.
 *   capturedOk / capturedTotal   the "n of m captured" count (required and optional)
 *   requiredOk / requiredTotal   required files present and identical
 *   canBuild                     true only when every required file matches AND no
 *                                chosen file is a wrong hash
 */
export function summarise(rows) {
  const requiredTotal = rows.filter((r) => r.required).length;
  const requiredOk = rows.filter((r) => r.required && r.status === 'match').length;
  const capturedOk = rows.filter((r) => r.status === 'match').length;
  const wrong = rows.filter((r) => r.status === 'wrong-hash' || r.status === 'wrong-size');
  const missing = rows.filter((r) => r.status === 'missing');
  const anyChosen = rows.some((r) => r.status !== 'missing' && r.status !== 'not-provided');
  return {
    capturedOk,
    capturedTotal: rows.length,
    requiredOk,
    requiredTotal,
    wrong,
    missing,
    canBuild: requiredOk === requiredTotal && wrong.length === 0,
    anyChosen,
  };
}

/**
 * One verdict for the page, in plain English.
 *   state 'nothing'     no captured file chosen yet
 *   state 'unsupported' a chosen file differs from stock: refuse
 *   state 'incomplete'  some required files are missing
 *   state 'supported'   every required file present and identical
 */
export function verdictFor(summary) {
  if (!summary.anyChosen) {
    return {
      state: 'nothing',
      title: 'No game files chosen yet',
      message: 'Choose your game folder, or drag it onto the box above.',
    };
  }
  if (summary.wrong.length > 0) {
    const names = summary.wrong.map((r) => r.path).join(', ');
    return {
      state: 'unsupported',
      title: 'This edition is not supported',
      details: summary.wrong.map((r) => `${r.path}: ${r.reason || 'does not match'}`),
      message:
        `${summary.wrong.length === 1 ? 'The file' : 'The files'} ${names} ${summary.wrong.length === 1 ? 'is' : 'are'} not the same as the English retail edition of ` +
        'Premier Manager 99 that this tool supports. Other editions, other ' +
        'languages, patched or damaged files are refused. Check that you chose ' +
        'the original game folder.',
    };
  }
  if (summary.missing.length > 0) {
    const names = summary.missing.map((r) => r.path).join(', ');
    return {
      state: 'incomplete',
      title: 'Some files are missing',
      message: `Still needed: ${names}. Choose the whole game folder, or add these files.`,
    };
  }
  return {
    state: 'supported',
    title: 'English retail edition recognised',
    message: 'All required files match the stock English retail edition.',
  };
}
