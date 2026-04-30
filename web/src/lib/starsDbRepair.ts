export interface StarsPayloadRepair {
  slotNumber: number;
  playerRecordId: number;
  oldPayloadLength: number;
  newPayloadLength: number;
  changed: boolean;
  appendedDecodedHex: string;
}

export interface StarsTeamRecordRepair {
  oldEqRecordId: number;
  newEqRecordId: number;
  changed: boolean;
  reason: string;
}

export interface StarsDatabaseRepairReport {
  patchName: 'stars-db-repair-poc';
  inputTeamFile: string;
  inputPlayerFile: string;
  outputTeamFile: string;
  outputPlayerFile: string;
  dryRun: boolean;
  ok: boolean;
  teamName: string;
  fullClubName: string;
  eqRecordIdBefore: number;
  eqRecordIdAfter: number;
  slotCount: number;
  linkedPlayerIds: number[];
  changedPayloadCount: number;
  totalSizeDelta: number;
  teamRecordRepair: StarsTeamRecordRepair;
  payloadRepairs: StarsPayloadRepair[];
  warnings: string[];
  sha256: {
    inputTeamFile: string;
    outputTeamFile: string;
    inputPlayerFile: string;
    outputPlayerFile: string;
  };
  notes: string[];
}

export interface StarsDatabaseRepairResult {
  outputTeamBytes: Uint8Array<ArrayBufferLike>;
  outputPlayerBytes: Uint8Array<ArrayBufferLike>;
  report: StarsDatabaseRepairReport;
}

interface IndexedEntry {
  recordId: number;
  key: string;
  payloadOffset: number;
  payloadLength: number;
  indexOffset: number;
}

interface IndexedFdi {
  entries: IndexedEntry[];
  indexEndOffset: number;
}

interface StarsRosterRow {
  slotIndex: number;
  flag: number;
  playerRecordId: number;
  rawRowOffset: number;
}

interface StarsRoster {
  eqRecordId: number;
  shortName: string;
  stadiumName: string;
  fullClubName: string;
  recordSize: number;
  modeByte: number;
  entCount: number;
  payloadOffset: number;
  payloadLength: number;
  rows: StarsRosterRow[];
}

const FDI_SIGNATURE = asciiBytes('DMFIv1.0');
const FDI_INDEX_START = 0x14;
const XOR_KEY = 0x61;
const EXTERNAL_LINK_JUMP = 0x6e7;
const MIN_EXTERNAL_LINK_RECORD_SIZE = 600;
const STARS_TEAM_NAME = 'Stars';
const STARS_BROKEN_EQ_RECORD_ID = 0x26ac;
const STARS_SAFE_EQ_RECORD_ID = 9899;
const MIN_STARS_PLAYER_PAYLOAD_LENGTH = 80;

function asciiBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function bytesHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function readU32LE(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
}

function readU16LE(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset, true);
}

function writeU32LE(bytes: Uint8Array, offset: number, value: number): void {
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(offset, value >>> 0, true);
}

function xorBytes(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) {
    out[i] = bytes[i] ^ XOR_KEY;
  }
  return out;
}

function readCp1252(bytes: Uint8Array): string {
  return new TextDecoder('windows-1252').decode(bytes);
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const normalized = new Uint8Array(data.byteLength);
  normalized.set(data);
  const digest = await crypto.subtle.digest('SHA-256', normalized.buffer);
  return bytesHex(new Uint8Array(digest));
}

function parseIndexedFdi(data: Uint8Array): IndexedFdi {
  if (data.length < FDI_INDEX_START) {
    throw new Error('File too small for indexed FDI header');
  }
  if (!equalBytes(data.slice(0, 8), FDI_SIGNATURE)) {
    throw new Error(`Invalid indexed FDI signature: ${readCp1252(data.slice(0, 8))}`);
  }

  const recordCount = readU32LE(data, 0x10);
  const entries: IndexedEntry[] = [];
  let pos = FDI_INDEX_START;
  for (let i = 0; i < recordCount; i += 1) {
    const indexOffset = pos;
    if (pos + 9 > data.length) {
      throw new Error(`Truncated indexed FDI directory entry at 0x${pos.toString(16)}`);
    }

    const recordId = readU32LE(data, pos);
    pos += 4;
    const keyLength = data[pos];
    pos += 1;
    if (pos + keyLength + 8 > data.length) {
      throw new Error(`Indexed FDI entry 0x${indexOffset.toString(16)} overruns file`);
    }

    const key = readCp1252(data.slice(pos, pos + keyLength));
    pos += keyLength;
    const payloadOffset = readU32LE(data, pos);
    pos += 4;
    const payloadLength = readU32LE(data, pos);
    pos += 4;

    if (payloadOffset + payloadLength > data.length) {
      throw new Error(`Indexed payload for record ${recordId} points outside file`);
    }

    entries.push({ recordId, key, payloadOffset, payloadLength, indexOffset });
  }

  return { entries, indexEndOffset: pos };
}

function decodeIndexedPayload(fileBytes: Uint8Array, entry: IndexedEntry): Uint8Array {
  return xorBytes(fileBytes.slice(entry.payloadOffset, entry.payloadOffset + entry.payloadLength));
}

function readXorU16String(rawPayload: Uint8Array, cursor: number): [string, number] {
  if (cursor + 2 > rawPayload.length) {
    throw new Error('truncated string length');
  }
  const size = readU16LE(rawPayload, cursor);
  const start = cursor + 2;
  const end = start + size;
  if (end > rawPayload.length) {
    throw new Error('truncated string payload');
  }
  return [readCp1252(xorBytes(rawPayload.slice(start, end))).replace(/\0+$/u, ''), end];
}

function advanceLegacyModeZeroCursor(rawPayload: Uint8Array, cursor: number, recordSize: number): number {
  if (recordSize > 0x207) {
    cursor += 2;
  }
  cursor += 4;
  [, cursor] = readXorU16String(rawPayload, cursor);
  cursor += 4;
  cursor += 4;
  [, cursor] = readXorU16String(rawPayload, cursor);
  [, cursor] = readXorU16String(rawPayload, cursor);
  cursor += 3;
  cursor += recordSize >= 0x1f9 ? 20 : 10;
  cursor += 15;
  cursor += recordSize >= 0x1f9 ? 46 : 42;
  if (recordSize < 700) {
    const pairCount = recordSize < 0x1f9 ? 7 : recordSize < 0x203 ? 17 : 21;
    cursor += pairCount * 2;
  } else {
    if (cursor >= rawPayload.length) {
      throw new Error('truncated legacy sparse-count byte');
    }
    const sparseCount = rawPayload[cursor];
    cursor += 1 + sparseCount * 3;
  }
  if (cursor > rawPayload.length) {
    throw new Error('legacy mode-0 block overruns payload');
  }
  return cursor;
}

function parseEqExternalTeamRosterPayload(rawPayload: Uint8Array): Omit<StarsRoster, 'eqRecordId' | 'payloadOffset' | 'payloadLength'> | null {
  if (rawPayload.length < 0x2a) {
    return null;
  }

  const recordSize = readU16LE(rawPayload, 0x26);
  const modeByte = rawPayload[0x29];
  if (recordSize < MIN_EXTERNAL_LINK_RECORD_SIZE) {
    return null;
  }

  let cursor = 0x2a;
  let shortName = '';
  let stadiumName = '';
  let fullClubName = '';
  try {
    [shortName, cursor] = readXorU16String(rawPayload, cursor);
    [stadiumName, cursor] = readXorU16String(rawPayload, cursor);
    cursor += 1;
    if (recordSize > 0x20c) {
      cursor += 1;
    }
    [fullClubName, cursor] = readXorU16String(rawPayload, cursor);
  } catch {
    return null;
  }

  cursor += 4;
  if (recordSize >= 0x1fe) {
    cursor += 4;
  }
  cursor += 2 + 2 + 2;

  let linkBase = cursor;
  if (modeByte === 0) {
    try {
      linkBase = advanceLegacyModeZeroCursor(rawPayload, cursor, recordSize);
    } catch {
      return null;
    }
  }

  const entCursor = linkBase + EXTERNAL_LINK_JUMP;
  if (entCursor >= rawPayload.length) {
    return null;
  }

  const entCount = rawPayload[entCursor];
  let playerCursor = entCursor + 1 + entCount * 4;
  if (playerCursor >= rawPayload.length) {
    return null;
  }

  const playerCount = rawPayload[playerCursor];
  playerCursor += 1;
  const rows: StarsRosterRow[] = [];
  for (let slotIndex = 0; slotIndex < playerCount; slotIndex += 1) {
    if (playerCursor + 5 > rawPayload.length) {
      return null;
    }
    rows.push({
      slotIndex,
      flag: rawPayload[playerCursor],
      playerRecordId: readU32LE(rawPayload, playerCursor + 1),
      rawRowOffset: playerCursor,
    });
    playerCursor += 5;
  }

  return { shortName, stadiumName, fullClubName, recordSize, modeByte, entCount, rows };
}

function selectStarsRoster(teamBytes: Uint8Array): { roster: StarsRoster; indexed: IndexedFdi } {
  const indexed = parseIndexedFdi(teamBytes);
  const matches: StarsRoster[] = [];

  for (const entry of indexed.entries) {
    const rawPayload = teamBytes.slice(entry.payloadOffset, entry.payloadOffset + entry.payloadLength);
    const parsed = parseEqExternalTeamRosterPayload(rawPayload);
    if (!parsed) {
      continue;
    }
    const short = parsed.shortName.trim().toLowerCase();
    const full = parsed.fullClubName.trim().toLowerCase();
    if (short === STARS_TEAM_NAME.toLowerCase() || full === STARS_TEAM_NAME.toLowerCase()) {
      matches.push({
        ...parsed,
        eqRecordId: entry.recordId,
        payloadOffset: entry.payloadOffset,
        payloadLength: entry.payloadLength,
      });
    }
  }

  if (matches.length === 0) {
    throw new Error('Could not find linked Stars roster in EQ file');
  }
  if (matches.length > 1) {
    throw new Error(`Multiple linked Stars rosters found in EQ file: ${matches.map((item) => item.eqRecordId).join(', ')}`);
  }

  return { roster: matches[0], indexed };
}

function rewriteIndexedRecordId(fileBytes: Uint8Array, indexed: IndexedFdi, oldRecordId: number, newRecordId: number): Uint8Array {
  if (oldRecordId === newRecordId) {
    return new Uint8Array(fileBytes);
  }

  const oldEntry = indexed.entries.find((entry) => entry.recordId === oldRecordId);
  if (!oldEntry) {
    throw new Error(`Indexed record id ${oldRecordId} not found`);
  }
  if (indexed.entries.some((entry) => entry.recordId === newRecordId)) {
    throw new Error(`Cannot rewrite record ${oldRecordId} to ${newRecordId}: target id already exists`);
  }

  const patched = new Uint8Array(fileBytes);
  writeU32LE(patched, oldEntry.indexOffset, newRecordId);
  const reparsed = parseIndexedFdi(patched);
  if (!reparsed.entries.some((entry) => entry.recordId === newRecordId)) {
    throw new Error(`Indexed record id rewrite to ${newRecordId} did not reparse`);
  }
  return patched;
}

function rewriteIndexedPayloads(
  fileBytes: Uint8Array,
  indexed: IndexedFdi,
  decodedPayloadByRecordId: Map<number, Uint8Array>,
): Uint8Array {
  if (decodedPayloadByRecordId.size === 0) {
    return new Uint8Array(fileBytes);
  }

  const entryByRecordId = new Map(indexed.entries.map((entry) => [entry.recordId, entry]));
  for (const recordId of decodedPayloadByRecordId.keys()) {
    if (!entryByRecordId.has(recordId)) {
      throw new Error(`Indexed payload id not found: ${recordId}`);
    }
  }

  const orderedEntries = [...indexed.entries].sort((a, b) => a.payloadOffset - b.payloadOffset);
  const firstPayloadOffset = orderedEntries[0]?.payloadOffset ?? 0;
  if (firstPayloadOffset <= 0 || firstPayloadOffset > fileBytes.length) {
    throw new Error('Indexed payload region starts outside file bounds');
  }

  const encodedPayloadByOldOffset = new Map<number, Uint8Array>();
  for (const entry of orderedEntries) {
    const oldEnd = entry.payloadOffset + entry.payloadLength;
    const decoded = decodedPayloadByRecordId.get(entry.recordId);
    encodedPayloadByOldOffset.set(
      entry.payloadOffset,
      decoded ? xorBytes(decoded) : fileBytes.slice(entry.payloadOffset, oldEnd),
    );
  }

  const parts: Uint8Array[] = [fileBytes.slice(0, firstPayloadOffset)];
  const newOffsetsByOldOffset = new Map<number, number>();
  const newLengthsByOldOffset = new Map<number, number>();
  let rebuiltLength = firstPayloadOffset;
  for (let index = 0; index < orderedEntries.length; index += 1) {
    const entry = orderedEntries[index];
    const oldEnd = entry.payloadOffset + entry.payloadLength;
    const encodedPayload = encodedPayloadByOldOffset.get(entry.payloadOffset);
    if (!encodedPayload) {
      throw new Error(`Internal payload map miss for 0x${entry.payloadOffset.toString(16)}`);
    }

    newOffsetsByOldOffset.set(entry.payloadOffset, rebuiltLength);
    newLengthsByOldOffset.set(entry.payloadOffset, encodedPayload.length);
    parts.push(encodedPayload);
    rebuiltLength += encodedPayload.length;

    const nextEntry = orderedEntries[index + 1];
    const gap = nextEntry ? fileBytes.slice(oldEnd, nextEntry.payloadOffset) : fileBytes.slice(oldEnd);
    if (nextEntry && nextEntry.payloadOffset < oldEnd) {
      throw new Error(`Indexed payload overlap detected between 0x${entry.payloadOffset.toString(16)} and 0x${nextEntry.payloadOffset.toString(16)}`);
    }
    parts.push(gap);
    rebuiltLength += gap.length;
  }

  const rebuilt = concatBytes(...parts);
  for (const entry of indexed.entries) {
    const keyLength = rebuilt[entry.indexOffset + 4];
    const payloadOffsetPos = entry.indexOffset + 5 + keyLength;
    const payloadLengthPos = payloadOffsetPos + 4;
    writeU32LE(rebuilt, payloadOffsetPos, newOffsetsByOldOffset.get(entry.payloadOffset) ?? entry.payloadOffset);
    writeU32LE(rebuilt, payloadLengthPos, newLengthsByOldOffset.get(entry.payloadOffset) ?? entry.payloadLength);
  }

  const reparsed = parseIndexedFdi(rebuilt);
  if (reparsed.entries.length !== indexed.entries.length) {
    throw new Error(`Indexed record count changed after rewrite (${indexed.entries.length} -> ${reparsed.entries.length})`);
  }
  return rebuilt;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.length;
  }
  return out;
}

export async function repairStarsDatabase(
  teamBytes: Uint8Array,
  playerBytes: Uint8Array,
  options: {
    dryRun: boolean;
    inputTeamFileName: string;
    inputPlayerFileName: string;
    outputTeamFileName?: string;
    outputPlayerFileName?: string;
  },
): Promise<StarsDatabaseRepairResult> {
  const inputTeam = new Uint8Array(teamBytes);
  const inputPlayer = new Uint8Array(playerBytes);
  const { roster, indexed: teamIndexed } = selectStarsRoster(inputTeam);
  const playerIndexed = parseIndexedFdi(inputPlayer);

  let outputTeam: Uint8Array<ArrayBufferLike> = new Uint8Array(inputTeam);
  const teamRecordRepair: StarsTeamRecordRepair =
    roster.eqRecordId === STARS_BROKEN_EQ_RECORD_ID
      ? {
          oldEqRecordId: roster.eqRecordId,
          newEqRecordId: STARS_SAFE_EQ_RECORD_ID,
          changed: true,
          reason: 'moved_stars_off_runtime_special_0x26ac',
        }
      : {
          oldEqRecordId: roster.eqRecordId,
          newEqRecordId: roster.eqRecordId,
          changed: false,
          reason: 'already_safe_record_id',
        };

  if (teamRecordRepair.changed) {
    outputTeam = rewriteIndexedRecordId(inputTeam, teamIndexed, STARS_BROKEN_EQ_RECORD_ID, STARS_SAFE_EQ_RECORD_ID);
  }

  const playerEntryById = new Map(playerIndexed.entries.map((entry) => [entry.recordId, entry]));
  const patchedPayloadById = new Map<number, Uint8Array>();
  const payloadRepairs: StarsPayloadRepair[] = [];
  const warnings: string[] = [];

  for (const row of roster.rows) {
    const entry = playerEntryById.get(row.playerRecordId);
    if (!entry) {
      warnings.push(`Stars slot ${row.slotIndex + 1} player id ${row.playerRecordId} is missing from JUG file`);
      continue;
    }

    const oldPayloadLength = entry.payloadLength;
    const decoded = decodeIndexedPayload(inputPlayer, entry);
    const changed = oldPayloadLength < MIN_STARS_PLAYER_PAYLOAD_LENGTH;
    let nextDecoded = decoded;
    let appended = new Uint8Array();
    if (changed) {
      const filler = decoded.length ? decoded[decoded.length - 1] : 0x00;
      appended = new Uint8Array(MIN_STARS_PLAYER_PAYLOAD_LENGTH - oldPayloadLength).fill(filler);
      nextDecoded = concatBytes(decoded, appended);
      patchedPayloadById.set(row.playerRecordId, nextDecoded);
    }

    payloadRepairs.push({
      slotNumber: row.slotIndex + 1,
      playerRecordId: row.playerRecordId,
      oldPayloadLength,
      newPayloadLength: changed ? MIN_STARS_PLAYER_PAYLOAD_LENGTH : oldPayloadLength,
      changed,
      appendedDecodedHex: bytesHex(appended),
    });
  }

  const outputPlayer = rewriteIndexedPayloads(inputPlayer, playerIndexed, patchedPayloadById);
  const linkedPlayerIds = roster.rows.map((row) => row.playerRecordId);
  const report: StarsDatabaseRepairReport = {
    patchName: 'stars-db-repair-poc',
    inputTeamFile: options.inputTeamFileName,
    inputPlayerFile: options.inputPlayerFileName,
    outputTeamFile: options.outputTeamFileName ?? 'EQ98030.skezmod.FDI',
    outputPlayerFile: options.outputPlayerFileName ?? 'JUG98030.skezmod.FDI',
    dryRun: options.dryRun,
    ok: warnings.length === 0,
    teamName: roster.shortName,
    fullClubName: roster.fullClubName,
    eqRecordIdBefore: roster.eqRecordId,
    eqRecordIdAfter: teamRecordRepair.newEqRecordId,
    slotCount: roster.rows.length,
    linkedPlayerIds,
    changedPayloadCount: patchedPayloadById.size,
    totalSizeDelta: payloadRepairs.reduce((sum, item) => sum + Math.max(0, item.newPayloadLength - item.oldPayloadLength), 0),
    teamRecordRepair,
    payloadRepairs,
    warnings,
    sha256: {
      inputTeamFile: await sha256Hex(inputTeam),
      outputTeamFile: await sha256Hex(outputTeam),
      inputPlayerFile: await sha256Hex(inputPlayer),
      outputPlayerFile: await sha256Hex(outputPlayer),
    },
    notes: [
      'POC browser DB repair: moves Stars EQ indexed record id 9900/0x26AC to 9899 when present.',
      'Pads short linked Stars JUG player payloads to 80 bytes using the existing trailing decoded filler byte.',
      'This DB repair does not patch MANAGPRE.EXE; it is intended to run alongside the existing EXE null guard patch.',
    ],
  };

  return { outputTeamBytes: outputTeam, outputPlayerBytes: outputPlayer, report };
}

export const starsDbRepairTestInternals = {
  parseIndexedFdi,
  readXorU16String,
};
