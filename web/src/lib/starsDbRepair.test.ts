import { describe, expect, it } from 'vitest';
import { repairStarsDatabase } from './starsDbRepair';

const XOR_KEY = 0x61;
const STARS_BROKEN_EQ_RECORD_ID = 0x26ac;
const STARS_SAFE_EQ_RECORD_ID = 9899;

Object.defineProperty(globalThis, 'crypto', {
  value: {
    subtle: {
      digest: async () => new ArrayBuffer(32),
    },
  },
});

function xorBytes(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) {
    out[i] = bytes[i] ^ XOR_KEY;
  }
  return out;
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

function packU32LE(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, true);
  return out;
}

function packU16LE(value: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, true);
  return out;
}

function readU32LE(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
}

function encodeXorU16String(text: string): Uint8Array {
  const raw = new TextEncoder().encode(text);
  return concatBytes(packU16LE(raw.length), xorBytes(raw));
}

function buildIndexedFdi(records: Array<[number, string, Uint8Array]>, encodePayloads: boolean): Uint8Array {
  const header = concatBytes(
    new TextEncoder().encode('DMFIv1.0'),
    packU32LE(0),
    packU32LE(0),
    packU32LE(records.length),
  );

  let payloadOffset = header.length;
  const encodedPayloads: Uint8Array[] = [];
  for (const [, key, payload] of records) {
    const keyBytes = new TextEncoder().encode(key);
    payloadOffset += 4 + 1 + keyBytes.length + 4 + 4;
    encodedPayloads.push(encodePayloads ? xorBytes(payload) : payload);
  }

  const indexParts: Uint8Array[] = [];
  let runningOffset = payloadOffset;
  for (let index = 0; index < records.length; index += 1) {
    const [recordId, key] = records[index];
    const keyBytes = new TextEncoder().encode(key);
    const encodedPayload = encodedPayloads[index];
    indexParts.push(packU32LE(recordId), new Uint8Array([keyBytes.length]), keyBytes, packU32LE(runningOffset), packU32LE(encodedPayload.length));
    runningOffset += encodedPayload.length;
  }

  return concatBytes(header, ...indexParts, ...encodedPayloads);
}

function buildExternalEqPayload(playerIds: number[]): Uint8Array {
  const payload = new Uint8Array(0x800);
  new DataView(payload.buffer).setUint16(0x26, 700, true);
  payload[0x29] = 1;

  let cursor = 0x2a;
  for (const text of ['Stars', 'Stars Ground']) {
    const part = encodeXorU16String(text);
    payload.set(part, cursor);
    cursor += part.length;
  }

  cursor += 1;
  cursor += 1;
  const full = encodeXorU16String('Stars');
  payload.set(full, cursor);
  cursor += full.length;

  cursor += 4;
  cursor += 4;
  cursor += 2 + 2 + 2;

  const linkBase = cursor + 0x6e7;
  payload[linkBase] = 0;
  let playerCursor = linkBase + 1;
  payload[playerCursor] = playerIds.length;
  playerCursor += 1;
  for (const playerId of playerIds) {
    payload[playerCursor] = 0;
    payload.set(packU32LE(playerId), playerCursor + 1);
    playerCursor += 5;
  }

  return payload.slice(0, playerCursor);
}

function firstRecordId(indexedFdi: Uint8Array): number {
  return readU32LE(indexedFdi, 0x14);
}

function firstPayloadLength(indexedFdi: Uint8Array): number {
  const keyLength = indexedFdi[0x14 + 4];
  return readU32LE(indexedFdi, 0x14 + 5 + keyLength + 4);
}

describe('Stars DB browser repair POC', () => {
  it('moves Stars EQ id and pads short linked JUG payloads', async () => {
    const teamBytes = buildIndexedFdi(
      [[STARS_BROKEN_EQ_RECORD_ID, '', buildExternalEqPayload([58, 20864])]],
      false,
    );
    const playerBytes = buildIndexedFdi(
      [
        [58, '', new Uint8Array(81).fill(0x41)],
        [20864, '', new Uint8Array(73).fill(0x42)],
      ],
      true,
    );

    const result = await repairStarsDatabase(teamBytes, playerBytes, {
      dryRun: false,
      inputTeamFileName: 'EQ98030.FDI',
      inputPlayerFileName: 'JUG98030.FDI',
    });

    expect(result.report.ok).toBe(true);
    expect(result.report.eqRecordIdBefore).toBe(STARS_BROKEN_EQ_RECORD_ID);
    expect(result.report.eqRecordIdAfter).toBe(STARS_SAFE_EQ_RECORD_ID);
    expect(result.report.linkedPlayerIds).toEqual([58, 20864]);
    expect(result.report.changedPayloadCount).toBe(1);
    expect(result.report.totalSizeDelta).toBe(7);
    expect(firstRecordId(result.outputTeamBytes)).toBe(STARS_SAFE_EQ_RECORD_ID);

    const secondIndexOffset = 0x14 + 4 + 1 + 0 + 4 + 4;
    const secondPayloadLength = readU32LE(result.outputPlayerBytes, secondIndexOffset + 4 + 1 + 0 + 4);
    expect(secondPayloadLength).toBe(80);
  });

  it('leaves already-safe Stars EQ id unchanged', async () => {
    const teamBytes = buildIndexedFdi([[STARS_SAFE_EQ_RECORD_ID, '', buildExternalEqPayload([20864])]], false);
    const playerBytes = buildIndexedFdi([[20864, '', new Uint8Array(80).fill(0x42)]], true);

    const result = await repairStarsDatabase(teamBytes, playerBytes, {
      dryRun: true,
      inputTeamFileName: 'EQ98030.FDI',
      inputPlayerFileName: 'JUG98030.FDI',
    });

    expect(result.report.teamRecordRepair.changed).toBe(false);
    expect(result.report.changedPayloadCount).toBe(0);
    expect(firstRecordId(result.outputTeamBytes)).toBe(STARS_SAFE_EQ_RECORD_ID);
    expect(firstPayloadLength(result.outputPlayerBytes)).toBe(80);
  });
});
