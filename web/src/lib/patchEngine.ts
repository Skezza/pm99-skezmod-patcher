export interface PatchRow {
  name: string;
  siteVa: string;
  siteFileOffset: string;
  siteBefore: string;
  siteAfter: string;
  bytesWritten?: number;
}

export interface PatchReport {
  patchName: 'skezmod';
  inputExe: string;
  outputExe: string;
  dryRun: boolean;
  patchCount: number;
  patches: PatchRow[];
  addresses: {
    bundleBase: string;
    bundleSize: number;
    lookupHelper: string;
    nullGuard: string;
    empty: string;
    stars: string;
    free: string;
    unknown: string;
  };
  sha256: {
    input: string;
    output: string;
  };
  notes: string[];
}

export interface CompatibilityResult {
  ok: boolean;
  variantLabel: string;
  reasons: string[];
  alreadyPatched: boolean;
}

export interface PatchResult {
  outputBytes: Uint8Array;
  report: PatchReport;
}

interface DirectPatch {
  name: string;
  siteVa: number;
  expected: Uint8Array;
  replacement: Uint8Array;
  alternates?: Uint8Array[];
}

interface BundleData {
  bundle: Uint8Array;
  stringAddrs: {
    empty: number;
    stars: number;
    free: number;
    unknown: number;
  };
}

interface SectionInfo {
  virtualAddress: number;
  virtualSize: number;
  rawPtr: number;
  rawSize: number;
}

type BaseVariant = 'vanilla' | 'nocd' | 'unknown';

const IMAGE_BASE = 0x400000;
const TEAM_ID_STARS = 4705;
const TEAM_ID_FREE_PLAYERS = 4706;
const TITLE_ORIGINAL = asciiBytes('PREMIER MANAGER 99\0');
const TITLE_BRANDING_TEXT = asciiBytes('PM99 SkezMod 0.1');
const TITLE_BRANDING = concatBytes(
  TITLE_BRANDING_TEXT,
  new Uint8Array(TITLE_ORIGINAL.length - TITLE_BRANDING_TEXT.length),
);

const CAVE_BUNDLE_BASE_VA = 0x006e5092;
const CAVE_BUNDLE_SIZE = 302;

const CAVE_EMPTY_STRING_VA = 0x006e5199;
const CAVE_STARS_STRING_VA = 0x006e519a;
const CAVE_FREE_STRING_VA = 0x006e51a0;
const CAVE_UNKNOWN_STRING_VA = 0x006e51ad;

const CAVE_NULL_GUARD_VA = 0x006e51c0;

// PM99 No-CD fingerprints from scripts/patch_pm99_nocd.py in the research repo.
const NOCD_FINGERPRINT_PATCHES = [
  { offset: 0x0080f6, original: hexBytes('8a442410'), patched: hexBytes('66b82e00') },
  { offset: 0x008119, original: hexBytes('7512'), patched: hexBytes('9090') },
  { offset: 0x32a97d, original: hexBytes('3a5c'), patched: hexBytes('5c00') },
] as const;

if (TITLE_BRANDING.length !== TITLE_ORIGINAL.length) {
  throw new Error('Branding bytes must preserve original string length');
}

function asciiBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hexBytes(hex: string): Uint8Array {
  const cleaned = hex.replace(/\s+/g, '').toLowerCase();
  if (cleaned.length % 2 !== 0) {
    throw new Error(`Invalid hex length: ${hex}`);
  }

  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
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
  const view = new DataView(out.buffer);
  view.setUint32(0, value >>> 0, true);
  return out;
}

function packI32LE(value: number): Uint8Array {
  if (value < -0x8000_0000 || value > 0x7fff_ffff) {
    throw new Error(`rel32 out of range: ${value}`);
  }
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setInt32(0, value, true);
  return out;
}

function sliceBytes(bytes: Uint8Array, offset: number, length: number): Uint8Array {
  return bytes.slice(offset, offset + length);
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

function anyMatch(candidate: Uint8Array, expected: Uint8Array[]): boolean {
  return expected.some((value) => equalBytes(candidate, value));
}

function readU32LE(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
}

function readU16LE(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset, true);
}

function readSections(peBytes: Uint8Array): SectionInfo[] {
  if (!equalBytes(sliceBytes(peBytes, 0, 2), asciiBytes('MZ'))) {
    throw new Error('Input is not an MZ executable');
  }

  const peOff = readU32LE(peBytes, 0x3c);
  if (!equalBytes(sliceBytes(peBytes, peOff, 4), asciiBytes('PE\0\0'))) {
    throw new Error('Input does not contain a valid PE header');
  }

  const sectionCount = readU16LE(peBytes, peOff + 6);
  const optSize = readU16LE(peBytes, peOff + 20);
  const sectionOff = peOff + 24 + optSize;

  const sections: SectionInfo[] = [];
  for (let i = 0; i < sectionCount; i += 1) {
    const off = sectionOff + i * 40;
    const virtualSize = readU32LE(peBytes, off + 8);
    const virtualAddress = readU32LE(peBytes, off + 12);
    const rawSize = readU32LE(peBytes, off + 16);
    const rawPtr = readU32LE(peBytes, off + 20);
    sections.push({ virtualAddress, virtualSize, rawPtr, rawSize });
  }

  return sections;
}

function vaToFileOffset(peBytes: Uint8Array, va: number): number {
  const rva = va - IMAGE_BASE;

  for (const sec of readSections(peBytes)) {
    const start = sec.virtualAddress;
    const size = Math.max(sec.virtualSize, sec.rawSize);
    const end = start + size;
    if (rva >= start && rva < end) {
      return sec.rawPtr + (rva - start);
    }
  }

  throw new Error(`VA 0x${va.toString(16).padStart(8, '0')} does not map to a file-backed section`);
}

function rel32(fromVa: number, instrLen: number, toVa: number): Uint8Array {
  const rel = toVa - (fromVa + instrLen);
  return packI32LE(rel);
}

export function buildTrampoline(srcVa: number, dstVa: number, totalLen: number): Uint8Array {
  if (totalLen < 5) {
    throw new Error('Trampoline region must be at least 5 bytes');
  }
  const rel = dstVa - (srcVa + 5);
  return concatBytes(new Uint8Array([0xe9]), packI32LE(rel), new Uint8Array(totalLen - 5).fill(0x90));
}

export function buildCall(srcVa: number, dstVa: number): Uint8Array {
  return concatBytes(new Uint8Array([0xe8]), rel32(srcVa, 5, dstVa));
}

function patchArray(out: number[], offset: number, patchBytes: Uint8Array): void {
  for (let i = 0; i < patchBytes.length; i += 1) {
    out[offset + i] = patchBytes[i];
  }
}

function buildNullTextGuardStub(caveVa: number, resumeVa: number, emptyTextVa: number): Uint8Array {
  const out: number[] = [];
  const push = (value: Uint8Array): void => value.forEach((b) => out.push(b));

  push(hexBytes('8b4c242033f68a472033d28be8'));
  push(hexBytes('85c9'));

  const jnzPos = out.length;
  push(hexBytes('0f85'));
  push(new Uint8Array(4));

  push(hexBytes('b9'));
  push(packU32LE(emptyTextVa));
  const continueVa = caveVa + out.length;

  push(hexBytes('8a01'));
  const jmpResumePos = out.length;
  push(hexBytes('e9'));
  push(new Uint8Array(4));

  patchArray(out, jnzPos + 2, rel32(caveVa + jnzPos, 6, continueVa));
  patchArray(out, jmpResumePos + 1, rel32(caveVa + jmpResumePos, 5, resumeVa));

  return uint8(out);
}

function buildLookupResultFallbackHelper(
  caveVa: number,
  epilogueVa: number,
  unknownRecVa: number,
  starsRecVa: number,
  freeRecVa: number,
): Uint8Array {
  const out: number[] = [];
  const push = (value: Uint8Array): void => value.forEach((b) => out.push(b));

  push(hexBytes('85c0'));
  const jzFallbackPos = out.length;
  push(hexBytes('0f84'));
  push(new Uint8Array(4));

  push(hexBytes('395810'));
  const jneFallbackPos = out.length;
  push(hexBytes('0f85'));
  push(new Uint8Array(4));

  push(hexBytes('8b5004'));
  push(hexBytes('85d2'));
  const jzFallback2Pos = out.length;
  push(hexBytes('0f84'));
  push(new Uint8Array(4));

  push(hexBytes('8a0a'));
  push(hexBytes('84c9'));
  const jzFallback3Pos = out.length;
  push(hexBytes('0f8e'));
  push(new Uint8Array(4));

  push(hexBytes('80f92e'));
  const jbeFallback4Pos = out.length;
  push(hexBytes('0f86'));
  push(new Uint8Array(4));

  const jmpEpilogueMatchPos = out.length;
  push(hexBytes('e9'));
  push(new Uint8Array(4));

  const fallbackVa = caveVa + out.length;
  push(hexBytes('85db'));
  const jeUnknownPos = out.length;
  push(hexBytes('0f84'));
  push(new Uint8Array(4));

  push(hexBytes('81fb'));
  push(packU32LE(TEAM_ID_STARS));
  const jeStarsPos = out.length;
  push(hexBytes('0f84'));
  push(new Uint8Array(4));

  push(hexBytes('81fb'));
  push(packU32LE(TEAM_ID_FREE_PLAYERS));
  const jeFreePos = out.length;
  push(hexBytes('0f84'));
  push(new Uint8Array(4));

  const jmpSetUnknownPos = out.length;
  push(hexBytes('e9'));
  push(new Uint8Array(4));

  const setUnknownVa = caveVa + out.length;
  push(hexBytes('b8'));
  push(packU32LE(unknownRecVa));
  const jmpEpilogueUnknownPos = out.length;
  push(hexBytes('e9'));
  push(new Uint8Array(4));

  const setStarsVa = caveVa + out.length;
  push(hexBytes('b8'));
  push(packU32LE(starsRecVa));
  const jmpEpilogueStarsPos = out.length;
  push(hexBytes('e9'));
  push(new Uint8Array(4));

  const setFreeVa = caveVa + out.length;
  push(hexBytes('b8'));
  push(packU32LE(freeRecVa));
  const jmpEpilogueFreePos = out.length;
  push(hexBytes('e9'));
  push(new Uint8Array(4));

  patchArray(out, jzFallbackPos + 2, rel32(caveVa + jzFallbackPos, 6, fallbackVa));
  patchArray(out, jneFallbackPos + 2, rel32(caveVa + jneFallbackPos, 6, fallbackVa));
  patchArray(out, jzFallback2Pos + 2, rel32(caveVa + jzFallback2Pos, 6, fallbackVa));
  patchArray(out, jzFallback3Pos + 2, rel32(caveVa + jzFallback3Pos, 6, fallbackVa));
  patchArray(out, jbeFallback4Pos + 2, rel32(caveVa + jbeFallback4Pos, 6, fallbackVa));

  patchArray(out, jmpEpilogueMatchPos + 1, rel32(caveVa + jmpEpilogueMatchPos, 5, epilogueVa));

  patchArray(out, jeUnknownPos + 2, rel32(caveVa + jeUnknownPos, 6, setUnknownVa));
  patchArray(out, jeStarsPos + 2, rel32(caveVa + jeStarsPos, 6, setStarsVa));
  patchArray(out, jeFreePos + 2, rel32(caveVa + jeFreePos, 6, setFreeVa));

  patchArray(out, jmpSetUnknownPos + 1, rel32(caveVa + jmpSetUnknownPos, 5, setUnknownVa));
  patchArray(out, jmpEpilogueUnknownPos + 1, rel32(caveVa + jmpEpilogueUnknownPos, 5, epilogueVa));
  patchArray(out, jmpEpilogueStarsPos + 1, rel32(caveVa + jmpEpilogueStarsPos, 5, epilogueVa));
  patchArray(out, jmpEpilogueFreePos + 1, rel32(caveVa + jmpEpilogueFreePos, 5, epilogueVa));

  return uint8(out);
}

function buildFakeTeamRecord(namePtrVa: number, teamId: number): Uint8Array {
  const rec = new Uint8Array(0x14);
  rec.set(packU32LE(namePtrVa), 0x04);
  rec.set(packU32LE(teamId), 0x10);
  return rec;
}

function buildBundle(): BundleData {
  const stringsBlob = hexBytes('005374617273004672656520706c617965727300556e6b6e6f776e20636c756200');
  const stringAddrs = {
    empty: CAVE_EMPTY_STRING_VA,
    stars: CAVE_STARS_STRING_VA,
    free: CAVE_FREE_STRING_VA,
    unknown: CAVE_UNKNOWN_STRING_VA,
  };

  const helperTmp = buildLookupResultFallbackHelper(CAVE_BUNDLE_BASE_VA, 0x004b5c7d, 0, 0, 0);
  const recBaseVa = CAVE_BUNDLE_BASE_VA + helperTmp.length;
  const unknownRecVa = recBaseVa;
  const starsRecVa = recBaseVa + 0x14;
  const freeRecVa = recBaseVa + 0x28;

  const helperReal = buildLookupResultFallbackHelper(
    CAVE_BUNDLE_BASE_VA,
    0x004b5c7d,
    unknownRecVa,
    starsRecVa,
    freeRecVa,
  );

  if (helperReal.length !== helperTmp.length) {
    throw new Error('Internal helper sizing mismatch');
  }

  const recUnknown = buildFakeTeamRecord(stringAddrs.unknown, 0);
  const recStars = buildFakeTeamRecord(stringAddrs.stars, TEAM_ID_STARS);
  const recFree = buildFakeTeamRecord(stringAddrs.free, TEAM_ID_FREE_PLAYERS);

  const prefix = concatBytes(helperReal, recUnknown, recStars, recFree);
  const prefixEndVa = CAVE_BUNDLE_BASE_VA + prefix.length;
  const padLen = CAVE_EMPTY_STRING_VA - prefixEndVa;
  if (padLen < 0) {
    throw new Error(
      `Bundle overflow before fixed strings: end=0x${prefixEndVa.toString(16)} > strings=0x${CAVE_EMPTY_STRING_VA.toString(16)}`,
    );
  }

  let bundle = concatBytes(prefix, new Uint8Array(padLen), stringsBlob);
  if (bundle.length > CAVE_BUNDLE_SIZE) {
    throw new Error(`Bundle too large (${bundle.length} > ${CAVE_BUNDLE_SIZE})`);
  }
  if (bundle.length < CAVE_BUNDLE_SIZE) {
    bundle = concatBytes(bundle, new Uint8Array(CAVE_BUNDLE_SIZE - bundle.length));
  }

  return {
    bundle,
    stringAddrs,
  };
}

function buildPatchPlan(lookupHelperVa: number, includeBranding: boolean): DirectPatch[] {
  const unpatchedLookupBytes = hexBytes('395810740233c0');

  const patches: DirectPatch[] = [
    {
      name: 'lookup_result_fallback_FUN_004B5C20',
      siteVa: 0x004b5c76,
      expected: unpatchedLookupBytes,
      replacement: buildTrampoline(0x004b5c76, lookupHelperVa, unpatchedLookupBytes.length),
    },
    {
      name: 'defense_in_depth_textptr_normalize_FUN_0066F1F0',
      siteVa: 0x0066f1fb,
      expected: hexBytes('8b4c242033f68a472033d28be88a01'),
      replacement: buildTrampoline(0x0066f1fb, CAVE_NULL_GUARD_VA, 15),
    },
  ];

  if (includeBranding) {
    patches.push(
      {
        name: 'brand_title_string_primary',
        siteVa: 0x006fc658,
        expected: TITLE_ORIGINAL,
        replacement: TITLE_BRANDING,
      },
      {
        name: 'brand_title_string_secondary',
        siteVa: 0x006fc670,
        expected: TITLE_ORIGINAL,
        replacement: TITLE_BRANDING,
      },
    );
  }

  return patches;
}

function uint8(values: number[]): Uint8Array {
  return Uint8Array.from(values);
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const normalized = new Uint8Array(data.byteLength);
  normalized.set(data);
  const digest = await crypto.subtle.digest('SHA-256', normalized.buffer);
  return bytesHex(new Uint8Array(digest));
}

function overwrite(target: Uint8Array, offset: number, data: Uint8Array): void {
  target.set(data, offset);
}

function detectBaseVariant(inputBytes: Uint8Array): BaseVariant {
  let originalMatches = 0;
  let patchedMatches = 0;

  for (const fingerprint of NOCD_FINGERPRINT_PATCHES) {
    const { offset, original, patched } = fingerprint;
    if (offset + original.length > inputBytes.length) {
      return 'unknown';
    }

    const current = sliceBytes(inputBytes, offset, original.length);
    if (equalBytes(current, original)) {
      originalMatches += 1;
      continue;
    }
    if (equalBytes(current, patched)) {
      patchedMatches += 1;
      continue;
    }
    return 'unknown';
  }

  if (originalMatches === NOCD_FINGERPRINT_PATCHES.length) {
    return 'vanilla';
  }
  if (patchedMatches === NOCD_FINGERPRINT_PATCHES.length) {
    return 'nocd';
  }
  return 'unknown';
}

function formatVariantLabel(baseVariant: BaseVariant, alreadyPatched: boolean): string {
  const baseLabel =
    baseVariant === 'vanilla' ? 'V1.0 Unpatched' : baseVariant === 'nocd' ? 'v1.0 No-CD Variant' : 'v1.0';
  return alreadyPatched ? `${baseLabel} (already patched)` : baseLabel;
}

export async function applySkezmodPatch(
  inputBytes: Uint8Array,
  options: { dryRun: boolean; inputFileName: string; outputFileName: string },
): Promise<PatchResult> {
  const inputCopy = new Uint8Array(inputBytes);
  const patched = new Uint8Array(inputBytes);

  const { bundle, stringAddrs } = buildBundle();
  const lookupHelperVa = CAVE_BUNDLE_BASE_VA;
  const patches = buildPatchPlan(lookupHelperVa, true);
  const rows: PatchRow[] = [];

  const bundleOff = vaToFileOffset(inputCopy, CAVE_BUNDLE_BASE_VA);
  const currentBundle = sliceBytes(inputCopy, bundleOff, CAVE_BUNDLE_SIZE);
  const allZero = currentBundle.every((b) => b === 0x00);
  const allCc = currentBundle.every((b) => b === 0xcc);
  const newBundle = equalBytes(currentBundle, bundle);

  if (!(allZero || allCc || newBundle)) {
    throw new Error(
      'Bundle cave bytes are not recognized for fresh or already patched binaries.',
    );
  }

  overwrite(patched, bundleOff, bundle);
  rows.push({
    name: 'write_shared_fallback_bundle_cave',
    siteVa: toHexVa(CAVE_BUNDLE_BASE_VA),
    siteFileOffset: toHexOff(bundleOff),
    siteBefore: bytesHex(currentBundle.slice(0, 64)),
    siteAfter: bytesHex(bundle.slice(0, 64)),
    bytesWritten: CAVE_BUNDLE_SIZE,
  });

  for (const spec of patches) {
    const siteOff = vaToFileOffset(inputCopy, spec.siteVa);
    const currentSite = sliceBytes(inputCopy, siteOff, spec.expected.length);
    const allowed = [spec.expected, spec.replacement, ...(spec.alternates ?? [])];
    if (!anyMatch(currentSite, allowed)) {
      throw new Error(`Patch-site bytes do not match expected signature for ${spec.name}.`);
    }

    overwrite(patched, siteOff, spec.replacement);
    rows.push({
      name: spec.name,
      siteVa: toHexVa(spec.siteVa),
      siteFileOffset: toHexOff(siteOff),
      siteBefore: bytesHex(currentSite),
      siteAfter: bytesHex(spec.replacement),
    });
  }

  const nullStub = buildNullTextGuardStub(CAVE_NULL_GUARD_VA, 0x0066f20a, stringAddrs.empty);

  const nullOff = vaToFileOffset(inputCopy, CAVE_NULL_GUARD_VA);
  const currentNull = sliceBytes(inputCopy, nullOff, nullStub.length);

  const allowedNull = [new Uint8Array(nullStub.length), nullStub];
  if (!anyMatch(currentNull, allowedNull)) {
    throw new Error('Null-guard cave bytes are not empty/known.');
  }

  overwrite(patched, nullOff, nullStub);
  rows.push({
    name: 'write_null_guard_cave',
    siteVa: toHexVa(CAVE_NULL_GUARD_VA),
    siteFileOffset: toHexOff(nullOff),
    siteBefore: bytesHex(currentNull),
    siteAfter: bytesHex(nullStub),
    bytesWritten: nullStub.length,
  });

  const outputBytes = new Uint8Array(patched);
  const report: PatchReport = {
    patchName: 'skezmod',
    inputExe: options.inputFileName,
    outputExe: options.outputFileName,
    dryRun: options.dryRun,
    patchCount: rows.length,
    patches: rows,
    addresses: {
      bundleBase: toHexVa(CAVE_BUNDLE_BASE_VA),
      bundleSize: CAVE_BUNDLE_SIZE,
      lookupHelper: toHexVa(lookupHelperVa),
      nullGuard: toHexVa(CAVE_NULL_GUARD_VA),
      empty: toHexVa(stringAddrs.empty),
      stars: toHexVa(stringAddrs.stars),
      free: toHexVa(stringAddrs.free),
      unknown: toHexVa(stringAddrs.unknown),
    },
    sha256: {
      input: await sha256Hex(inputCopy),
      output: await sha256Hex(outputBytes),
    },
    notes: [
      'SkezMod Patch 0.1.',
      'Adds null protection at FUN_0066F1F0 (0x0066F1FB) via code cave 0x006E51C0.',
      'Adds fallback lookup at FUN_004B5C20 (0x004B5C76) via code cave 0x006E5092.',
      'Applies title branding strings: PM99 SkezMod 0.1.',
      'Built for first-rollout MANAGPRE.EXE patching.',
    ],
  };

  return {
    outputBytes,
    report,
  };
}

function toHexVa(value: number): string {
  return `0x${value.toString(16).padStart(8, '0')}`;
}

function toHexOff(value: number): string {
  return `0x${value.toString(16).padStart(8, '0')}`;
}

export async function inspectCompatibility(
  inputBytes: Uint8Array,
  inputFileName: string,
): Promise<CompatibilityResult> {
  const baseVariant = detectBaseVariant(inputBytes);

  try {
    const { report } = await applySkezmodPatch(inputBytes, {
      dryRun: true,
      inputFileName,
      outputFileName: 'MANAGPRE.skezmod.exe',
    });

    const alreadyPatched = report.patches.every((row) => row.siteBefore === row.siteAfter);
    return {
      ok: true,
      variantLabel: formatVariantLabel(baseVariant, alreadyPatched),
      reasons: ['Signature checks passed.'],
      alreadyPatched,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown compatibility error';
    return {
      ok: false,
      variantLabel: baseVariant === 'unknown' ? 'Unknown or unsupported variant' : formatVariantLabel(baseVariant, false),
      reasons: [toUserCompatibilityReason(message)],
      alreadyPatched: false,
    };
  }
}

function toUserCompatibilityReason(message: string): string {
  if (
    message.includes('Input is not an MZ executable') ||
    message.includes('valid PE header') ||
    message.includes('does not map to a file-backed section')
  ) {
    return 'The selected file is not a supported MANAGPRE.EXE executable.';
  }

  if (
    message.includes('Bundle cave bytes are not recognized') ||
    message.includes('Patch-site bytes do not match expected signature') ||
    message.includes('Null-guard cave bytes are not empty/known')
  ) {
    return 'This MANAGPRE.EXE build is unsupported by the current patch profile.';
  }

  return 'Compatibility checks failed for this file.';
}

export function byteSizeLabel(size: number): string {
  if (size < 1024) {
    return `${size} B`;
  }
  const kb = size / 1024;
  if (kb < 1024) {
    return `${kb.toFixed(1)} KB`;
  }
  return `${(kb / 1024).toFixed(1)} MB`;
}
