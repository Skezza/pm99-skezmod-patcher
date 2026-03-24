import { describe, expect, it } from 'vitest';
import { buildCall, buildTrampoline, inspectCompatibility } from './patchEngine';

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('patchEngine helper bytes', () => {
  it('buildTrampoline emits jmp rel32 plus nop padding', () => {
    const out = buildTrampoline(0x401000, 0x401100, 8);
    expect(hex(out)).toBe('e9fb000000909090');
  });

  it('buildCall emits call rel32', () => {
    const out = buildCall(0x401000, 0x401200);
    expect(hex(out)).toBe('e8fb010000');
  });
});

describe('compatibility guardrails', () => {
  it('rejects clearly non-PE data', async () => {
    const result = await inspectCompatibility(new Uint8Array([0x00, 0x01, 0x02]), 'bad.exe');
    expect(result.ok).toBe(false);
    expect(result.variantLabel).toContain('Unknown');
    expect(result.reasons[0]).toContain('supported MANAGPRE.EXE executable');
  });
});
