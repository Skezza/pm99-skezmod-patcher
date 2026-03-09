# Valderrama Patch Handover (2026-03-09)

## Goal
Fix Valderrama-related UI instability and blank team/club text in PM99 `MANAGPRE.EXE`, without regressing crash safety.

## Canonical Working File
- `scripts/patch_managpre_valderrama_guard.py`

## Current Binary State (live local)
- Target EXE:
  - `.local/premier-manager-ninety-nine/MANAGPRE.EXE`
- Current hash (from dry-run input/output):
  - `cd893be8b68da1476fe1139e8b7def83f3ea37680f0265a25a49e1307564c676`
- Patch idempotence:
  - Dry-run shows identical input/output SHA (already patched).

## Latest Backup Chain
Most recent backup before latest patch apply:
- `.local/premier-manager-ninety-nine/MANAGPRE.EXE.bak_valderrama_upstream_20260309_213856`

Recent backups (newest first):
- `..._213856`
- `..._213450`
- `..._213220`
- `..._212151`
- `..._211257`
- `..._210624`

## Active Hook/Helper Layout (current script intent)
- Null guard (kept crash-safe baseline):
  - Site `0x0066F1FB` -> cave `0x006E51C0`
  - Behavior: `NULL -> empty string` (not `Unknown club`; that variant regressed).
- Search window pre-sprintf normalization:
  - Site `0x0047494B` -> helper `0x006E5092`
- Lookup fallback:
  - Site `0x004B5C76` -> helper `0x006E50E5`
- Search token LE/DE wrapper:
  - Site `0x00499E0A` -> wrapper `0x00499E91`
- Formatter empty-template fallback:
  - Site `0x0049A111` -> helper `0x005FC92F`
- New forward attempt (latest):
  - Formatter call wrapper at `0x0049A103` -> helper `0x006E51E1`
  - Wrapper calls original `FUN_00499D00`, then backfills empty output with `"Unknown club"` via `lstrcpyA`.

## What Is Known From Testing
- Stable:
  - Crash guard at `0x0066F1FB` has repeatedly prevented original Valderrama hover crash.
  - Startup smoke under Wine timeouts typically completes without immediate crash.
- Observed regressions:
  - Switching null-guard fallback text from empty -> `Unknown club` caused crash; reverted.
- Open behavior (needs user validation after latest forward patch):
  - Whether Search Player by Name still shows blank team/club text with the new `0x0049A103` wrapper.

## Important Debug Note
The long Wine logs previously shared were shutdown traces. They do not include the first failing instruction.
For actionable crash triage, capture the first:
- `Unhandled exception ... addr 0x...`

## Next Worker: Exact Steps
1. Reproduce in-game path:
   - Open Search Player by Name.
   - Trigger Valderrama path and observe: crash vs blank vs text.
2. If crash occurs:
   - Capture first exception line with address.
   - Map failing address to patched sites above before changing code.
3. If no crash but still blank:
   - Keep current null-guard baseline.
   - Trace true render consumer for search team column (post-format path), not hover path.
   - Avoid changing null-guard fallback target again.
4. Keep edits in `scripts/patch_managpre_valderrama_guard.py` only (research track), then re-apply in-place and retest.

## Fast Rollback Command
From repo root:
```bash
cp .local/premier-manager-ninety-nine/MANAGPRE.EXE.bak_valderrama_upstream_20260309_213856 \
   .local/premier-manager-ninety-nine/MANAGPRE.EXE
```

## Scope Boundary
This is active research patching, not productionized SkezMod release code.
Do not treat `scripts/patch_managpre_valderrama_guard.py` as release-canonical until behavior is fully validated.
