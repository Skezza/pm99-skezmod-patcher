# SkezMod Stars Patch Promotion (2026-03-08)

Stable patch promotion completed:

- Submodule: `upstream/skezmod`
- Commit: `4abe273`
- Tag: `v0.1.0`
- Release name: `Stars Patch`

What was promoted:

- RC2 null-guard protection at `0x0066F1FB` (`FUN_0066F1F0` crash path hardening).
- `FUN_004B5C20` miss fallback hook at `0x004B5C76` with safe non-null records:
  - `Unknown club` (team id `0`)
  - `Stars` (team id `4705`)
  - `Free players` (team id `4706`)
- Explicit restoration of RC1 source-wrapper callsites back to `CALL 0x004A4720`.

Research-only status retained in PM99RE:

- `scripts/patch_managpre_valderrama_guard.py` stays as experimental history and comparison baseline.
