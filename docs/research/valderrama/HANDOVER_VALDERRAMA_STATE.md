# Valderrama Patch Handover (2026-03-11)

## Goal
Fix Valderrama-related UI instability and blank team/club text in PM99 `MANAGPRE.EXE`, without regressing crash safety.

## Canonical Working File
- `scripts/research/patch_managpre_valderrama_guard.py`
- Script now auto-detects PM99 root between repo-local `.local` and shared `../../.local`.

## Patch Modes (Implemented)
- Canonical rollback baseline:
  - `.local/premier-manager-ninety-nine/MANAGPRE.EXE.stable_unknownclub_20260310_130159`
- Script interface now supports:
  - `--mode stable`: copy canonical stable baseline image bytes (no patch synthesis).
  - `--mode instrument --probe-id <id>`: deterministic single-probe marker mode.
  - `--mode final`: production patch mode.
- Instrumentation probe IDs:
  - `hover_field_stage3`
  - `bio_copy_src_43f24f`
  - `postcall_68e52`
  - `postcall_43bd46`
- Safety gate:
  - `--force-known-legacy` is required to bypass known-bad signatures (default is reject).
  - Exception (2026-03-22 fix-forward): malformed wrapper variant
    `817c2408cc4a7300750a66837c240e007502c744240cad516e00eb8e909090`
    is now treated as auto-migratable legacy for safe re-apply without `--force`.

## Dry-Run Validation Matrix (2026-03-11)
- `python3 -m py_compile scripts/research/patch_managpre_valderrama_guard.py` -> OK
- `--dry-run --mode stable` -> OK
- `--dry-run --mode final` -> OK
- `--dry-run --mode instrument --probe-id hover_field_stage3` -> OK
- `--dry-run --mode instrument --probe-id bio_copy_src_43f24f` -> OK
- `--dry-run --mode instrument --probe-id postcall_68e52` -> OK
- `--dry-run --mode instrument --probe-id postcall_43bd46` -> OK

Status:
- Tooling and mode-switch safety are implemented and deterministic.
- Full gameplay gate remains runtime-only and must be validated in-game.

## Current Binary State (live local)
- Target EXE:
  - `.local/premier-manager-ninety-nine/MANAGPRE.EXE`
- Current hash (from dry-run input/output):
  - `432fe25c99d378daf17b365f97a74d845eecb73002eb6a68d589ca583aeb2efc`
- Patch idempotence:
  - Dry-run shows identical input/output SHA (already patched).

## Latest Backup Chain
Most recent backup before latest patch apply:
- `.local/premier-manager-ninety-nine/MANAGPRE.EXE.bak_valderrama_upstream_20260311_074114`

Split-out stable baseline (kept explicitly):
- `.local/premier-manager-ninety-nine/MANAGPRE.EXE.stable_unknownclub_20260310_130159`
- SHA256: `b1128c3be3df18c3423dbcc44f06ae2002aae774875964df900114d25c3dc335`

Recent backups (newest first):
- `..._20260311_074114`
- `..._20260311_003623`
- `..._20260311_000151`
- `..._20260310_234952`
- `..._20260310_231716`
- `..._20260310_225441`
- `..._20260310_224850`
- `..._20260310_184105`
- `..._20260310_183125`
- `..._20260310_182502`
- `..._20260310_181816`
- `..._20260310_175217`
- `..._20260310_174531`
- `..._20260310_174237`
- `..._20260310_174140`
- `..._20260310_174010`
- `..._20260310_172657`
- `..._20260310_170833`
- `..._20260310_165307`
- `..._20260310_163403`
- `..._20260310_162233`
- `..._20260310_161606`
- `..._20260310_142721`
- `..._20260310_134812`
- `..._20260310_134010`
- `..._20260310_132317`
- `..._20260310_130159`
- `..._20260310_124209`
- `..._20260310_122420`
- `..._20260310_115649`
- `..._20260310_114314`
- `..._20260310_113457`
- `..._20260310_113153`
- `..._20260310_112704`
- `..._20260310_100624`
- `..._20260310_100415`
- `..._20260310_093421`
- `..._20260310_092954`
- `..._20260310_092302`
- `..._20260310_091049`
- `..._20260310_083548`
- `..._20260310_072137`
- `..._232328`
- `..._224518`
- `..._213856`
- `..._213450`
- `..._213220`
- `..._212151`
- `..._211257`
- `..._210624`

## Active Hook/Helper Layout (current script intent)
- Mode control:
  - `stable` mode bypasses hook synthesis and writes the stable baseline image.
  - `instrument` mode only mutates one selected field-writer path at a time using `[PRB:<id>]` marker text.
  - `final` mode applies production hooks/fallbacks.
- Null guard (kept crash-safe baseline):
  - Site `0x0066F1FB` -> cave `0x006E51C0`
  - Behavior: `NULL -> empty string` (not `Unknown club`; that variant regressed).
- Search window pre-sprintf normalization:
  - Site `0x0047494B` -> helper `0x006E5092`
- Lookup fallback:
  - Site `0x004B5C76` -> helper `0x006E50E5`
- Search connector call restored:
  - Site `0x00499E0A` -> original `CALL 0x004A4720` (no wrapper).
- Global formatter call (crash-safe baseline):
  - Site `0x0049A103` is restored to original direct call target `0x00499D00`.
  - `0x00499E91` is no longer used by the global formatter path.
- Shared formatter arg3 low-pointer guard:
  - Routed callsites are restored to original import thunk (`0x006E64C8`) to avoid global side effects.
  - `0x006E51E1` is now repurposed as an `lstrcpyA` source-empty shim (`[esp+8]` -> `"Unknown club"` when NULL/empty).
- `FUN_0049A410` internals restored:
  - Site `0x0049A478` restored to original `CALL 0x0049A0E0`.
  - Site `0x0049A486` now uses miss-fallback epilogue (writes `"Unknown club"` into destination buffer).
- `FUN_0049A410` primary callsites restored to original:
  - Site `0x00468E4D` -> original `CALL 0x0049A410`.
  - Site `0x0043BD41` -> original `CALL 0x0049A410`.
  - Site `0x0041E74B..0x0041E750` now routes through a local staged hover-field hook.
- Caller-local post-call helpers (active):
  - Site `0x00468E52` now calls adapter cave `0x00468F61` (loads `[esp+0x3C]`, tail-jumps to `0x005FC92F`).
  - Site `0x0043BD46` now calls adapter cave `0x00499E91` (+NOPx3; loads `[esp+0x10]`, tail-jumps to `0x005FC92F`).
  - Cave `0x005FC92F` behavior (2026-03-11 update): destination-fill helper; if `EAX==NULL` or `*EAX=='\\0'`, copy `"Unknown club"` in place via `lstrcpyA`, then return.
  - Cave `0x00499E91` is now a stack-slot adapter for `FUN_0043BD10` post-call fill.
  - Cave `0x00468F61` is now a stack-slot adapter for `FUN_00468C90` list-text fill.
  - Hover-field staged caves (2026-03-11 update):
    - `0x006E4191`: call `FUN_0049A410`, jump stage2.
    - `0x006E4251`: replay `add esi,0x903c`, jump stage3.
    - `0x006E42D1`: if `*EAX=='\\0'`, set `EAX="Unknown club"`, then jump resume `0x0041E756`.
  - New bio/search copy-site hook: `0x0043F24F` now calls `0x006E51E1` (+NOP) instead of direct `CALL [0x006E6108]`.
  - Mode-switch safety (2026-03-11):
    - `0x006E42D1`, `0x00468F61`, `0x006E51E1`, `0x00499E91` now accept both final and probe variants as known signatures.
    - This prevents false "unknown cave bytes" failures when toggling between `instrument` and `final`.
- D1 raw formatter path:
  - Site `0x00499D53` restored to original bytes.
  - No global sanitizer routing from this path.
- S2/S3 raw formatter pointer guard:
  - Sites `0x00499D91` and `0x00499DA1` are restored to original bytes (no global hook).
- LE/DE/EN token null-source normalization:
  - Sites in `FUN_00499D00` are restored to original bytes (no global token hook).
  - Local helper caves remain only as compatibility/rollback artifacts.
- Secondary object-chain null guard (from Wine AV at `0x0064CFD6`):
  - Site `0x0064CFD6` guarded inline.
  - Stage caves: `0x0064CFFA` -> `0x0064CE25` -> `0x0064D077`.
  - Behavior: if `EBP==NULL`, skip virtual call and preserve original tail path (`mov edx,[esp+0xA4]` then continue).
- Formatter empty-template branch restored:
  - Site `0x0049A111` is restored to original bytes (no helper/trampoline).
- Global formatter call remains restored:
  - Keep direct `CALL 0x00499D00` at `0x0049A103`; do not retarget this site to `0x00499E91`.
- Menu formatter call restored:
  - Site `0x00496358` remains original `CALL 0x0049A0E0`.
- Menu draw call restored:
  - Site `0x0049635D` remains original `push eax; push edi; call 0x0040D3E0`.

## What Is Known From Testing
- Stable:
  - Crash guard at `0x0066F1FB` has repeatedly prevented original Valderrama hover crash.
  - Startup smoke under Wine timeouts typically completes without immediate crash.
- Observed regressions:
  - Switching null-guard fallback text from empty -> `Unknown club` caused crash; reverted.
  - Broad/unconditional post-call fallback at `0x00468C81` caused `"Unknown club"` to appear everywhere when stage2 was copy-only; later replaced with full sanitize/copy helper path.
  - Crash signatures from user repro (before latest D1 guard):
    - `EXCEPTION_ACCESS_VIOLATION (c0000005)` read at `0x00000425` (Wine `ip=7B1630E6`).
    - `EXCEPTION_ACCESS_VIOLATION (c0000005)` read at `0x00000433` (Wine `ip=7B1630E6`).
    - Both indicate low numeric IDs flowing into `%s` formatting.
  - Crash signature from buggy formatter wrapper variant:
    - `EXCEPTION_PRIV_INSTRUCTION (c0000096)` at `0x006E51F9`.
    - Root cause: malformed wrapper short jumps (`75 0A` / `75 02`) landed in the immediate bytes of `mov [esp+0x0c], 0x006E51AD`.
  - Crash signature from broken `FUN_0049A410` entry-wrapper attempt:
    - `EXCEPTION_ACCESS_VIOLATION (c0000005)` at `0x0049A48D`, write to `0x00468E52`.
    - Root cause: wrapper `CALL` inserted an extra return address, shifting args so `FUN_0049A410` treated code address as destination buffer.
  - Crash signature from broken hover draw helper attempt:
    - `EXCEPTION_ACCESS_VIOLATION (c0000005)` with `ip=0x04A4CC49`, `addr=0x00000001` while searching player by name.
    - Root cause: helper pushed draw args, called `0x0040D3E0`, then `RET` without stack cleanup, returning into argument data.
  - Crash signature from broken hover lookup wrapper attempt:
    - Search-by-name crash at player select (Valderrama path), with helper-active site `0x0041E74B -> 0x005FC92F`.
    - Root cause: wrapper `CALL` into `FUN_0049A410` shifted stack args by one return address (callee-entry wrapping issue).
  - Open behavior (needs user validation after latest forward patch):
  - Validate first-season load stability (regression check after `0x0064CFD6` null-chain crash report).
  - Validate Search Player by Name hover and bio panel now render non-empty team/club text via (`0x0041E74B..0x0041E750` staged hook, `0x0043F24F` source-empty copy hook, `0x00468E52->0x00468F61->0x005FC92F`, `0x0043BD46->0x00499E91->0x005FC92F`).
  - Validate signing string behavior remains unchanged (no global formatter or `FUN_0049A410` internal hooks active).
  - Confirm both:
    - `c0000005` read-at-`0x425`/`0x433` crash does not appear.
    - Player bio club field no longer blanks for Valderrama.

## Attempt Ledger (to avoid circular retries)
Each method below has already been tried. Re-open only with new evidence.

| ID | Method | Key sites | Outcome | Decision |
|---|---|---|---|---|
| A1 | Keep crash null guard with empty-string fallback | `0x0066F1FB` | Stable baseline for original hover crash path | Keep |
| A2 | Change null guard fallback to `"Unknown club"` | `0x0066F1FB` | Regressed stability (startup/season crashes) | Retired |
| A3 | Global formatter retarget/wrapper | `0x0049A103` | Produced crashes and/or broad side effects | Retired (site restored original) |
| A4 | Menu draw-call end-of-path wrapper | `0x0049635D` | Too late in pipeline; did not fix core blank paths | Retired (site restored original) |
| A5 | Menu caller-specific formatter hook | `0x00496358` | Safer than global retarget, but did not solve bio/hover fields | Retired (site restored original) |
| A6 | Token-branch pointer hooks in formatter | `0x00499DCF`, `0x00499DED`, `0x00499E5B` | Multiple instability cases across flows | Retired (sites restored original) |
| A7 | Connector wrapper assumption (`"of"/"Of"/""`) | `0x00499E0A -> FUN_004A4720` | Wrong layer; connector text only, not club lookup | Retired (restored original) |
| A8 | Callee-entry wrapper of `FUN_0049A410` | entry + `0x0049A478` path | Arg-shift crash at `0x0049A48D` (write to code addr) | Retired (internals restored) |
| A9 | Hover draw helper with manual call/return | `0x0041E756` region | Stack/return corruption crash at `0x04A4CC49` | Retired |
| A10 | Hover lookup wrapper via direct `CALL` stage | `0x0041E74B -> 0x005FC92F` (early variant) | Player-select crash due to stack-shifted args | Retired |
| A11 | Broad post-call fallback in caller | `0x00468C81` | `"Unknown club"` appeared everywhere | Retired |
| A12 | `FUN_0049A410` miss epilogue fallback | `0x0049A486` | Stable; only affects lookup miss path | Active (targeted) |
| A13 | Field-level hover staged hook | `0x0041E74B..0x0041E750` -> `0x006E4191/4251/42D1` | Stable but still blank in current user repro | Active, unresolved |
| A14 | Bio/search copy source-empty shim | `0x0043F24F -> 0x006E51E1` | Stable but still blank in current user repro | Active, unresolved |
| A15 | Stack-slot adapters into destination-fill helper | `0x00468E52 -> 0x00468F61 -> 0x005FC92F`, `0x0043BD46 -> 0x00499E91 -> 0x005FC92F` | Stable but still blank in current user repro | Active, unresolved |
| A16 | Lookup tail fallback mapping | `0x004B5C76` | Kept for unresolved IDs and known edge IDs | Keep |
| A17 | Mode-gated deterministic probing framework | `stable/instrument/final`, probes at `0x006E42D1`, `0x006E51E1`, `0x00468F61`, `0x00499E91` | Implemented; dry-run matrix passes; runtime ownership validation pending | Active |

Interpretation for next work:
- We are no longer cycling global/callee-entry hooks (`A3`, `A8`) because they were crash-prone.
- Remaining open area is field-level write provenance (why active write hooks `A13-A15` do not observe non-empty or writable destination in bio/hover paths).

## 2026-03-11 Late Update (Crash Root Cause + Script Fix)
- Root cause of latest probe crashes:
  - `lookup_call_*` instrumentation was routed through `0x00404A41` (token-null helper cave), which is reused by unrelated token logic.
  - This leaked probe behavior into non-target paths and produced ASCII-like fault addresses (`"You "`, `"Firs"` patterns in exception pointers).
- Script corrections now implemented in `patch_managpre_valderrama_guard.py`:
  - `lookup_call_*` probes now route to dedicated `CAVE_LOOKUP_MISS_HELPER_VA` (`0x0046B781`), not token-null helper cave.
  - Added explicit cave writer for `0x0046B781` in all modes:
    - `final`: `_build_lookup_miss_unknown_helper` (`lstrcpyA` Unknown fallback)
    - `instrument lookup_call_*`: `_build_return_marker_ptr_stdcall2`
  - Restored token-null helper (`0x00404A41`) to always use default null/empty normalization in all modes.
  - Added idempotency alternates for old probe callsites (`0x00468167/DB/24B -> 0x00404A41`) and old token probe blob, so migration back to safe/final works without `--force`.
  - Validation:
    - `python3 -m py_compile` passes.
    - Dry-run matrix passes for `final` and all probes.
    - Final patch applied in-place to `.local` with backup:
      - `MANAGPRE.EXE.bak_valderrama_upstream_20260311_221006`
      - `MANAGPRE.EXE.bak_valderrama_upstream_20260311_222113` (post runtime-framework refresh)

## Last Binary Pass Implementation (Runtime Ownership Tracing, 2 Sessions)
Implemented in:
- `scripts/research/patch_managpre_valderrama_guard.py`

New execution support:
- `--emit-ownership-manifest` prints a deterministic JSON command pack for Session 1 + Session 2.
- Runtime probe promotion without code edits:
  - `--mode instrument --probe-id runtime_<label>`
  - `--runtime-probe-site-va <VA>`
  - `--runtime-probe-expected-hex <5-byte callsite bytes>`
  - `--runtime-probe-original-target-va <VA>` (optional idempotency alternate)

Hard safety boundaries retained:
- No global formatter retargeting.
- No callee-entry wrapping.
- Runtime promotion is restricted to exact 5-byte CALL rel32 callsites only.

### Session 1 Commands (Ownership Pass)
Generate manifest (recommended):
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --emit-ownership-manifest \
  --json-output /tmp/pm99_ownership_manifest.json
cat /tmp/pm99_ownership_manifest.json
```

Reset baseline:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode stable
```

Probe sequence (one launch per probe):
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode instrument --probe-id hover_field_stage3
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode instrument --probe-id bio_copy_src_43f24f
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode instrument --probe-id postcall_68e52
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode instrument --probe-id postcall_43bd46
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode instrument --probe-id lookup_call_68167
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode instrument --probe-id lookup_call_681db
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode instrument --probe-id lookup_call_6824b
```

Revert for disappearance check:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode stable
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode final
```

### Session 2 Commands (Runtime Writer Capture -> Promotion)
1) Reset stable:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py --in-place --mode stable
```

2) Capture exact MANAGPRE callsite writer in runtime debugger for unresolved field.
   Use the breakpoint recipes from `--emit-ownership-manifest`.

3) Promote exact callsite to runtime probe (example shape):
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --in-place \
  --mode instrument \
  --probe-id runtime_search_hover_owner \
  --runtime-probe-site-va 0x00400000 \
  --runtime-probe-expected-hex e800000000 \
  --runtime-probe-original-target-va 0x0049A410
```

4) Confirm marker in 2 clean launches. If still unresolved by end of Session 2: stop binary hunt.

### Session 2 Attempt Log
- Attempt 1 (runtime probe): callsite `0x0041F70B` (`CALL 0x004B5C20`, bytes `e810650900`, `pop_bytes=4`)
  - Outcome: rejected.
  - Reason: probe corrupted briefcase `Stars` text (global side effect), so callsite is not field-local owner for the target bio slot.
  - Recovery applied immediately: `stable -> final` reset.
- Attempt 2 (runtime probe, isolated helper cave): callsite `0x0041F70B` (`CALL 0x004B5C20`, bytes `e810650900`, `pop_bytes=4`)
  - Outcome: rejected.
  - Reason: briefcase text corruption persisted even with isolated runtime helper cave, confirming callsite is upstream/shared and not acceptable for field-local final patching.
  - Recovery applied immediately: `stable -> final` reset.

## Important Debug Note
The long Wine logs previously shared were shutdown traces. They do not include the first failing instruction.
For actionable crash triage, capture the first:
- `Unhandled exception ... addr 0x...`

## Next Worker: Exact Steps
1. Baseline reset:
   - Apply `--mode stable --in-place` once to reset to canonical stable image.
2. Probe ownership (one at a time):
   - Apply `--mode instrument --probe-id hover_field_stage3 --in-place`, verify whether `[PRB:hover_field_s` appears in Search-by-Name hover club field.
   - Apply `--mode instrument --probe-id bio_copy_src_43f24f --in-place`, verify whether marker appears in bio club field.
   - Apply `--mode instrument --probe-id postcall_68e52 --in-place`, verify whether marker appears in search/list path fed via `0x00468E52`.
   - Apply `--mode instrument --probe-id postcall_43bd46 --in-place`, verify whether marker appears in bio/postcall path fed via `0x0043BD46`.
3. After each probe:
   - Record visible field ownership result in this file (`active/resolved/retired`).
   - If crash occurs, capture first exception address and map it to the patched site before any further code change.
4. Final mode:
   - Re-apply `--mode final --in-place`.
   - Run full gameplay gate: startup, first fixture, search hover field, bio field, briefcase, signing text.
5. Scope control:
   - Keep edits in `scripts/research/patch_managpre_valderrama_guard.py` only.
   - Do not reintroduce global formatter retargeting or callee-entry wrapping (`A3`, `A8`).

## Fast Rollback Command
From repo root:
```bash
cp .local/premier-manager-ninety-nine/MANAGPRE.EXE.bak_valderrama_upstream_20260311_165039 \
   .local/premier-manager-ninety-nine/MANAGPRE.EXE
```

## Scope Boundary
This is active research patching, not productionized SkezMod release code.
Do not treat `scripts/research/patch_managpre_valderrama_guard.py` as release-canonical until behavior is fully validated.

## 2026-03-11 Fix-Forward Update (Applied)
Forward-only stabilization pass applied to reduce blank/garbage club strings without reintroducing global hooks.

### Script changes
File:
- `scripts/research/patch_managpre_valderrama_guard.py`

Implemented:
- `0x005FC92F` post-call helper now performs stronger local sanity gating:
  - returns unchanged when `EAX==NULL`,
  - treats first-byte values `<= '.'` or obvious high-bit junk (`JS` after cmp) as invalid,
  - routes invalid buffers to `0x0046B781` miss-helper copy path (`Unknown club` in destination).
- `0x006E42D1` hover stage3 now:
  - `CALL 0x005FC92F` sanitizer helper,
  - then jumps back to `0x0041E756` draw resume.
- `0x006E51E1` lstrcpy source shim now sanitizes source pointer using the same local first-byte validity logic (not just NUL).
- Idempotency guard lists updated so migration from prior final bytes to this forward variant does not require `--force`.

### Binary apply
Command used:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode final \
  --json-output /tmp/pm99_fixforward_apply.json
```

Backup created:
- `/home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE.bak_valderrama_upstream_20260311_234502`

Hash:
- Live `MANAGPRE.EXE` after fix-forward apply:
  - `3bebec1e03cbf53502afdd904b860f03b9ae19c7e1c584bac40311bc95aa19ad`

### Notes
- Runtime DB (`JUG98030.FDI`) was not modified in this pass.
- This pass is intentionally field-local/helper-local; no global formatter retargeting or callee-entry wrapping was added.

## 2026-03-11 DB Repair Pivot (Applied)
Given unresolved binary ownership after the 2-session cap, a reversible data-only repair variant was applied to runtime DB:

- Script:
  - `scripts/research/patch_jug_valderrama_indexed_repair.py`
- Command:
  - `PYTHONPATH=/home/joe/pm99-research/upstream/pm99-skezmod-db-editor python3 scripts/research/patch_jug_valderrama_indexed_repair.py --jug /home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/JUG98030.FDI --mode donor_template_fullname --in-place --json-output /tmp/valderrama_indexed_repair_apply.json`
- Backup created:
  - `/home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/JUG98030.FDI.bak_valderrama_indexed_repair_20260311_232527`
- Hashes:
  - Before variant (backup): `46641a36f66998b22097d35addefdfbf6e2d5ecf7fef1261cb84ecbc07dfa5fe`
  - After variant (live): `1a9b362536222b496b5e846192d7d6efb26f4aa59df91a41667a666c0174fcb7`

Rollback to pre-variant DB:
```bash
cp /home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/JUG98030.FDI.bak_valderrama_indexed_repair_20260311_232527 \
   /home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/JUG98030.FDI
```

Result:
- Rejected for runtime use.
- User-observed behavior indicated donor-link contamination ("linked to Dmytro MIHAJLENKO").
- Rolled back immediately to backup `..._20260311_232527`; live and backup hashes match:
  - `46641a36f66998b22097d35addefdfbf6e2d5ecf7fef1261cb84ecbc07dfa5fe`

## 2026-03-12 Fix-Forward Adjustment (Applied)
Targeted correction to the latest field-local wrapper attempt:

- `search hover draw wrapper` corrected from writing stack arg2 to arg1:
  - `0x006C42D2`: `mov [esp+0x08], unknown` -> `mov [esp+0x04], unknown`
  - Reason: `FUN_0040D3E0` reads text from first stack argument.
- `bio star-slot wrapper` reverted to original call target:
  - `0x0041F739`: restored call to `0x00674430` (removed forced wrapper call)
  - Reason: wrapper target was unproven and risked wrong-parameter side effects.
- Kept all other active final-mode guards/fallbacks unchanged for this pass.

Apply command used:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode final \
  --json-output /tmp/pm99_apply_fixforward.json
```

Backup created:
- `/home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE.bak_valderrama_upstream_20260312_000152`

Hashes:
- Before apply: `8af9d8a0d03c489b96891d3c54feedcfc8c1fdd78ae0d0aff77d339086edefc2`
- After apply:  `235aca69dcfc906648f86dcdaf13f33421b2eebbe931f2532d8d857e00e0760c`

## 2026-03-12 Crash-Fix Rollforward (Applied)
Crash observed with access violation on low read address (`0x0000006b`) during helper path. Applied a crash-focused rollback/hardening pass:

- Restored `0x0043BD46` to original bytes:
  - from helper call stub back to `8A 44 24 0C 84 C0 74 4A`
- Hardened post-call destination sanitizer (`0x005FC92F`):
  - now guards `EAX < 0x10000` before dereferencing `[EAX]`
- Reworked lstrcpy source shim (`0x006E51E1`):
  - fixed control-flow bug that could force fallback path unexpectedly
  - adds low-address pointer floor check (`< 0x10000`) before source dereference

Apply command:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode final \
  --json-output /tmp/pm99_apply_crashfix.json
```

Backup:
- `/home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE.bak_valderrama_upstream_20260312_000928`

Hashes:
- Before apply: `235aca69dcfc906648f86dcdaf13f33421b2eebbe931f2532d8d857e00e0760c`
- After apply:  `34123fbbfc56889c5c5de1db6db3bd8d2b96344f42dddc74c438c31a448b4902`

## 2026-03-12 Crash-Fix Forward (Applied)
Crash signature while searching/hovering showed destination writes into literal text (`info[1]=72756f59`, `"Your"`), consistent with argument-shape corruption on hover draw routing.

Applied targeted rollback of that callsite only:

- `0x0041E756` (`restore_search_hover_draw_call_FUN_0041e720`)
  - from patched `call 0x006C42D2` wrapper path
  - back to original `call 0x0040D3E0` sequence

Rationale:
- Wrapper routing at this callsite was not ownership-proven and could invert/overwrite stack arg semantics for non-target UI strings.
- This change is stability-first and keeps other active field-local experiments unchanged.

Apply command:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode final
```

Backup:
- `/home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE.bak_valderrama_upstream_20260312_075006`

Hashes:
- Before apply: `f9c0f42534441c151ebca8637517ab1a06c203f08ae5f609889974490a96eb42`
- After apply:  `9a275b65863090bad662c218fa1c68776ca4dea13b841a38f15a76ecec97f539`

## 2026-03-12 DB-First Stars Team-ID Repair (Applied)
Implemented plan: repair JUG team ownership for the EQ-linked Stars cluster only (Valderrama + Stars roster), with staged output first and explicit live promotion.

### Script added
- `scripts/research/repair_jug_stars_team_ids.py`

### Stage command
```bash
python3 scripts/research/repair_jug_stars_team_ids.py \
  --jug /home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/JUG98030.FDI \
  --eq /home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/EQ98030.FDI \
  --team-query Stars \
  --known-good-jug /home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/JUG98030.FDI.bak_valderrama_restore_20260307_084408 \
  --primary-player-id 20864 \
  --output-jug /tmp/JUG98030.stars_teamid_repair.FDI \
  --json-output /tmp/stars_teamid_repair_stage.json
```

### Preflight/stage findings
- Matched EQ-linked roster: `eq_record_id=9900`, short/full = `Stars`.
- Resolved canonical Stars `team_id`: `4705` (single unique candidate).
- Target player IDs patched (Stars linked roster):
  - `58, 115, 8425, 16955, 17126, 20863, 20864, 20865, 20866, 20867`
- Primary player (`20864`, Carlos VALDERRAMA):
  - baseline source = known-good backup payload
  - `team_id`: `0 -> 4705`

### Staged validations
- Stars linked PID check on staged JUG:
  - all target IDs parse as `team_id=4705` via direct indexed payload decode.
- Parser-backed file validation:
```bash
python3 -m app.cli validate-database \
  --players /tmp/JUG98030.stars_teamid_repair.FDI \
  --teams /home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/EQ98030.FDI \
  --coaches /home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/ENT98030.FDI \
  --json
```
- Result: `all_valid: true`.

### Promote to live JUG
Performed staged promote with explicit live backup.

Backup created:
- `/home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/JUG98030.FDI.bak_stars_teamid_repair_promote_20260312_223257`

Hashes:
- Live JUG before promote (backup hash): `46641a36f66998b22097d35addefdfbf6e2d5ecf7fef1261cb84ecbc07dfa5fe`
- Staged repaired JUG: `845991b625108a61d84aaa30dbb2bad39c5824510b275d21576fd61e4f9c8f44`
- Live JUG after promote: `845991b625108a61d84aaa30dbb2bad39c5824510b275d21576fd61e4f9c8f44`

Rollback command:
```bash
cp /home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/JUG98030.FDI.bak_stars_teamid_repair_promote_20260312_223257 \
   /home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/JUG98030.FDI
```

### Runtime gate status
- Binary was intentionally untouched in this pass.
- Gameplay/UI verification pending user run:
  - search-by-name hover club text,
  - bio star-slot club text,
  - briefcase still `Stars`,
  - no crash through first fixture.
- Hard stop rule retained: if Stars/Valderrama `team_id` repair is present and fields remain blank, DB path is considered exhausted.

## 2026-03-12 Post-Repair Evidence + Stable EXE Reset
User runtime result after DB team-id repair:
- Search-by-name and bio club fields remain blank.

New evidence gathered:
- `JUG` first 2-byte `team_id` field is not authoritative for those UI fields:
  - Many normal linked-club players (for example Barcelona/Man Utd roster samples) also parse with `team_id=0` in `JUG` while club links clearly resolve via EQ linked rosters.
  - Therefore the Stars-cluster `team_id` repair, while internally consistent, is not sufficient to drive those two UI text paths.

Safety reset applied (to remove hook interference while keeping DB repair):
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode stable \
  --json-output /tmp/pm99_apply_stable_reset.json
```

Backup created:
- `/home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE.bak_valderrama_upstream_20260312_224432`

Hashes:
- EXE before reset: `9a275b65863090bad662c218fa1c68776ca4dea13b841a38f15a76ecec97f539`
- EXE after reset:  `b1128c3be3df18c3423dbcc44f06ae2002aae774875964df900114d25c3dc335`

DB repair persistence check after EXE reset:
- Stars linked PIDs in live JUG remain patched (`team_id=4705` for all target IDs).

## 2026-03-12 Final Deep Debugger Pass Kickoff (Session 0 Complete)
Implemented the agreed hard-stop ownership pass setup using existing tooling only.

### Session 0 prep (completed)
Stable reset command:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode stable --json-output /tmp/pm99_s0_stable.json
```

Ownership manifest command:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --emit-ownership-manifest > /tmp/ownership_manifest.json
```

Artifacts:
- Stable apply JSON: `/tmp/pm99_s0_stable.json`
- Ownership manifest: `/tmp/ownership_manifest.json`
- Stable backup created by apply: `/home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE.bak_valderrama_upstream_20260312_232352`

Hashes:
- EXE before stable apply: `b1128c3be3df18c3423dbcc44f06ae2002aae774875964df900114d25c3dc335`
- EXE after stable apply:  `b1128c3be3df18c3423dbcc44f06ae2002aae774875964df900114d25c3dc335`

Session 1 probe order (manifest-locked):
1. `hover_field_stage3`
2. `bio_copy_src_43f24f`
3. `postcall_68e52`
4. `postcall_43bd46`
5. `lookup_call_68167`
6. `lookup_call_681db`
7. `lookup_call_6824b`

### Run log rows (for this pass)
Record each launch as:
`mode | probe_id | ui_action | hover_value | bio_star_slot_value | briefcase_value | crash | first_writer_eip | dest_buffer`

### Session 1 Run 1 armed (probe apply complete)
Probe apply command:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode instrument --probe-id hover_field_stage3 --force-known-legacy \
  --json-output /tmp/pm99_s1_p1_probe_hover_field_stage3.json
```

Notes:
- `--force-known-legacy` was required due guarded legacy cave signature check.
- Active marker for this run: `[PRB:hover_field_s`.
- Apply JSON: `/tmp/pm99_s1_p1_probe_hover_field_stage3.json`

Run row (awaiting runtime observation):
`instrument | hover_field_stage3 | hover test | <pending> | <pending> | <pending> | <pending> | <n/a> | <n/a>`

Run row (observed):
`instrument | hover_field_stage3 | hover test | hover=blank | bio_star_slot=blank | briefcase=[PRB:hover_field_s in transfer-scout blue bubble | crash=no (not reported) | first_writer_eip=<n/a> | dest_buffer=<n/a>`

Interpretation:
- Probe marker appeared in briefcase transfer-scout speech region again.
- Ownership for target fields not proven; classify `hover_field_stage3` as non-owner for this pass.

### Session 1 Run 2 armed (probe apply complete)
Probe apply command:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode instrument --probe-id bio_copy_src_43f24f --force-known-legacy \
  --json-output /tmp/pm99_s1_p2_probe_bio_copy_src_43f24f.json
```

Notes:
- `--force-known-legacy` required again for guarded migration.
- Active marker for this run: `[PRB:bio_copy_src_`.
- Apply JSON: `/tmp/pm99_s1_p2_probe_bio_copy_src_43f24f.json`

Run row (awaiting runtime observation):
`instrument | bio_copy_src_43f24f | bio open | hover=<pending> | bio_star_slot=<pending> | briefcase=<pending> | crash=<pending> | first_writer_eip=<n/a> | dest_buffer=<n/a>`

Run row (observed):
`instrument | bio_copy_src_43f24f | bio open | hover=blank | bio_star_slot=blank | briefcase=no probe marker observed | crash=no (not reported) | first_writer_eip=<n/a> | dest_buffer=<n/a>`

Interpretation:
- Probe marker not observed in target field; target fields remained blank.
- Ownership for target fields not proven; classify `bio_copy_src_43f24f` as non-owner for this pass.

### Session 1 Run 3 armed (probe apply complete)
Probe apply command:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode instrument --probe-id postcall_68e52 --force-known-legacy \
  --json-output /tmp/pm99_s1_p3_probe_postcall_68e52.json
```

Notes:
- `--force-known-legacy` required for guarded migration.
- Active marker for this run: `[PRB:postcall_68e5`.
- Apply JSON: `/tmp/pm99_s1_p3_probe_postcall_68e52.json`

Run row (awaiting runtime observation):
`instrument | postcall_68e52 | hover test | hover=<pending> | bio_star_slot=<pending> | briefcase=<pending> | crash=<pending> | first_writer_eip=<n/a> | dest_buffer=<n/a>`

Run row (observed):
`instrument | postcall_68e52 | hover test | hover=blank | bio_star_slot=blank | briefcase=no probe marker observed | crash=no (not reported) | first_writer_eip=<n/a> | dest_buffer=<n/a>`

Interpretation:
- Probe marker not observed in target field; target fields remained blank.
- Ownership for target fields not proven; classify `postcall_68e52` as non-owner for this pass.

### Session 1 Run 4 armed (probe apply complete)
Probe apply command:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode instrument --probe-id postcall_43bd46 --force-known-legacy \
  --json-output /tmp/pm99_s1_p4_probe_postcall_43bd46.json
```

Notes:
- `--force-known-legacy` required for guarded migration.
- Active marker for this run: `[PRB:postcall_43bd`.
- Apply JSON: `/tmp/pm99_s1_p4_probe_postcall_43bd46.json`

Run row (awaiting runtime observation):
`instrument | postcall_43bd46 | bio open | hover=<pending> | bio_star_slot=<pending> | briefcase=<pending> | crash=<pending> | first_writer_eip=<n/a> | dest_buffer=<n/a>`

### Session 1 early-stop decision (applied)
User challenged repeated probe pattern ("haven't we done this already?"). Based on cumulative evidence and current-pass results:
- `hover_field_stage3`: non-owner (marker in briefcase transfer-scout bubble)
- `bio_copy_src_43f24f`: non-owner (no marker; fields blank)
- `postcall_68e52`: non-owner (no marker; fields blank)
- `postcall_43bd46`: armed but **not executed** (superseded by early transition)

Action taken:
- Stopped remaining Session 1 marker sweeps (`postcall_43bd46`, `lookup_call_68167`, `lookup_call_681db`, `lookup_call_6824b` not executed in this pass).
- Reset EXE to stable and entered Session 2 watchpoint ownership tracing phase.

Command:
```bash
python3 scripts/research/patch_managpre_valderrama_guard.py \
  --input-exe /home/joe/pm99-research/.local/premier-manager-ninety-nine/MANAGPRE.EXE \
  --in-place --mode stable --json-output /tmp/pm99_s2_entry_stable.json
```

Hash after Session 2 entry reset:
- `b1128c3be3df18c3423dbcc44f06ae2002aae774875964df900114d25c3dc335`
