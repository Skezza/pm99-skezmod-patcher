# SkezMod Patcher for Premier Manager 99

SkezMod Patcher repairs the Premier Manager 99 `Stars` database issue and applies a minimal defensive `MANAGPRE.EXE` null guard.

## Current Patch

The current deliverable is DB-first:

- Repairs the linked `Stars` team roster in `DBDAT/EQ98030.FDI` / `DBDAT/JUG98030.FDI`.
- Finds every player linked from the `Stars` roster, not just Valderrama.
- Pads short linked JUG player payloads to the runtime-safe minimum length of `80` bytes using each payload's existing trailing filler byte.
- Keeps the EXE patch surface to one null text-pointer guard in `FUN_0066F1F0` at `0x0066F1FB`.
- Does not inject Stars strings, player-id-specific formatter fallbacks, search/profile renderer hooks, or title branding into `MANAGPRE.EXE`.

The repaired `Stars` roster currently contains these 10 linked player record ids:

```text
58, 115, 8425, 16955, 17126, 20863, 20864, 20865, 20866, 20867
```

Seven of those payloads are short in the investigated database and are extended by a total of 80 bytes. Existing indexed offsets and lengths are rebuilt in `JUG98030.FDI`.

## Why This Exists

The old approach patched multiple MANAGPRE formatter/search/profile paths so the game would display `Stars` when broken database records produced blank club strings. That worked for selected surfaces, but it was the wrong long-term shape: it scattered fallback behaviour through the EXE.

The current approach repairs the database records so the game can resolve the linked `Stars` players normally, while retaining only the crash-prevention null guard as defense in depth.

## To Use

Run from your Premier Manager 99 install directory:

```bash
python3 skezmod.py --dry-run --json-output /tmp/skezmod_dry_run.json
python3 skezmod.py --json-output /tmp/skezmod_apply.json
```

By default the patcher expects:

- `MANAGPRE.EXE` or `managpre.exe` in the current directory
- `DBDAT/EQ98030.FDI`
- `DBDAT/JUG98030.FDI`

Useful flags:

```bash
--dbdat-dir /path/to/DBDAT
--skip-db-repair
--json-output /tmp/skezmod_report.json
```

`--no-branding` is still accepted for compatibility but is now a no-op because branding is no longer applied.

## Backups

On apply, the patcher uses a staged EXE flow:

```text
MANAGPRE.EXE -> MANAGPRE.original.exe
MANAGPRE.skezmod.exe -> MANAGPRE.EXE
```

The player database receives its own backup before write:

```text
DBDAT/JUG98030.FDI.skezmod-original
```

## Release Notes

See: `docs/releases/v0.2.0.md`
