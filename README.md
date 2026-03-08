# pm99-skezmod

SkezMod is the production patch pack for PM99 binaries.

## Stable patches

- `stars_patch` (SkezMod v0.1.0):
  - target: `MANAGPRE.EXE`
  - keeps RC2 null guard at `0x0066F1FB`
  - adds `FUN_004B5C20` miss fallback hook at `0x004B5C76`
  - fallback records: `Unknown club`, `Stars`, `Free players`

## Usage

```bash
python stars_patch.py --input /path/to/MANAGPRE.EXE --output /tmp/MANAGPRE.stars_patch.EXE
```

Useful flags:

- `--in-place`
- `--dry-run`
- `--force`
- `--no-backup`
- `--json-output /tmp/stars_patch_report.json`

## Release notes

- `docs/releases/v0.1.0.md`
