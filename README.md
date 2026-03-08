# SkezMod Patcher for Premier Manager 99
SkezMod Patcher is the worlds first (as far as I know) production patchset for x86 edition of Premier Manager Ninety Nine `MANAGPRE.EXE`.
I'm looking to fix a few stability issues in the game and hopefully produce a fully functioning database editor in the future.

### What SkezMod Patcher v0.1 Ships
`Stars Patch` -
Hovering over **Carlos Valderrama** or **Alexi Lalas** causes the game to crash. This happens because 10 hidden players exist in the database with **Team ID 4705**, which doesn't exist. Their team name appears as "Stars" in the player database as leftover data from an earlier PC Futbol database.

When the game tries to access the missing team, it results in a **null pointer dereference**, triggering the "Application cannot continue" crash.

This patch adds **null protection with a Team ID fallback lookup table** via a code cave, preventing the crash and patching most string references. The fallback covers 'Stars', Free players that trigger the same crash (not sure why), and "Unknown Club" for 0's (just being defensive)

Patch consists of:
- Null-check at `0x0066F1FB` protecting the `0x0066F208` dereference path.
- Tail hook at `0x004B5C76` in `FUN_004B5C20`.
- Fallback lookup table for unresolved team IDs:
  - `0` -> `Unknown club`
  - `4705` -> `Stars`
  - `4706` -> `Free players`
- (Optional) Lightweight branding text update to `PM99 SkezMod 0.1`.

## To Use
Copy into your Premier Manager 99 install directory and execute the python script skezmod.py.

```bash
./skezmod.py or python3 skezmod.py or py skezmod.py
```

If you are unsure whether you have the correct MANAGPRE.exe, validate with `--dry-run` first.

```bash
./skezmod.py --dry-run
```

Write JSON report:

```bash
./skezmod.py --json-output /tmp/skezmod_report.json
```

## Optional

Skip branding, just apply patch?:

```bash
./skezmod.py --no-branding
```

## Release Notes
See: `docs/releases/v0.1.0.md`
