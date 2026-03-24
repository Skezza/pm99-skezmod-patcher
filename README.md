# SkezMod Patcher for Premier Manager 99
SkezMod Patcher is the worlds first (as far as I know) production patchset for x86 edition of Premier Manager Ninety Nine `MANAGPRE.EXE`.
I'm looking to fix a few stability issues in the game and hopefully produce a fully functioning database editor in the future.

<img width="256" height="384" alt="image" src="https://github.com/user-attachments/assets/d28b6e6c-35ab-48f0-b8a7-1004a84e7ed1" />


## v0.1
`Stars Patch` -
Hovering over **Carlos Valderrama** or **Alexi Lalas** causes the game to crash. This happens because 10 hidden players exist in the database with **Team ID 4705**, which doesn't exist. Their team name appears as "Stars" in the player database as leftover data from an earlier PC Futbol database.

<img width="320" height="240" alt="Screenshot from 2026-03-06 22-56-52" src="https://github.com/user-attachments/assets/90b292ab-c153-4382-8302-a2747284a570" />
<img width="247" height="148" alt="Screenshot from 2026-03-07 00-27-53" src="https://github.com/user-attachments/assets/cf9dd1c0-eda9-4501-bdb8-f8d2332998b0" />

When the game tries to access the missing team, it results in a **null pointer dereference**, triggering the "Application cannot continue" crash.

This patch adds **null protection with a Team ID fallback lookup table** via a code cave, preventing the crash and patching most string references. The fallback covers 'Stars', Free players that trigger the same crash (not sure why), and "Unknown Club". The patch is comprehensive, you can access the players for transfer and sign them. 

<img width="320" height="240" alt="Screenshot from 2026-03-08 23-30-19" src="https://github.com/user-attachments/assets/9c31ccef-fd2e-452d-9cd4-1fe593b6f680" />

Patch consists of:
- Null-check at `0x0066F1FB` protecting the `0x0066F208` dereference path.
- Tail hook at `0x004B5C76` in `FUN_004B5C20`.
- Fallback lookup table for unresolved team IDs:
  - `0` -> `Unknown club`
  - `4705` -> `Stars`
  - `4706` -> `Free players`
- (Optional) Lightweight branding text update to `PM99 SkezMod 0.1`.

## To Use
Copy into your Premier Manager 99 install directory and execute skezmod.py.

Validate with `--dry-run` first.

Write JSON report:

```bash
--json-output /tmp/skezmod_report.json
```

## Optional

Skip branding, just apply patch?:

```bash
 --no-branding
```

## Release Notes
See: `docs/releases/v0.1.0.md`

## Web Self-Service (Client-Side)
The repository now includes a browser patcher in `web/` (React + TypeScript + Web Worker).

Run locally:

```bash
cd web
npm install
npm run dev
```

The web app performs signature preflight checks in-browser and downloads `MANAGPRE.skezmod.exe` after a successful patch.
