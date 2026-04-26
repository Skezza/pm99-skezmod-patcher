v0.2.0 (2026-04-26): Reworked the Stars fix into a DB-first repair. The patcher now pads every short linked player payload from the Stars EQ roster in `JUG98030.FDI` and reduces the EXE patch surface to the single `FUN_0066F1F0` null text-pointer guard. Old formatter/search/profile fallback hooks are no longer part of the deliverable.

v0.1.1 (2026-04-22): Scaled the Stars patch beyond Valderrama-only signing text. The `{S3}` formatter fallback now resolves the event team through the central team lookup, and the player-record special-club renderer now backfills blank `0x26AC` club text with `Stars` for Lalas/Stars records.

v0.1.0 (2026-03-08): First production SkezMod Stars Patch release with RC2+ hover-crash fix, defensive staged patch flow, optional `--no-branding`, lowercase `managpre.exe` fallback, and GPLv3 licensing.
