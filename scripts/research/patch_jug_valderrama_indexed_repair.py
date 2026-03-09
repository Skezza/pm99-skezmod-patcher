#!/usr/bin/env python3
"""Repair Valderrama's indexed JUG payload using deterministic indexed-entry surgery.

Modes:
- suffix (default, safest): preserve all target bytes through end-of-name,
  copy donor suffix only.
- donor_template_fullname: donor template + preserve target alias/name window.

The default `suffix` mode avoids changing target prefix/header bytes that can
participate in game-side identity/link behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.fdi_indexed import IndexedFDIFile
from app.models import PlayerRecord
from app.xor import xor_encode

DEFAULT_JUG = REPO_ROOT / ".local" / "premier-manager-ninety-nine" / "DBDAT" / "JUG98030.FDI"


@dataclass(frozen=True)
class IndexedPlayerHit:
    record_id: int
    payload_offset: int
    payload_length: int
    name: str
    name_off: int
    payload: bytes


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _parse_player(payload: bytes, payload_offset: int) -> dict[str, Any]:
    rec = PlayerRecord.from_bytes(payload, payload_offset)
    return {
        "team_id": getattr(rec, "team_id", None),
        "nationality": getattr(rec, "nationality", None),
        "position": getattr(rec, "position", None),
        "birth_day": getattr(rec, "birth_day", None),
        "birth_month": getattr(rec, "birth_month", None),
        "birth_year": getattr(rec, "birth_year", None),
        "height": getattr(rec, "height", None),
        "weight": getattr(rec, "weight", None),
        "indexed_unknown_0": getattr(rec, "indexed_unknown_0", None),
        "indexed_unknown_1": getattr(rec, "indexed_unknown_1", None),
        "indexed_unknown_9": getattr(rec, "indexed_unknown_9", None),
        "indexed_unknown_10": getattr(rec, "indexed_unknown_10", None),
    }


def _find_indexed_hit(*, file_bytes: bytes, indexed: IndexedFDIFile, full_name: str) -> IndexedPlayerHit:
    needle = full_name.encode("cp1252", errors="strict")
    for entry in indexed.entries:
        payload = entry.decode_payload(file_bytes)
        pos = payload.find(needle)
        if pos < 0:
            continue
        return IndexedPlayerHit(
            record_id=entry.record_id,
            payload_offset=entry.payload_offset,
            payload_length=entry.payload_length,
            name=full_name,
            name_off=pos,
            payload=payload,
        )
    raise RuntimeError(f"Could not locate indexed payload containing name: {full_name}")


def _repair_suffix_mode(*, target: IndexedPlayerHit, donor: IndexedPlayerHit) -> tuple[bytes, dict[str, Any]]:
    target_name_bytes = target.name.encode("cp1252", errors="strict")
    donor_name_bytes = donor.name.encode("cp1252", errors="strict")

    if len(target.payload) != len(donor.payload):
        raise RuntimeError(
            f"Payload length mismatch: target={len(target.payload)} donor={len(donor.payload)}"
        )
    if len(target_name_bytes) != len(donor_name_bytes):
        raise RuntimeError(
            f"Name length mismatch: target={len(target_name_bytes)} donor={len(donor_name_bytes)}"
        )
    if target.name_off != donor.name_off:
        raise RuntimeError(
            f"Name offset mismatch: target={target.name_off} donor={donor.name_off}"
        )

    name_start = target.name_off
    name_end = name_start + len(target_name_bytes)

    repaired = bytearray(target.payload)
    repaired[name_end:] = donor.payload[name_end:]

    info = {
        "mode": "suffix",
        "name_start": name_start,
        "name_end": name_end,
        "target_prefix_preserved_hex": target.payload[:name_end].hex(),
        "donor_suffix_hex": donor.payload[name_end:].hex(),
    }
    return bytes(repaired), info


def _repair_donor_template_fullname_mode(
    *, target: IndexedPlayerHit, donor: IndexedPlayerHit, alias_window: int
) -> tuple[bytes, dict[str, Any]]:
    target_name_bytes = target.name.encode("cp1252", errors="strict")
    donor_name_bytes = donor.name.encode("cp1252", errors="strict")

    if len(target.payload) != len(donor.payload):
        raise RuntimeError(
            f"Payload length mismatch: target={len(target.payload)} donor={len(donor.payload)}"
        )
    if len(target_name_bytes) != len(donor_name_bytes):
        raise RuntimeError(
            f"Name length mismatch: target={len(target_name_bytes)} donor={len(donor_name_bytes)}"
        )
    if target.name_off != donor.name_off:
        raise RuntimeError(
            f"Name offset mismatch: target={target.name_off} donor={donor.name_off}"
        )

    name_start = target.name_off
    name_end = name_start + len(target_name_bytes)
    alias_start = name_start - alias_window
    if alias_start < 0:
        raise RuntimeError(
            f"Alias window underflow: name_off={name_start}, alias_window={alias_window}"
        )

    repaired = bytearray(donor.payload)
    repaired[alias_start:name_end] = target.payload[alias_start:name_end]

    info = {
        "mode": "donor_template_fullname",
        "alias_window": alias_window,
        "alias_start": alias_start,
        "name_start": name_start,
        "name_end": name_end,
        "target_identity_block_hex": target.payload[alias_start:name_end].hex(),
        "donor_identity_block_hex": donor.payload[alias_start:name_end].hex(),
    }
    return bytes(repaired), info


def apply_patch(
    *,
    jug_path: Path,
    target_name: str,
    donor_name: str,
    mode: str,
    in_place: bool,
    output_path: Path | None,
    dry_run: bool,
    backup: bool,
    alias_window: int,
) -> dict[str, Any]:
    file_bytes = jug_path.read_bytes()
    indexed = IndexedFDIFile.from_bytes(file_bytes)

    target = _find_indexed_hit(file_bytes=file_bytes, indexed=indexed, full_name=target_name)
    donor = _find_indexed_hit(file_bytes=file_bytes, indexed=indexed, full_name=donor_name)

    if mode == "suffix":
        repaired_payload, details = _repair_suffix_mode(target=target, donor=donor)
    elif mode == "donor_template_fullname":
        repaired_payload, details = _repair_donor_template_fullname_mode(
            target=target,
            donor=donor,
            alias_window=alias_window,
        )
    else:
        raise RuntimeError(f"Unsupported mode: {mode}")

    patched = bytearray(file_bytes)
    encoded_repaired = xor_encode(repaired_payload)
    patched[target.payload_offset : target.payload_offset + target.payload_length] = encoded_repaired

    target_before_parse = _parse_player(target.payload, target.payload_offset)
    target_after_parse = _parse_player(repaired_payload, target.payload_offset)
    donor_parse = _parse_player(donor.payload, donor.payload_offset)

    out_path: Path
    if in_place:
        out_path = jug_path
    else:
        out_path = output_path or Path("/tmp/JUG98030.valderrama_indexed_repaired.FDI")

    backup_path: Path | None = None
    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if in_place and backup:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = jug_path.with_name(f"{jug_path.name}.bak_valderrama_indexed_repair_{stamp}")
            shutil.copy2(jug_path, backup_path)
        out_path.write_bytes(bytes(patched))

    report: dict[str, Any] = {
        "jug_path": str(jug_path),
        "output_path": str(out_path),
        "backup_path": str(backup_path) if backup_path else None,
        "dry_run": bool(dry_run),
        "mode": mode,
        "target": {
            "name": target.name,
            "record_id": target.record_id,
            "payload_offset": target.payload_offset,
            "payload_length": target.payload_length,
            "name_off": target.name_off,
        },
        "donor": {
            "name": donor.name,
            "record_id": donor.record_id,
            "payload_offset": donor.payload_offset,
            "payload_length": donor.payload_length,
            "name_off": donor.name_off,
        },
        "repair": details,
        "parsed": {
            "target_before": target_before_parse,
            "target_after": target_after_parse,
            "donor": donor_parse,
        },
        "sha256": {
            "input": _sha256_file(jug_path),
            "patched_output": _sha256_bytes(bytes(patched)),
        },
        "notes": [
            "Indexed-entry deterministic patch (no heuristic subrecord rewrites).",
            "Payload length preserved exactly; no DMFI index offset rewrites.",
            "Default suffix mode preserves target prefix/identity bytes and patches only trailing suffix.",
        ],
    }
    return report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Repair Valderrama indexed payload shape in JUG98030.FDI")
    p.add_argument("--jug", default=str(DEFAULT_JUG), help="Path to JUG98030.FDI")
    p.add_argument("--target-name", default="Carlos VALDERRAMA", help="Target player full name")
    p.add_argument("--donor-name", default="Dmytro MIHAJLENKO", help="Donor player full name")
    p.add_argument(
        "--mode",
        choices=("suffix", "donor_template_fullname"),
        default="suffix",
        help="Repair strategy (default: suffix)",
    )
    p.add_argument(
        "--alias-window",
        type=int,
        default=12,
        help="Bytes before full name to preserve from target (donor_template_fullname mode only)",
    )
    p.add_argument("--in-place", action="store_true", help="Patch file in place")
    p.add_argument("--output", help="Output path when not using --in-place")
    p.add_argument("--dry-run", action="store_true", help="Analyze only; no file write")
    p.add_argument("--no-backup", action="store_true", help="Disable backup for --in-place writes")
    p.add_argument("--json-output", help="Optional JSON report output path")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    jug_path = Path(args.jug)
    output = Path(args.output) if args.output else None

    report = apply_patch(
        jug_path=jug_path,
        target_name=str(args.target_name),
        donor_name=str(args.donor_name),
        mode=str(args.mode),
        in_place=bool(args.in_place),
        output_path=output,
        dry_run=bool(args.dry_run),
        backup=not bool(args.no_backup),
        alias_window=int(args.alias_window),
    )

    text = json.dumps(report, indent=2)
    print(text)
    if args.json_output:
        out = Path(args.json_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
