#!/usr/bin/env python3
"""Restore one indexed player payload from a known-good JUG backup.

Contract:
- deterministic single-record copy (no variable-length writes)
- source and target record payload lengths must match exactly
- defaults to restoring Carlos VALDERRAMA into local runtime JUG
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

DEFAULT_TARGET = REPO_ROOT / ".local" / "premier-manager-ninety-nine" / "DBDAT" / "JUG98030.FDI"
DEFAULT_SOURCE = (
    REPO_ROOT
    / ".local"
    / "premier-manager-ninety-nine"
    / "DBDAT"
    / "JUG98030.FDI.bak_valderrama_restore_20260307_084408"
)
DEFAULT_OUTPUT = Path("/tmp") / "JUG98030.valderrama_restored.FDI"


@dataclass(frozen=True)
class IndexedHit:
    record_id: int
    payload_offset: int
    payload_length: int
    name_offset: int
    payload: bytes


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _find_hit(file_bytes: bytes, indexed: IndexedFDIFile, full_name: str) -> IndexedHit:
    needle = full_name.encode("cp1252", errors="strict")
    for entry in indexed.entries:
        payload = entry.decode_payload(file_bytes)
        pos = payload.find(needle)
        if pos < 0:
            continue
        return IndexedHit(
            record_id=entry.record_id,
            payload_offset=entry.payload_offset,
            payload_length=entry.payload_length,
            name_offset=pos,
            payload=payload,
        )
    raise RuntimeError(f"Could not locate indexed payload containing name: {full_name}")


def _parse_payload(payload: bytes, payload_offset: int) -> dict[str, Any]:
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
        "attribute_prefix": list(getattr(rec, "attributes", [])[:3]) if getattr(rec, "attributes", None) else [],
    }


def apply_restore(
    *,
    target_jug: Path,
    source_jug: Path,
    player_name: str,
    in_place: bool,
    output_path: Path | None,
    dry_run: bool,
    make_backup: bool,
) -> dict[str, Any]:
    target_bytes = target_jug.read_bytes()
    source_bytes = source_jug.read_bytes()

    target_idx = IndexedFDIFile.from_bytes(target_bytes)
    source_idx = IndexedFDIFile.from_bytes(source_bytes)

    target_hit = _find_hit(target_bytes, target_idx, player_name)
    source_hit = _find_hit(source_bytes, source_idx, player_name)

    if target_hit.payload_length != source_hit.payload_length:
        raise RuntimeError(
            "Payload length mismatch; refusing variable-length rewrite: "
            f"target={target_hit.payload_length} source={source_hit.payload_length}"
        )

    patched = bytearray(target_bytes)
    patched[
        target_hit.payload_offset : target_hit.payload_offset + target_hit.payload_length
    ] = xor_encode(source_hit.payload)

    output_bytes = bytes(patched)

    out_path: Path
    if in_place:
        out_path = target_jug
    else:
        out_path = output_path or DEFAULT_OUTPUT

    backup_path: Path | None = None
    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if in_place and make_backup:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = target_jug.with_name(f"{target_jug.name}.bak_valderrama_restore_single_{stamp}")
            shutil.copy2(target_jug, backup_path)
        out_path.write_bytes(output_bytes)

    return {
        "target_jug": str(target_jug),
        "source_jug": str(source_jug),
        "output_jug": str(out_path),
        "backup_jug": str(backup_path) if backup_path else None,
        "dry_run": bool(dry_run),
        "player_name": player_name,
        "target": {
            "record_id": target_hit.record_id,
            "payload_offset": target_hit.payload_offset,
            "payload_length": target_hit.payload_length,
            "name_offset": target_hit.name_offset,
            "parsed_before": _parse_payload(target_hit.payload, target_hit.payload_offset),
        },
        "source": {
            "record_id": source_hit.record_id,
            "payload_offset": source_hit.payload_offset,
            "payload_length": source_hit.payload_length,
            "name_offset": source_hit.name_offset,
            "parsed_source": _parse_payload(source_hit.payload, source_hit.payload_offset),
        },
        "parsed_after": _parse_payload(source_hit.payload, target_hit.payload_offset),
        "sha256": {
            "target_input": _sha256_bytes(target_bytes),
            "source_input": _sha256_bytes(source_bytes),
            "patched_output": _sha256_bytes(output_bytes),
        },
        "notes": [
            "Single indexed payload copy by matched full-name entry.",
            "No entry-size or index-table edits are performed.",
            "Use this to undo donor-contaminated Valderrama payloads safely.",
        ],
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Restore Valderrama payload from a known-good indexed JUG backup")
    p.add_argument("--target-jug", default=str(DEFAULT_TARGET), help="Target JUG98030.FDI path")
    p.add_argument("--source-jug", default=str(DEFAULT_SOURCE), help="Source backup JUG file")
    p.add_argument("--player-name", default="Carlos VALDERRAMA", help="Player full name to restore")
    p.add_argument("--in-place", action="store_true", help="Write target file in place")
    p.add_argument("--output", help="Output path when not using --in-place")
    p.add_argument("--dry-run", action="store_true", help="Validate/preview only")
    p.add_argument("--no-backup", action="store_true", help="Disable backup creation for --in-place writes")
    p.add_argument("--json-output", help="Optional JSON report output path")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    report = apply_restore(
        target_jug=Path(args.target_jug),
        source_jug=Path(args.source_jug),
        player_name=str(args.player_name),
        in_place=bool(args.in_place),
        output_path=Path(args.output) if args.output else None,
        dry_run=bool(args.dry_run),
        make_backup=not bool(args.no_backup),
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
