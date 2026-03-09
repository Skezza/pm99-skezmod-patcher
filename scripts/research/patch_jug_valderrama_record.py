#!/usr/bin/env python3
"""Apply a reversible JUG98030.FDI data patch for the Valderrama crash experiment.

Strategy:
- Locate the separator-delimited subrecord containing target full name.
- Locate a donor subrecord (same subrecord length and same full-name length).
- Patch mode `suffix` (default): preserve target bytes through full-name span, replace
  suffix bytes after full name with donor suffix bytes.
- Patch mode `donor_template_fullname`: clone donor subrecord shape and write the target
  full name back into the donor template at the same span.

This is a data-only workaround experiment (no EXE changes).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.xor import decode_entry, encode_entry

SEPARATOR = bytes([0xDD, 0x63, 0x60])
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JUG = REPO_ROOT / ".local" / "premier-manager-ninety-nine" / "DBDAT" / "JUG98030.FDI"


@dataclass(frozen=True)
class LocatedSubrecord:
    entry_offset: int
    entry_length: int
    subrecord_index: int
    subrecord_relative_offset: int
    subrecord_length: int
    name_start: int
    name_end: int
    full_name: str
    bytes_data: bytes


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _iter_subrecords(file_bytes: bytes):
    offset = 0x400
    file_len = len(file_bytes)
    while offset + 2 <= file_len:
        try:
            decoded_entry, enc_len = decode_entry(file_bytes, offset)
        except Exception:
            offset += 1
            continue

        if SEPARATOR not in decoded_entry:
            offset += enc_len + 2
            continue

        starts: list[int] = []
        pos = decoded_entry.find(SEPARATOR)
        while pos != -1:
            starts.append(pos)
            pos = decoded_entry.find(SEPARATOR, pos + 1)

        for idx, start in enumerate(starts):
            end = starts[idx + 1] if idx + 1 < len(starts) else len(decoded_entry)
            seg = decoded_entry[start:end]
            if not (50 <= len(seg) <= 256):
                continue
            yield {
                "entry_offset": offset,
                "entry_length": enc_len,
                "entry_decoded": decoded_entry,
                "subrecord_index": idx,
                "subrecord_relative_offset": start,
                "subrecord_length": len(seg),
                "bytes": seg,
            }

        offset += enc_len + 2


def _locate_by_name(file_bytes: bytes, full_name: str) -> LocatedSubrecord:
    needle = full_name.encode("latin-1", errors="strict")
    for row in _iter_subrecords(file_bytes):
        seg = row["bytes"]
        name_start = seg.find(needle)
        if name_start < 0:
            continue
        name_end = name_start + len(needle)
        return LocatedSubrecord(
            entry_offset=int(row["entry_offset"]),
            entry_length=int(row["entry_length"]),
            subrecord_index=int(row["subrecord_index"]),
            subrecord_relative_offset=int(row["subrecord_relative_offset"]),
            subrecord_length=int(row["subrecord_length"]),
            name_start=name_start,
            name_end=name_end,
            full_name=full_name,
            bytes_data=bytes(seg),
        )
    raise RuntimeError(f"Could not locate subrecord containing full name: {full_name}")


def patch_file(
    *,
    jug_path: Path,
    target_name: str,
    donor_name: str,
    mode: str,
    in_place: bool,
    output_path: Path | None,
    dry_run: bool,
) -> dict[str, Any]:
    raw = jug_path.read_bytes()

    target = _locate_by_name(raw, target_name)
    donor = _locate_by_name(raw, donor_name)

    if target.subrecord_length != donor.subrecord_length:
        raise RuntimeError(
            "Target and donor subrecord lengths differ: "
            f"target={target.subrecord_length}, donor={donor.subrecord_length}"
        )

    target_name_len = target.name_end - target.name_start
    donor_name_len = donor.name_end - donor.name_start
    if target_name_len != donor_name_len:
        raise RuntimeError(
            "Target and donor full-name lengths differ: "
            f"target={target_name_len}, donor={donor_name_len}"
        )
    suffix_start = target.name_end
    target_before = bytearray(target.bytes_data)
    donor_bytes = donor.bytes_data

    target_before_hex = target_before.hex()
    donor_suffix_hex = donor_bytes[suffix_start:].hex()

    if mode == "suffix":
        # Preserve name bytes, normalize suffix bytes from donor.
        target_after = bytearray(target_before)
        target_after[suffix_start:] = donor_bytes[suffix_start:]
    elif mode == "donor_template_fullname":
        # Clone full donor shape, then restore the visible target full name.
        target_after = bytearray(donor_bytes)
        target_after[target.name_start:target.name_end] = target_before[target.name_start:target.name_end]
    else:
        raise RuntimeError(f"Unsupported patch mode: {mode}")

    target_after_hex = target_after.hex()

    # Rebuild decoded entry.
    decoded_entry, enc_len = decode_entry(raw, target.entry_offset)
    if enc_len != target.entry_length:
        raise RuntimeError("Entry length mismatch while rebuilding decoded entry")

    dec_buf = bytearray(decoded_entry)
    start = target.subrecord_relative_offset
    end = start + target.subrecord_length
    dec_buf[start:end] = target_after
    new_decoded_entry = bytes(dec_buf)

    encoded_entry = encode_entry(new_decoded_entry)
    if len(encoded_entry) != (2 + target.entry_length):
        raise RuntimeError(
            "Patched entry size changed unexpectedly; refusing variable-length rewrite"
        )

    patched_raw = bytearray(raw)
    patched_raw[target.entry_offset : target.entry_offset + len(encoded_entry)] = encoded_entry

    out_path: Path
    if in_place:
        out_path = jug_path
    else:
        out_path = output_path or Path("/tmp/JUG98030.valderrama_patched.FDI")

    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(bytes(patched_raw))

    return {
        "jug_path": str(jug_path),
        "output_path": str(out_path),
        "dry_run": bool(dry_run),
        "target": {
            "name": target.full_name,
            "entry_offset": target.entry_offset,
            "subrecord_index": target.subrecord_index,
            "subrecord_relative_offset": target.subrecord_relative_offset,
            "subrecord_length": target.subrecord_length,
            "name_start": target.name_start,
            "name_end": target.name_end,
        },
        "donor": {
            "name": donor.full_name,
            "entry_offset": donor.entry_offset,
            "subrecord_index": donor.subrecord_index,
            "subrecord_relative_offset": donor.subrecord_relative_offset,
            "subrecord_length": donor.subrecord_length,
            "name_start": donor.name_start,
            "name_end": donor.name_end,
        },
        "patch_mode": mode,
        "suffix_start": suffix_start,
        "target_before_hex": target_before_hex,
        "target_after_hex": target_after_hex,
        "donor_suffix_hex": donor_suffix_hex,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Patch Valderrama subrecord metadata in JUG98030.FDI")
    p.add_argument("--jug", default=str(DEFAULT_JUG), help="Path to JUG98030.FDI")
    p.add_argument("--target-name", default="Carlos VALDERRAMA", help="Target full name")
    p.add_argument("--donor-name", default="Christian AMOROSO", help="Safe donor full name")
    p.add_argument(
        "--mode",
        choices=("suffix", "donor_template_fullname"),
        default="suffix",
        help="Patch strategy to apply",
    )
    p.add_argument("--in-place", action="store_true", help="Patch in place")
    p.add_argument("--output", help="Output file path when not using --in-place")
    p.add_argument("--dry-run", action="store_true", help="Analyze only, do not write file")
    p.add_argument("--backup", action="store_true", help="Create timestamped backup before in-place write")
    p.add_argument("--json-output", help="Optional JSON report path")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    jug = Path(args.jug)
    out = Path(args.output) if args.output else None

    before_hash = _sha256(jug)
    backup_path = None
    if args.in_place and args.backup and not args.dry_run:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = jug.with_name(f"{jug.name}.bak_valderrama_dbpatch_{stamp}")
        shutil.copy2(jug, backup_path)

    report = patch_file(
        jug_path=jug,
        target_name=args.target_name,
        donor_name=args.donor_name,
        mode=str(args.mode),
        in_place=bool(args.in_place),
        output_path=out,
        dry_run=bool(args.dry_run),
    )

    report["sha256_before"] = before_hash
    report["backup_path"] = str(backup_path) if backup_path else None
    if args.in_place and not args.dry_run:
        report["sha256_after"] = _sha256(jug)
    elif out is not None and out.exists() and not args.dry_run:
        report["sha256_after"] = _sha256(out)
    else:
        report["sha256_after"] = before_hash

    text = json.dumps(report, indent=2)
    print(text)
    if args.json_output:
        j = Path(args.json_output)
        j.parent.mkdir(parents=True, exist_ok=True)
        j.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
