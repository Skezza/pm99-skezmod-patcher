#!/usr/bin/env python3
"""Repair JUG player team IDs for one EQ-linked team cluster (default: Stars).

This script performs deterministic indexed payload rewrites only:
- resolves one EQ-linked roster (e.g. Stars),
- resolves one canonical team_id from EQ team records,
- patches bytes 0x00..0x01 (team_id LE) in JUG indexed payloads for that roster's PIDs,
- keeps payload/index lengths unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DB_EDITOR_ROOT = REPO_ROOT.parent / "pm99-skezmod-db-editor"

for candidate in (REPO_ROOT, DB_EDITOR_ROOT):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from app.eq_jug_linked import EQLinkedTeamRoster, load_eq_linked_team_rosters
from app.fdi_indexed import IndexedFDIEntry, IndexedFDIFile
from app.loaders import load_teams
from app.models import PlayerRecord
from app.xor import xor_encode


DEFAULT_KNOWN_GOOD_JUG = Path(
    "/home/joe/pm99-research/.local/premier-manager-ninety-nine/DBDAT/"
    "JUG98030.FDI.bak_valderrama_restore_20260307_084408"
)
DEFAULT_OUTPUT_JUG = Path("/tmp/JUG98030.stars_teamid_repair.FDI")


@dataclass(frozen=True)
class RosterSelection:
    roster: EQLinkedTeamRoster
    matched_count: int


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _norm(text: str) -> str:
    return " ".join((text or "").strip().lower().split())


def _select_roster(rosters: list[EQLinkedTeamRoster], team_query: str) -> RosterSelection:
    q = _norm(team_query)
    matches: list[EQLinkedTeamRoster] = []
    for roster in rosters:
        short_name = _norm(roster.short_name)
        full_name = _norm(roster.full_club_name)
        if q and (q in short_name or q in full_name):
            matches.append(roster)

    if not matches:
        raise RuntimeError(f"No EQ-linked roster matched team query: {team_query!r}")
    if len(matches) > 1:
        ids = ", ".join(str(item.eq_record_id) for item in matches[:8])
        raise RuntimeError(
            f"Ambiguous EQ-linked roster match for {team_query!r}: {len(matches)} candidates "
            f"(eq_record_ids: {ids})"
        )
    return RosterSelection(roster=matches[0], matched_count=len(matches))


def _resolve_canonical_team_id(eq_path: Path, team_query: str, roster: EQLinkedTeamRoster) -> tuple[int, list[dict[str, Any]]]:
    q = _norm(team_query)
    short_q = _norm(roster.short_name)
    full_q = _norm(roster.full_club_name)
    candidates: list[dict[str, Any]] = []

    for offset, team in load_teams(str(eq_path)):
        team_id_raw = getattr(team, "team_id", None)
        try:
            team_id = int(team_id_raw) if team_id_raw is not None else None
        except Exception:
            team_id = None
        short_name = str(getattr(team, "name", "") or "")
        full_name = str(getattr(team, "full_club_name", "") or "")
        short_norm = _norm(short_name)
        full_norm = _norm(full_name)

        matched = False
        if q and (q in short_norm or q in full_norm):
            matched = True
        if short_q and (short_q == short_norm or short_q == full_norm):
            matched = True
        if full_q and (full_q == short_norm or full_q == full_norm):
            matched = True

        if matched:
            candidates.append(
                {
                    "offset": int(offset),
                    "team_id": team_id,
                    "short_name": short_name,
                    "full_club_name": full_name,
                }
            )

    valid_team_ids = sorted({int(item["team_id"]) for item in candidates if item.get("team_id") not in (None, 0)})
    if not valid_team_ids:
        raise RuntimeError(f"Could not resolve non-zero team_id for team query: {team_query!r}")
    if len(valid_team_ids) != 1:
        raise RuntimeError(
            f"Ambiguous canonical team_id for {team_query!r}: {valid_team_ids} "
            f"(from {len(candidates)} candidate team records)"
        )

    canonical = int(valid_team_ids[0])
    if not (1 <= canonical <= 5000):
        raise RuntimeError(f"Resolved team_id out of expected range (1..5000): {canonical}")
    return canonical, candidates


def _build_entry_map(indexed: IndexedFDIFile) -> dict[int, IndexedFDIEntry]:
    return {int(entry.record_id): entry for entry in indexed.entries}


def _decoded_payload(file_bytes: bytes, entry: IndexedFDIEntry) -> bytes:
    return entry.decode_payload(file_bytes)


def _team_id_from_payload(payload: bytes, payload_offset: int) -> int:
    record = PlayerRecord.from_bytes(payload, payload_offset)
    value = getattr(record, "team_id", 0)
    return int(value) if value is not None else 0


def _name_from_payload(payload: bytes, payload_offset: int) -> str:
    record = PlayerRecord.from_bytes(payload, payload_offset)
    return str(getattr(record, "name", "") or "").strip()


def _patched_team_payload(payload: bytes, team_id: int) -> bytes:
    if len(payload) < 2:
        raise RuntimeError(f"Payload too short to patch team_id: length={len(payload)}")
    out = bytearray(payload)
    out[0:2] = struct.pack("<H", int(team_id))
    return bytes(out)


def apply_repair(
    *,
    jug_path: Path,
    eq_path: Path,
    team_query: str,
    known_good_jug_path: Path,
    primary_player_id: int,
    output_jug_path: Path,
    in_place: bool,
    dry_run: bool,
    make_backup: bool,
) -> dict[str, Any]:
    jug_bytes = jug_path.read_bytes()
    eq_rosters = load_eq_linked_team_rosters(str(eq_path), player_file=str(jug_path))
    selection = _select_roster(eq_rosters, team_query)
    roster = selection.roster

    canonical_team_id, team_candidates = _resolve_canonical_team_id(eq_path, team_query, roster)

    target_pids = sorted({int(row.player_record_id) for row in roster.rows})
    if not target_pids:
        raise RuntimeError(f"Roster {roster.eq_record_id} resolved no player IDs")

    indexed_live = IndexedFDIFile.from_bytes(jug_bytes)
    live_entry_map = _build_entry_map(indexed_live)

    missing = [pid for pid in target_pids if pid not in live_entry_map]
    if missing:
        raise RuntimeError(f"Missing target player IDs in live JUG: {missing}")

    known_good_bytes = known_good_jug_path.read_bytes()
    indexed_known = IndexedFDIFile.from_bytes(known_good_bytes)
    known_entry_map = _build_entry_map(indexed_known)
    if primary_player_id not in known_entry_map:
        raise RuntimeError(
            f"Primary player {primary_player_id} not found in known-good JUG: {known_good_jug_path}"
        )
    if primary_player_id not in live_entry_map:
        raise RuntimeError(f"Primary player {primary_player_id} not found in live JUG: {jug_path}")

    live_primary = live_entry_map[primary_player_id]
    known_primary = known_entry_map[primary_player_id]
    if int(live_primary.payload_length) != int(known_primary.payload_length):
        raise RuntimeError(
            "Known-good/live payload length mismatch for primary player "
            f"{primary_player_id}: live={live_primary.payload_length} known={known_primary.payload_length}"
        )

    output_bytes = bytearray(jug_bytes)
    detail_rows: list[dict[str, Any]] = []

    name_by_pid = {int(row.player_record_id): str(row.player_name or "").strip() for row in roster.rows}

    for pid in target_pids:
        live_entry = live_entry_map[pid]
        live_payload = _decoded_payload(jug_bytes, live_entry)
        old_team_id = _team_id_from_payload(live_payload, live_entry.payload_offset)

        source_payload = "live"
        baseline_payload = live_payload
        if pid == int(primary_player_id):
            known_payload = _decoded_payload(known_good_bytes, known_primary)
            if len(known_payload) != len(live_payload):
                raise RuntimeError(
                    f"Primary payload size mismatch after decode for {pid}: "
                    f"live={len(live_payload)} known={len(known_payload)}"
                )
            baseline_payload = known_payload
            source_payload = "known_good"

        patched_payload = _patched_team_payload(baseline_payload, canonical_team_id)
        if len(patched_payload) != int(live_entry.payload_length):
            raise RuntimeError(
                f"Variable-length rewrite refused for player {pid}: "
                f"patched={len(patched_payload)} live_len={live_entry.payload_length}"
            )

        encoded_payload = xor_encode(patched_payload)
        if len(encoded_payload) != int(live_entry.payload_length):
            raise RuntimeError(
                f"Encoded payload length mismatch for player {pid}: "
                f"encoded={len(encoded_payload)} expected={live_entry.payload_length}"
            )

        out_start = int(live_entry.payload_offset)
        out_end = out_start + int(live_entry.payload_length)
        output_bytes[out_start:out_end] = encoded_payload

        new_team_id = _team_id_from_payload(patched_payload, live_entry.payload_offset)
        if new_team_id != int(canonical_team_id):
            raise RuntimeError(
                f"Post-patch parse mismatch for player {pid}: new_team_id={new_team_id} "
                f"expected={canonical_team_id}"
            )

        parsed_name = _name_from_payload(patched_payload, live_entry.payload_offset)
        detail_rows.append(
            {
                "record_id": int(pid),
                "player_name": name_by_pid.get(pid) or parsed_name,
                "payload_offset": int(live_entry.payload_offset),
                "payload_length": int(live_entry.payload_length),
                "source_payload": source_payload,
                "old_team_id": int(old_team_id),
                "new_team_id": int(new_team_id),
                "before_payload_sha256": _sha256_bytes(live_payload),
                "after_payload_sha256": _sha256_bytes(patched_payload),
            }
        )

    output_data = bytes(output_bytes)
    backup_path: Path | None = None
    if in_place:
        target_output = jug_path
    else:
        target_output = output_jug_path

    if not dry_run:
        target_output.parent.mkdir(parents=True, exist_ok=True)
        if in_place and make_backup:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = jug_path.with_name(f"{jug_path.name}.bak_stars_teamid_repair_{stamp}")
            shutil.copy2(jug_path, backup_path)
        target_output.write_bytes(output_data)

    primary_before_team = next(
        (int(item["old_team_id"]) for item in detail_rows if int(item["record_id"]) == int(primary_player_id)),
        None,
    )
    primary_after_team = next(
        (int(item["new_team_id"]) for item in detail_rows if int(item["record_id"]) == int(primary_player_id)),
        None,
    )

    return {
        "jug_path": str(jug_path),
        "eq_path": str(eq_path),
        "known_good_jug_path": str(known_good_jug_path),
        "output_jug_path": str(target_output),
        "backup_path": str(backup_path) if backup_path else None,
        "dry_run": bool(dry_run),
        "in_place": bool(in_place),
        "team_query": str(team_query),
        "primary_player_id": int(primary_player_id),
        "preflight": {
            "matched_rosters_count": int(selection.matched_count),
            "eq_record_id": int(roster.eq_record_id),
            "roster_short_name": str(roster.short_name),
            "roster_full_club_name": str(roster.full_club_name),
            "stars_linked_player_ids": target_pids,
            "resolved_canonical_team_id": int(canonical_team_id),
            "canonical_team_candidates": team_candidates,
            "primary_before_team_id": primary_before_team,
            "primary_after_team_id": primary_after_team,
        },
        "players": detail_rows,
        "sha256": {
            "input_jug": _sha256_bytes(jug_bytes),
            "output_jug": _sha256_bytes(output_data),
            "known_good_jug": _sha256_bytes(known_good_bytes),
        },
        "notes": [
            "Stars-cluster-only repair based on EQ-linked roster ownership.",
            "Only indexed payload bytes 0x00..0x01 (team_id) are changed for target PIDs.",
            "No variable-length writes and no DMFI index-table rewrites are performed.",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Repair JUG team_id values for one EQ-linked team cluster (default: Stars)"
    )
    parser.add_argument("--jug", required=True, help="Live JUG98030.FDI path")
    parser.add_argument("--eq", required=True, help="Live EQ98030.FDI path")
    parser.add_argument("--team-query", default="Stars", help="Team query filter (default: Stars)")
    parser.add_argument(
        "--known-good-jug",
        default=str(DEFAULT_KNOWN_GOOD_JUG),
        help="Known-good JUG backup path for primary-player baseline",
    )
    parser.add_argument(
        "--primary-player-id",
        type=int,
        default=20864,
        help="Primary player record ID to baseline from known-good payload (default: 20864)",
    )
    parser.add_argument(
        "--output-jug",
        default=str(DEFAULT_OUTPUT_JUG),
        help="Staged output JUG path when not using --in-place",
    )
    parser.add_argument("--in-place", action="store_true", help="Write directly to --jug")
    parser.add_argument("--dry-run", action="store_true", help="Validate only; do not write output")
    parser.add_argument("--no-backup", action="store_true", help="Disable backup creation for --in-place writes")
    parser.add_argument("--json-output", help="Optional report output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = apply_repair(
        jug_path=Path(args.jug),
        eq_path=Path(args.eq),
        team_query=str(args.team_query),
        known_good_jug_path=Path(args.known_good_jug),
        primary_player_id=int(args.primary_player_id),
        output_jug_path=Path(args.output_jug),
        in_place=bool(args.in_place),
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
