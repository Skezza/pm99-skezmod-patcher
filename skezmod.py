#!/usr/bin/env python3
"""SkezMod DB repair plus scoped MANAGPRE.EXE guards.

The scalable display fix is database-side: find the linked ``Stars`` team
roster in ``DBDAT/EQ98030.FDI``, move it off the runtime-special ``0x26AC``
record id, and pad every short linked player payload in ``DBDAT/JUG98030.FDI``
to the runtime-safe minimum length observed during the investigation.

The retained EXE surface is intentionally narrow:
- a null-pointer guard for the legacy text reader crash path;
- a formatter-local ``{S3}`` fallback for signing news where MANAGPRE supplies
  a null club argument before the formatter runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

ASCII_BRAND = (
    "############################################################\n"
    "#   _____ _  _______ ______ __  __  ____  _____            #\n"
    "#  / ____| |/ / ____|___  /|  \\/  |/ __ \\|  __ \\           #\n"
    "# | (___ | ' /| |__     / /| \\  / | |  | | |  | |          #\n"
    "#  \\___ \\|  < |  __|   / / | |\\/| | |  | | |  | |          #\n"
    "#  ____) | . \\| |____ / /_ | |  | | |__| | |__| |          #\n"
    "# |_____/|_|\\_\\______/_____|_|  |_|\\____/|_____/           #\n"
    "#       Premier Manager 99 SkezMod DB Repair + Guard        #\n"
    "############################################################"
)

DEFAULT_INPUT_EXE = Path("MANAGPRE.EXE")
FALLBACK_INPUT_EXE = Path("managpre.exe")
DEFAULT_OUTPUT_NAME = "MANAGPRE.skezmod.exe"
DEFAULT_BACKUP_NAME = "MANAGPRE.original.exe"
DEFAULT_DBDAT_DIR = Path("DBDAT")
IMAGE_BASE = 0x400000
FDI_SIGNATURE = b"DMFIv1.0"
FDI_INDEX_START = 0x14
XOR_KEY = 0x61
STARS_TEAM_NAME = "Stars"
MIN_LINKED_PLAYER_PAYLOAD_LENGTH = 80
STARS_BROKEN_EQ_RECORD_ID = 0x26AC
STARS_SAFE_EQ_RECORD_ID = 9899
STARS_STRING_VA = 0x006E519A
FORMATTER_S3_SITE_VA = 0x00499DA1
FORMATTER_S3_SITE_ORIGINAL = bytes.fromhex("8b451885c00f84c4000000")
FORMATTER_S3_ORIGINAL_PUSH_VA = 0x00499E62
FORMATTER_S3_ORIGINAL_SKIP_VA = 0x00499E70
FORMATTER_S3_STAGE0_VA = 0x006E4251
FORMATTER_S3_STAGE0_SIZE = 15
FORMATTER_S3_STAGE1_VA = 0x006E42D1
FORMATTER_S3_STAGE1_SIZE = 15
FORMATTER_S3_STAGE2_VA = 0x006E42F5
FORMATTER_S3_STAGE2_SIZE = 11
FORMATTER_S3_SKIP_VA = 0x006E4E85
FORMATTER_S3_SKIP_SIZE = 11
FORMATTER_S3_TEAM_LOOKUP1_VA = 0x006E4DF2
FORMATTER_S3_TEAM_LOOKUP1_SIZE = 14
FORMATTER_S3_TEAM_LOOKUP2_VA = 0x006E4E22
FORMATTER_S3_TEAM_LOOKUP2_SIZE = 14
TEAM_LOOKUP_VA = 0x004B5C20
VALDERRAMA_PLAYER_RECORD_ID = 20864


@dataclass(frozen=True)
class NullGuardSpec:
    name: str
    site_va: int
    site_original: bytes
    cave_va: int
    resume_va: int
    null_target_va: int


NULL_GUARD = NullGuardSpec(
    name="guard_null_textptr_FUN_0066F1F0_only",
    site_va=0x0066F1FB,
    site_original=bytes.fromhex("8b4c242033f68a472033d28be88a01"),
    cave_va=0x006E51C0,
    resume_va=0x0066F20A,
    null_target_va=0x0066F243,
)


@dataclass(frozen=True)
class RestoreSite:
    name: str
    site_va: int
    original: bytes
    alternates: tuple[bytes, ...]


@dataclass(frozen=True)
class CaveRestoreRange:
    name: str
    start_va: int
    original_fill: bytes


@dataclass(frozen=True)
class IndexedFDIEntry:
    record_id: int
    key: str
    payload_offset: int
    payload_length: int
    index_offset: int

    def decode_payload(self, file_bytes: bytes) -> bytes:
        end = self.payload_offset + self.payload_length
        if self.payload_offset < 0 or end > len(file_bytes):
            raise ValueError(f"Indexed payload for record {self.record_id} is outside file bounds")
        return _xor(file_bytes[self.payload_offset:end])


@dataclass(frozen=True)
class IndexedFDIFile:
    entries: list[IndexedFDIEntry]
    index_end_offset: int


@dataclass(frozen=True)
class LinkedRosterRow:
    slot_index: int
    flag: int
    player_record_id: int


@dataclass(frozen=True)
class LinkedTeamRoster:
    eq_record_id: int
    short_name: str
    stadium_name: str
    full_club_name: str
    record_size: int
    mode_byte: int
    ent_count: int
    rows: list[LinkedRosterRow]


def _sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _xor(data: bytes, key: int = XOR_KEY) -> bytes:
    return bytes(byte ^ key for byte in data)


def _read_sections(pe_bytes: bytes) -> list[dict[str, int]]:
    if pe_bytes[:2] != b"MZ":
        raise ValueError("Input is not an MZ executable")
    pe_off = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if pe_bytes[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise ValueError("Input does not contain a valid PE header")

    section_count = struct.unpack_from("<H", pe_bytes, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", pe_bytes, pe_off + 20)[0]
    section_off = pe_off + 24 + opt_size
    sections: list[dict[str, int]] = []
    for i in range(section_count):
        off = section_off + i * 40
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", pe_bytes, off + 8)
        sections.append(
            {
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_ptr": raw_ptr,
                "raw_size": raw_size,
            }
        )
    return sections


def _va_to_file_offset(pe_bytes: bytes, va: int) -> int:
    rva = va - IMAGE_BASE
    for sec in _read_sections(pe_bytes):
        start = sec["virtual_address"]
        size = max(sec["virtual_size"], sec["raw_size"])
        end = start + size
        if start <= rva < end:
            return sec["raw_ptr"] + (rva - start)
    raise ValueError(f"VA 0x{va:08X} does not map to a file-backed section")


def _rel32(from_va: int, instr_len: int, to_va: int) -> bytes:
    return struct.pack("<i", to_va - (from_va + instr_len))


def _build_trampoline(src_va: int, dst_va: int, total_len: int) -> bytes:
    if total_len < 5:
        raise ValueError("Trampoline region must be at least 5 bytes")
    return b"\xE9" + struct.pack("<i", dst_va - (src_va + 5)) + (b"\x90" * (total_len - 5))


def _build_call(src_va: int, dst_va: int) -> bytes:
    return b"\xE8" + _rel32(src_va, 5, dst_va)


def _build_null_guard_stub(spec: NullGuardSpec = NULL_GUARD) -> bytes:
    out = bytearray()
    # Replay overwritten setup, then guard immediately before MOV AL,[ECX].
    out += bytes.fromhex("8b4c242033f68a472033d28be8")
    out += b"\x85\xC9"  # test ecx, ecx
    jz_va = spec.cave_va + len(out)
    out += b"\x0F\x84" + _rel32(jz_va, 6, spec.null_target_va)
    out += b"\x8A\x01"  # original faulting read
    jmp_va = spec.cave_va + len(out)
    out += b"\xE9" + _rel32(jmp_va, 5, spec.resume_va)
    return bytes(out)


def _build_obsolete_empty_text_null_guard_stub() -> bytes:
    out = bytearray()
    out += bytes.fromhex("8b4c242033f68a472033d28be8")
    out += b"\x85\xC9"
    jnz_pos = len(out)
    out += b"\x0F\x85" + b"\x00\x00\x00\x00"
    out += b"\xB9" + struct.pack("<I", 0x006E5199)
    continue_va = NULL_GUARD.cave_va + len(out)
    out += b"\x8A\x01"
    jmp_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"
    out[jnz_pos + 2:jnz_pos + 6] = _rel32(NULL_GUARD.cave_va + jnz_pos, 6, continue_va)
    out[jmp_pos + 1:jmp_pos + 5] = _rel32(NULL_GUARD.cave_va + jmp_pos, 5, NULL_GUARD.resume_va)
    return bytes(out)


def _build_formatter_s3_team_lookup_stages() -> tuple[bytes, bytes, bytes]:
    """Older retained variant: null {S3} resolved by event/team id lookup."""
    stage0 = bytearray()
    stage0 += b"\x8B\x45\x18"  # mov eax,[ebp+0x18]
    stage0 += b"\x85\xC0"  # test eax,eax
    jz_stage1_pos = len(stage0)
    stage0 += b"\x74\x00"
    stage0 += b"\xE9" + _rel32(FORMATTER_S3_STAGE0_VA + len(stage0), 5, FORMATTER_S3_ORIGINAL_PUSH_VA)
    stage0[jz_stage1_pos + 1] = (FORMATTER_S3_STAGE1_VA - (FORMATTER_S3_STAGE0_VA + jz_stage1_pos + 2)) & 0xFF

    stage1 = bytearray()
    stage1 += b"\xB9\xE0\x4B\x75\x00"  # mov ecx,0x754be0
    stage1 += b"\xFF\x75\x0C"  # push dword ptr [ebp+0x0c]
    stage1 += b"\xE8" + _rel32(FORMATTER_S3_STAGE1_VA + len(stage1), 5, TEAM_LOOKUP_VA)
    stage1 += b"\xEB\x00"
    stage1[-1] = (FORMATTER_S3_STAGE2_VA - (FORMATTER_S3_STAGE1_VA + len(stage1))) & 0xFF

    stage2 = bytearray()
    stage2 += b"\x8B\x40\x04"  # mov eax,[eax+0x04]
    stage2 += b"\xE9" + _rel32(FORMATTER_S3_STAGE2_VA + len(stage2), 5, FORMATTER_S3_ORIGINAL_PUSH_VA)
    return bytes(stage0), bytes(stage1), bytes(stage2)


def _build_formatter_s3_valderrama_stages() -> tuple[bytes, bytes, bytes]:
    """Older v0.1 compatibility variant: null {S3} only for Valderrama."""
    stage0 = bytearray()
    stage0 += b"\x8B\x45\x18"
    stage0 += b"\x85\xC0"
    jz_stage1_pos = len(stage0)
    stage0 += b"\x74\x00"
    stage0 += b"\xE9" + _rel32(FORMATTER_S3_STAGE0_VA + len(stage0), 5, FORMATTER_S3_ORIGINAL_PUSH_VA)
    stage0[jz_stage1_pos + 1] = (FORMATTER_S3_STAGE1_VA - (FORMATTER_S3_STAGE0_VA + jz_stage1_pos + 2)) & 0xFF

    stage1 = bytearray()
    stage1 += b"\x81\x7D\x08" + struct.pack("<I", VALDERRAMA_PLAYER_RECORD_ID)
    je_stage2_pos = len(stage1)
    stage1 += b"\x74\x00"
    stage1 += b"\xE9" + _rel32(FORMATTER_S3_STAGE1_VA + len(stage1), 5, FORMATTER_S3_ORIGINAL_SKIP_VA)
    stage1[je_stage2_pos + 1] = (FORMATTER_S3_STAGE2_VA - (FORMATTER_S3_STAGE1_VA + je_stage2_pos + 2)) & 0xFF

    stage2 = bytearray()
    stage2 += b"\xB8" + struct.pack("<I", STARS_STRING_VA)
    stage2 += b"\xE9" + _rel32(FORMATTER_S3_STAGE2_VA + len(stage2), 5, FORMATTER_S3_ORIGINAL_PUSH_VA)
    return bytes(stage0), bytes(stage1), bytes(stage2)


def _build_formatter_s3_zero_team_stars_fallback() -> tuple[bytes, bytes, bytes, tuple[tuple[str, int, int, bytes], ...]]:
    """Scalable null-{S3} fallback for signing-notice style events.

    Non-null formatter input is untouched. Nonzero event/team ids are resolved
    through the central lookup. The broken Stars signing feed reaches the
    formatter with both {S3} and the event team id set to null/zero, so that
    narrow case receives the literal Stars club suffix.
    """
    stage0 = bytearray()
    stage0 += b"\x8B\x45\x18"  # mov eax,[ebp+0x18]
    stage0 += b"\x85\xC0"  # test eax,eax
    jz_stage1_pos = len(stage0)
    stage0 += b"\x74\x00"
    stage0 += b"\xE9" + _rel32(FORMATTER_S3_STAGE0_VA + len(stage0), 5, FORMATTER_S3_ORIGINAL_PUSH_VA)
    stage0[jz_stage1_pos + 1] = (FORMATTER_S3_STAGE1_VA - (FORMATTER_S3_STAGE0_VA + jz_stage1_pos + 2)) & 0xFF

    stage1 = bytearray()
    stage1 += b"\x83\x7D\x0C\x00"  # cmp dword ptr [ebp+0x0c],0
    je_stage2_pos = len(stage1)
    stage1 += b"\x74\x00"
    stage1 += b"\x8B\x45\x0C"  # mov eax,[ebp+0x0c]
    stage1 += b"\xE9" + _rel32(FORMATTER_S3_STAGE1_VA + len(stage1), 5, FORMATTER_S3_TEAM_LOOKUP1_VA)
    stage1[je_stage2_pos + 1] = (FORMATTER_S3_STAGE2_VA - (FORMATTER_S3_STAGE1_VA + je_stage2_pos + 2)) & 0xFF

    stage2 = bytearray()
    stage2 += b"\xB8" + struct.pack("<I", STARS_STRING_VA)
    stage2 += b"\xE9" + _rel32(FORMATTER_S3_STAGE2_VA + len(stage2), 5, FORMATTER_S3_ORIGINAL_PUSH_VA)

    skip = bytearray()
    skip += b"\xE9" + _rel32(FORMATTER_S3_SKIP_VA, 5, FORMATTER_S3_ORIGINAL_SKIP_VA)

    team_lookup1 = bytearray()
    team_lookup1 += b"\xB9\xE0\x4B\x75\x00"  # mov ecx,0x754be0
    team_lookup1 += b"\x50"  # push eax
    team_lookup1 += b"\xE8" + _rel32(FORMATTER_S3_TEAM_LOOKUP1_VA + len(team_lookup1), 5, TEAM_LOOKUP_VA)
    team_lookup1 += b"\xEB\x00"
    team_lookup1[-1] = (FORMATTER_S3_TEAM_LOOKUP2_VA - (FORMATTER_S3_TEAM_LOOKUP1_VA + len(team_lookup1))) & 0xFF

    team_lookup2 = bytearray()
    team_lookup2 += b"\x85\xC0"  # test eax,eax
    team_lookup2 += b"\x74\x00"  # jz -> skip
    team_lookup2 += b"\x8B\x40\x04"  # mov eax,[eax+0x04]
    team_lookup2 += b"\xE9" + _rel32(FORMATTER_S3_TEAM_LOOKUP2_VA + len(team_lookup2), 5, FORMATTER_S3_ORIGINAL_PUSH_VA)
    team_lookup2[3] = (FORMATTER_S3_SKIP_VA - (FORMATTER_S3_TEAM_LOOKUP2_VA + 4)) & 0xFF

    extras = (
        ("write_formatter_s3_skip_cave", FORMATTER_S3_SKIP_VA, FORMATTER_S3_SKIP_SIZE, bytes(skip)),
        ("write_formatter_s3_team_lookup1_cave", FORMATTER_S3_TEAM_LOOKUP1_VA, FORMATTER_S3_TEAM_LOOKUP1_SIZE, bytes(team_lookup1)),
        ("write_formatter_s3_team_lookup2_cave", FORMATTER_S3_TEAM_LOOKUP2_VA, FORMATTER_S3_TEAM_LOOKUP2_SIZE, bytes(team_lookup2)),
    )
    return bytes(stage0), bytes(stage1), bytes(stage2), extras


def _known_old_exe_restore_sites() -> list[RestoreSite]:
    orig_search = bytes.fromhex("e8d51204008b4004")
    orig_transfer_a = bytes.fromhex("e8d8b3fbff8b4004")
    orig_transfer_b = bytes.fromhex("e887a6fbff8b4004")
    unpatched_lookup = bytes.fromhex("395810740233c0")
    null_trampoline = _build_trampoline(NULL_GUARD.site_va, NULL_GUARD.cave_va, len(NULL_GUARD.site_original))
    return [
        RestoreSite("restore_obsolete_lookup_search_FUN_00474870", 0x00474946, orig_search, (_build_trampoline(0x00474946, 0x006E5092, len(orig_search)),)),
        RestoreSite("restore_obsolete_lookup_transfer_FUN_004FA000", 0x004FA843, orig_transfer_a, (_build_trampoline(0x004FA843, 0x006E50EB, len(orig_transfer_a)),)),
        RestoreSite("restore_obsolete_lookup_transfer_FUN_004FAC80", 0x004FB594, orig_transfer_b, (_build_trampoline(0x004FB594, 0x006E5142, len(orig_transfer_b)),)),
        RestoreSite("restore_obsolete_signing_multiyear_hook_FUN_004B8B40", 0x004B8C2E, bytes.fromhex("25ffff0000"), (_build_call(0x004B8C2E, 0x006E51E1), _build_call(0x004B8C2E, 0x006E5092))),
        RestoreSite("restore_obsolete_signing_multiyear_hook_FUN_004B8E20", 0x004B8EFA, bytes.fromhex("25ffff0000"), (_build_call(0x004B8EFA, 0x006E51E1), _build_call(0x004B8EFA, 0x006E5092))),
        RestoreSite("restore_obsolete_source_wrapper_FUN_004B8B40_multiyear", 0x004B8C3D, _build_call(0x004B8C3D, 0x004A4720), (_build_call(0x004B8C3D, 0x006E5092),)),
        RestoreSite("restore_obsolete_source_wrapper_FUN_004B8B40_oneyear", 0x004B8C73, _build_call(0x004B8C73, 0x004A4720), (_build_call(0x004B8C73, 0x006E5092),)),
        RestoreSite("restore_obsolete_source_wrapper_FUN_004B8E20_multiyear", 0x004B8F09, _build_call(0x004B8F09, 0x004A4720), (_build_call(0x004B8F09, 0x006E5092),)),
        RestoreSite("restore_obsolete_source_wrapper_FUN_004B8E20_oneyear", 0x004B8F3F, _build_call(0x004B8F3F, 0x004A4720), (_build_call(0x004B8F3F, 0x006E5092),)),
        RestoreSite(
            "restore_obsolete_lookup_result_fallback_FUN_004B5C20",
            0x004B5C76,
            unpatched_lookup,
            (
                bytes.fromhex("395810740933c0"),
                _build_trampoline(0x004B5C76, 0x006E5092, len(unpatched_lookup)),
                _build_trampoline(0x004B5C76, 0x006E50F4, len(unpatched_lookup)),
                _build_trampoline(0x004B5C76, 0x006E5108, len(unpatched_lookup)),
                _build_trampoline(0x004B5C76, 0x006E50E3, len(unpatched_lookup)),
                _build_trampoline(0x004B5C76, 0x006E50E4, len(unpatched_lookup)),
            ),
        ),
        RestoreSite("restore_obsolete_lookup_hook_block", 0x004B5C84, bytes.fromhex("909090909090909090909090"), (bytes.fromhex("e878ee2200e9efffffff9090"),)),
        RestoreSite(
            "restore_obsolete_search_hover_hook_FUN_00405F30",
            0x00406116,
            bytes.fromhex("668b4618663dac2675058b4610eb1325ffff0000b9e04b750050e8ebfa0a008b4004"),
            (_build_trampoline(0x00406116, 0x006E5145, 34),),
        ),
        RestoreSite("restore_obsolete_profile_special_club_hook_FUN_0043EBD0", 0x0043F20F, bytes.fromhex("8b4710eb21"), (_build_trampoline(0x0043F20F, 0x006E51E1, 5),)),
        RestoreSite("restore_obsolete_title_brand_primary", 0x006FC658, b"PREMIER MANAGER 99\x00", (b"PM99 SkezMod 0.1\x00",)),
        RestoreSite("restore_obsolete_title_brand_secondary", 0x006FC670, b"PREMIER MANAGER 99\x00", (b"PM99 SkezMod 0.1\x00",)),
    ]


def _known_old_cave_restore_ranges() -> list[CaveRestoreRange]:
    return [
        CaveRestoreRange("clear_obsolete_lookup_fallback_bundle_cave", 0x006E5092, b"\x00" * 302),
        CaveRestoreRange("clear_obsolete_profile_special_team_cave", 0x006E51E1, b"\x00" * 31),
    ]


def _parse_indexed_fdi(data: bytes) -> IndexedFDIFile:
    if len(data) < FDI_INDEX_START:
        raise ValueError("File too small for indexed FDI header")
    if data[:8] != FDI_SIGNATURE:
        raise ValueError(f"Invalid indexed FDI signature: {data[:8]!r}")
    record_count = struct.unpack_from("<I", data, 0x10)[0]
    entries: list[IndexedFDIEntry] = []
    pos = FDI_INDEX_START
    for _ in range(record_count):
        index_offset = pos
        if pos + 9 > len(data):
            raise ValueError(f"Truncated indexed FDI directory entry at 0x{pos:x}")
        record_id = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        key_length = data[pos]
        pos += 1
        if pos + key_length + 8 > len(data):
            raise ValueError(f"Indexed FDI entry at 0x{index_offset:x} overruns file")
        key_bytes = data[pos:pos + key_length]
        pos += key_length
        payload_offset = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        payload_length = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        end = payload_offset + payload_length
        if payload_offset < 0 or end > len(data):
            raise ValueError(f"Indexed payload for record {record_id} points outside file")
        key = key_bytes.decode("cp1252", errors="replace")
        entries.append(IndexedFDIEntry(record_id, key, payload_offset, payload_length, index_offset))
    return IndexedFDIFile(entries=entries, index_end_offset=pos)


def _read_xor_u16_string(raw_payload: bytes, cursor: int) -> tuple[str, int]:
    if cursor + 2 > len(raw_payload):
        raise ValueError("truncated string length")
    size = int.from_bytes(raw_payload[cursor:cursor + 2], "little")
    cursor += 2
    end = cursor + size
    if end > len(raw_payload):
        raise ValueError("truncated string payload")
    text = _xor(raw_payload[cursor:end]).decode("cp1252", errors="replace")
    return text.rstrip("\x00"), end


def _advance_legacy_mode_zero_cursor(raw_payload: bytes, cursor: int, record_size: int) -> int:
    if record_size > 0x207:
        cursor += 2
    cursor += 4
    _, cursor = _read_xor_u16_string(raw_payload, cursor)
    cursor += 4
    cursor += 4
    _, cursor = _read_xor_u16_string(raw_payload, cursor)
    _, cursor = _read_xor_u16_string(raw_payload, cursor)
    cursor += 3
    cursor += 20 if record_size >= 0x1F9 else 10
    cursor += 15
    cursor += 46 if record_size >= 0x1F9 else 42
    if record_size < 700:
        if record_size < 0x1F9:
            pair_count = 7
        elif record_size < 0x203:
            pair_count = 17
        else:
            pair_count = 21
        cursor += pair_count * 2
    else:
        if cursor >= len(raw_payload):
            raise ValueError("truncated legacy sparse-count byte")
        sparse_count = raw_payload[cursor]
        cursor += 1 + sparse_count * 3
    if cursor > len(raw_payload):
        raise ValueError("legacy mode-0 block overruns payload")
    return cursor


def _parse_eq_external_team_roster_payload(raw_payload: bytes) -> LinkedTeamRoster | None:
    if len(raw_payload) < 0x2A:
        return None
    record_size = int.from_bytes(raw_payload[0x26:0x28], "little")
    mode_byte = raw_payload[0x29]
    if record_size < 600:
        return None

    cursor = 0x2A
    try:
        short_name, cursor = _read_xor_u16_string(raw_payload, cursor)
        stadium_name, cursor = _read_xor_u16_string(raw_payload, cursor)
        cursor += 1
        if record_size > 0x20C:
            cursor += 1
        full_club_name, cursor = _read_xor_u16_string(raw_payload, cursor)
    except Exception:
        return None

    cursor += 4
    if record_size >= 0x1FE:
        cursor += 4
    cursor += 2 + 2 + 2

    link_base = cursor
    if mode_byte == 0:
        try:
            link_base = _advance_legacy_mode_zero_cursor(raw_payload, cursor, record_size)
        except Exception:
            return None

    ent_cursor = link_base + 0x6E7
    if ent_cursor >= len(raw_payload):
        return None
    ent_count = raw_payload[ent_cursor]
    player_cursor = ent_cursor + 1 + ent_count * 4
    if player_cursor >= len(raw_payload):
        return None
    player_count = raw_payload[player_cursor]
    player_cursor += 1

    rows: list[LinkedRosterRow] = []
    for slot_index in range(player_count):
        if player_cursor + 5 > len(raw_payload):
            return None
        flag = raw_payload[player_cursor]
        player_record_id = int.from_bytes(raw_payload[player_cursor + 1:player_cursor + 5], "little")
        rows.append(LinkedRosterRow(slot_index=slot_index, flag=flag, player_record_id=player_record_id))
        player_cursor += 5

    return LinkedTeamRoster(
        eq_record_id=0,
        short_name=short_name,
        stadium_name=stadium_name,
        full_club_name=full_club_name,
        record_size=record_size,
        mode_byte=mode_byte,
        ent_count=ent_count,
        rows=rows,
    )


def _load_linked_rosters(team_file: Path) -> list[LinkedTeamRoster]:
    team_bytes = team_file.read_bytes()
    indexed = _parse_indexed_fdi(team_bytes)
    rosters: list[LinkedTeamRoster] = []
    for entry in indexed.entries:
        roster = _parse_eq_external_team_roster_payload(team_bytes[entry.payload_offset:entry.payload_offset + entry.payload_length])
        if roster is None:
            continue
        rosters.append(
            LinkedTeamRoster(
                eq_record_id=int(entry.record_id),
                short_name=roster.short_name,
                stadium_name=roster.stadium_name,
                full_club_name=roster.full_club_name,
                record_size=roster.record_size,
                mode_byte=roster.mode_byte,
                ent_count=roster.ent_count,
                rows=roster.rows,
            )
        )
    return rosters


def _resolve_stars_roster(team_file: Path, team_name: str = STARS_TEAM_NAME) -> LinkedTeamRoster:
    wanted = team_name.casefold()
    matches = [
        roster for roster in _load_linked_rosters(team_file)
        if roster.short_name.casefold() == wanted or roster.full_club_name.casefold() == wanted
    ]
    if not matches:
        raise RuntimeError(f"Linked team roster not found in {team_file}: {team_name!r}")
    if len(matches) > 1:
        ids = ", ".join(str(roster.eq_record_id) for roster in matches)
        raise RuntimeError(f"Ambiguous linked team roster {team_name!r}; matching EQ ids: {ids}")
    return matches[0]


def _rewrite_indexed_record_id(
    file_data: bytes,
    indexed: IndexedFDIFile,
    old_record_id: int,
    new_record_id: int,
) -> bytes:
    if old_record_id == new_record_id:
        return file_data

    old_entry = None
    for entry in indexed.entries:
        if int(entry.record_id) == int(old_record_id):
            old_entry = entry
            break
    if old_entry is None:
        raise RuntimeError(f"Indexed record id {old_record_id} not found")
    if any(int(entry.record_id) == int(new_record_id) for entry in indexed.entries):
        raise RuntimeError(f"Cannot rewrite record {old_record_id} to {new_record_id}: target id already exists")

    patched = bytearray(file_data)
    struct.pack_into("<I", patched, int(old_entry.index_offset), int(new_record_id))

    reparsed = _parse_indexed_fdi(bytes(patched))
    if not any(int(entry.record_id) == int(new_record_id) for entry in reparsed.entries):
        raise RuntimeError(f"Indexed record id rewrite to {new_record_id} did not reparse")
    return bytes(patched)


def _backup_path(path: Path, suffix: str) -> Path:
    candidate = path.with_name(f"{path.name}.{suffix}")
    if not candidate.exists():
        return candidate
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return path.with_name(f"{path.name}.{suffix}.{stamp}")


def _rewrite_indexed_payloads(
    file_data: bytes,
    indexed: IndexedFDIFile,
    decoded_payload_by_record_id: dict[int, bytes],
) -> bytes:
    if not indexed.entries:
        raise RuntimeError("Indexed file has no entries")
    ordered_entries = sorted(indexed.entries, key=lambda item: int(item.payload_offset))
    first_payload_offset = int(ordered_entries[0].payload_offset)
    if first_payload_offset <= 0 or first_payload_offset > len(file_data):
        raise RuntimeError("Indexed payload region starts outside file bounds")

    encoded_by_old_offset: dict[int, bytes] = {}
    new_lengths_by_old_offset: dict[int, int] = {}
    for entry in ordered_entries:
        old_offset = int(entry.payload_offset)
        old_end = old_offset + int(entry.payload_length)
        if entry.record_id in decoded_payload_by_record_id:
            encoded = _xor(decoded_payload_by_record_id[entry.record_id])
        else:
            encoded = bytes(file_data[old_offset:old_end])
        encoded_by_old_offset[old_offset] = encoded
        new_lengths_by_old_offset[old_offset] = len(encoded)

    rebuilt = bytearray(file_data[:first_payload_offset])
    new_offsets_by_old_offset: dict[int, int] = {}
    for idx, entry in enumerate(ordered_entries):
        old_offset = int(entry.payload_offset)
        old_length = int(entry.payload_length)
        old_end = old_offset + old_length
        new_offsets_by_old_offset[old_offset] = len(rebuilt)
        rebuilt.extend(encoded_by_old_offset[old_offset])
        if idx + 1 < len(ordered_entries):
            next_offset = int(ordered_entries[idx + 1].payload_offset)
            if next_offset < old_end:
                raise RuntimeError(f"Indexed payload overlap at 0x{old_offset:x}")
            rebuilt.extend(file_data[old_end:next_offset])
        else:
            rebuilt.extend(file_data[old_end:])

    for entry in indexed.entries:
        index_offset = int(entry.index_offset)
        if index_offset < 0 or index_offset + 5 > first_payload_offset:
            raise RuntimeError(f"Indexed directory entry at 0x{index_offset:x} is outside index region")
        key_length = int(rebuilt[index_offset + 4])
        payload_offset_pos = index_offset + 5 + key_length
        payload_length_pos = payload_offset_pos + 4
        if payload_length_pos + 4 > first_payload_offset:
            raise RuntimeError(f"Indexed directory entry at 0x{index_offset:x} has invalid key length")
        old_offset = int(entry.payload_offset)
        struct.pack_into("<I", rebuilt, payload_offset_pos, int(new_offsets_by_old_offset[old_offset]))
        struct.pack_into("<I", rebuilt, payload_length_pos, int(new_lengths_by_old_offset[old_offset]))

    reparsed = _parse_indexed_fdi(bytes(rebuilt))
    if len(reparsed.entries) != len(indexed.entries):
        raise RuntimeError("Indexed record count changed after rebuild")
    return bytes(rebuilt)


def repair_stars_database(
    *,
    dbdat_dir: Path,
    dry_run: bool,
    min_payload_length: int = MIN_LINKED_PLAYER_PAYLOAD_LENGTH,
    create_backup: bool = True,
) -> dict[str, Any]:
    team_file = dbdat_dir / "EQ98030.FDI"
    player_file = dbdat_dir / "JUG98030.FDI"
    if not team_file.exists():
        raise RuntimeError(f"Team file not found: {team_file}")
    if not player_file.exists():
        raise RuntimeError(f"Player file not found: {player_file}")

    warnings: list[str] = []
    roster = _resolve_stars_roster(team_file)
    team_bytes = team_file.read_bytes()
    team_indexed = _parse_indexed_fdi(team_bytes)
    team_repair: dict[str, Any] = {
        "old_eq_record_id": roster.eq_record_id,
        "new_eq_record_id": roster.eq_record_id,
        "changed": False,
        "backup_path": None,
        "applied_to_disk": False,
        "reason": "already_safe_record_id",
        "sha256": {
            "input_team_file": _sha256(team_bytes),
            "output_team_file": _sha256(team_bytes),
        },
    }
    if int(roster.eq_record_id) == STARS_BROKEN_EQ_RECORD_ID:
        repaired_team_bytes = _rewrite_indexed_record_id(
            team_bytes,
            team_indexed,
            STARS_BROKEN_EQ_RECORD_ID,
            STARS_SAFE_EQ_RECORD_ID,
        )
        team_repair.update(
            {
                "new_eq_record_id": STARS_SAFE_EQ_RECORD_ID,
                "changed": True,
                "reason": "moved_stars_off_runtime_special_0x26ac",
                "sha256": {
                    "input_team_file": _sha256(team_bytes),
                    "output_team_file": _sha256(repaired_team_bytes),
                },
            }
        )
        if not dry_run:
            team_backup = _backup_path(team_file, "skezmod-original")
            if create_backup:
                shutil.copy2(team_file, team_backup)
                team_repair["backup_path"] = str(team_backup)
            team_file.write_bytes(repaired_team_bytes)
            team_repair["applied_to_disk"] = True
    elif int(roster.eq_record_id) != STARS_SAFE_EQ_RECORD_ID:
        warnings.append(
            f"Stars roster record id is {roster.eq_record_id}; expected {STARS_BROKEN_EQ_RECORD_ID} or {STARS_SAFE_EQ_RECORD_ID}"
        )

    player_bytes = player_file.read_bytes()
    indexed = _parse_indexed_fdi(player_bytes)
    entries_by_id = {entry.record_id: entry for entry in indexed.entries}
    patched_payload_by_id: dict[int, bytes] = {}
    changes: list[dict[str, Any]] = []

    for row in roster.rows:
        entry = entries_by_id.get(row.player_record_id)
        if entry is None:
            warnings.append(f"Stars slot {row.slot_index + 1} player id {row.player_record_id} is missing from JUG98030.FDI")
            continue
        old_len = int(entry.payload_length)
        decoded = entry.decode_payload(player_bytes)
        changed = old_len < min_payload_length
        appended = b""
        if changed:
            filler = decoded[-1:] if decoded else b"\x00"
            appended = filler * (min_payload_length - old_len)
            patched_payload_by_id[entry.record_id] = decoded + appended
        changes.append(
            {
                "slot_number": row.slot_index + 1,
                "player_record_id": row.player_record_id,
                "payload_offset_before": entry.payload_offset,
                "old_payload_length": old_len,
                "new_payload_length": min_payload_length if changed else old_len,
                "changed": changed,
                "appended_decoded_hex": appended.hex(),
                "appended_decoded_text": appended.decode("cp1252", errors="replace"),
            }
        )

    backup = None
    output_sha = _sha256(player_bytes)
    applied_to_disk = False
    size_delta = sum(max(0, change["new_payload_length"] - change["old_payload_length"]) for change in changes)
    if patched_payload_by_id:
        rebuilt = _rewrite_indexed_payloads(player_bytes, indexed, patched_payload_by_id)
        output_sha = _sha256(rebuilt)
        if not dry_run:
            if create_backup:
                backup = _backup_path(player_file, "skezmod-original")
                shutil.copy2(player_file, backup)
            player_file.write_bytes(rebuilt)
            applied_to_disk = True

    unresolved_short = [
        change for change in changes
        if int(change["new_payload_length"]) < min_payload_length
    ]
    ok = not unresolved_short and not warnings
    return {
        "dbdat_dir": str(dbdat_dir),
        "team_file": str(team_file),
        "player_file": str(player_file),
        "eq_record_id": team_repair["new_eq_record_id"],
        "eq_record_id_before": roster.eq_record_id,
        "team_record_repair": team_repair,
        "team_name": roster.short_name,
        "full_club_name": roster.full_club_name,
        "slot_count": len(roster.rows),
        "linked_player_ids": [row.player_record_id for row in roster.rows],
        "min_payload_length": min_payload_length,
        "changed_payload_count": len(patched_payload_by_id),
        "total_size_delta": size_delta,
        "backup_path": str(backup) if backup else None,
        "applied_to_disk": applied_to_disk,
        "dry_run": dry_run,
        "ok": ok,
        "changes": changes,
        "warnings": warnings,
        "sha256": {
            "input_player_file": _sha256(player_bytes),
            "output_player_file": output_sha,
        },
        "notes": [
            "Database repair is roster-driven: every player linked from the Stars EQ roster is checked.",
            "The Stars EQ indexed record id is moved from 0x26AC/9900 to 9899 to avoid MANAGPRE's hard-coded special-club display branch.",
            "Short JUG payloads are extended with their existing decoded trailing filler byte.",
            "No player-specific Valderrama/Lalas hardcoding is used.",
        ],
    }


def _write_formatter_s3_signing_fallback(
    *,
    input_bytes: bytes,
    patched: bytearray,
    rows: list[dict[str, Any]],
    force: bool,
) -> None:
    site_off = _va_to_file_offset(input_bytes, FORMATTER_S3_SITE_VA)
    trampoline = _build_trampoline(FORMATTER_S3_SITE_VA, FORMATTER_S3_STAGE0_VA, len(FORMATTER_S3_SITE_ORIGINAL))
    current_site = bytes(patched[site_off:site_off + len(FORMATTER_S3_SITE_ORIGINAL)])
    if current_site not in {FORMATTER_S3_SITE_ORIGINAL, trampoline} and not force:
        raise RuntimeError("Signing formatter {S3} patch-site bytes do not match expected signature")

    patched[site_off:site_off + len(FORMATTER_S3_SITE_ORIGINAL)] = trampoline
    rows.append(
        {
            "name": "formatter_s3_signing_stars_fallback_FUN_00499D00",
            "site_va": f"0x{FORMATTER_S3_SITE_VA:08X}",
            "site_file_offset": f"0x{site_off:08X}",
            "site_before": current_site.hex(),
            "site_after": trampoline.hex(),
            "bytes_written": len(FORMATTER_S3_SITE_ORIGINAL),
            "purpose": "retained signing-news formatter fallback",
        }
    )

    stars_bytes = b"Stars\x00"
    stars_off = _va_to_file_offset(input_bytes, STARS_STRING_VA)
    current_stars = bytes(patched[stars_off:stars_off + len(stars_bytes)])
    if current_stars not in {b"\x00" * len(stars_bytes), stars_bytes} and not force:
        raise RuntimeError("Stars string cave bytes are not empty/already patched")
    patched[stars_off:stars_off + len(stars_bytes)] = stars_bytes
    rows.append(
        {
            "name": "write_formatter_stars_literal",
            "site_va": f"0x{STARS_STRING_VA:08X}",
            "site_file_offset": f"0x{stars_off:08X}",
            "site_before": current_stars.hex(),
            "site_after": stars_bytes.hex(),
            "bytes_written": len(stars_bytes),
            "purpose": "retained signing-news formatter fallback",
        }
    )

    stage0, stage1, stage2, extras = _build_formatter_s3_zero_team_stars_fallback()
    old_team_lookup = _build_formatter_s3_team_lookup_stages()
    old_valderrama = _build_formatter_s3_valderrama_stages()
    stage_specs: tuple[tuple[str, int, int, bytes, tuple[bytes, ...]], ...] = (
        (
            "write_formatter_s3_stage0_cave",
            FORMATTER_S3_STAGE0_VA,
            FORMATTER_S3_STAGE0_SIZE,
            stage0,
            (old_team_lookup[0], old_valderrama[0]),
        ),
        (
            "write_formatter_s3_stage1_cave",
            FORMATTER_S3_STAGE1_VA,
            FORMATTER_S3_STAGE1_SIZE,
            stage1,
            (old_team_lookup[1], old_valderrama[1]),
        ),
        (
            "write_formatter_s3_stage2_cave",
            FORMATTER_S3_STAGE2_VA,
            FORMATTER_S3_STAGE2_SIZE,
            stage2,
            (old_team_lookup[2], old_valderrama[2]),
        ),
    ) + tuple((name, cave_va, cave_size, cave_code, ()) for name, cave_va, cave_size, cave_code in extras)

    for name, cave_va, cave_size, cave_code, alternates in stage_specs:
        if len(cave_code) > cave_size:
            raise RuntimeError(f"{name} overflow ({len(cave_code)} > {cave_size})")
        cave_blob = cave_code + (b"\xCC" * (cave_size - len(cave_code)))
        cave_off = _va_to_file_offset(input_bytes, cave_va)
        current_cave = bytes(patched[cave_off:cave_off + cave_size])
        allowed_caves = {b"\xCC" * cave_size, b"\x00" * cave_size, cave_blob}
        for old_code in alternates:
            allowed_caves.add(old_code + (b"\xCC" * (cave_size - len(old_code))))
        if current_cave not in allowed_caves and not force:
            raise RuntimeError(f"{name} cave bytes are not recognized. Use --force only after manual verification.")
        patched[cave_off:cave_off + cave_size] = cave_blob
        rows.append(
            {
                "name": name,
                "site_va": f"0x{cave_va:08X}",
                "site_file_offset": f"0x{cave_off:08X}",
                "site_before": current_cave.hex(),
                "site_after": cave_blob.hex(),
                "bytes_written": cave_size,
                "purpose": "retained signing-news formatter fallback",
            }
        )


def _apply_exe_cleanup_and_null_guard(*, input_exe: Path, output_exe: Path, dry_run: bool, force: bool) -> dict[str, Any]:
    input_bytes = input_exe.read_bytes()
    patched = bytearray(input_bytes)
    rows: list[dict[str, Any]] = []

    for site in _known_old_exe_restore_sites():
        off = _va_to_file_offset(input_bytes, site.site_va)
        current = bytes(patched[off:off + len(site.original)])
        if current == site.original:
            continue
        if current in site.alternates:
            patched[off:off + len(site.original)] = site.original
            rows.append(
                {
                    "name": site.name,
                    "site_va": f"0x{site.site_va:08X}",
                    "site_file_offset": f"0x{off:08X}",
                    "site_before": current.hex(),
                    "site_after": site.original.hex(),
                    "bytes_written": len(site.original),
                    "purpose": "remove obsolete non-nullguard EXE hook",
                }
            )
            continue
        if not force:
            raise RuntimeError(
                f"Unexpected bytes at obsolete-patch guard site 0x{site.site_va:08X}. "
                "Use --force only after manual verification."
            )

    for cave in _known_old_cave_restore_ranges():
        off = _va_to_file_offset(input_bytes, cave.start_va)
        current = bytes(patched[off:off + len(cave.original_fill)])
        if current == cave.original_fill:
            continue
        patched[off:off + len(cave.original_fill)] = cave.original_fill
        rows.append(
            {
                "name": cave.name,
                "site_va": f"0x{cave.start_va:08X}",
                "site_file_offset": f"0x{off:08X}",
                "site_before": current.hex(),
                "site_after": cave.original_fill.hex(),
                "bytes_written": len(cave.original_fill),
                "purpose": "remove obsolete non-nullguard cave bytes",
            }
        )

    spec = NULL_GUARD
    site_off = _va_to_file_offset(input_bytes, spec.site_va)
    cave_off = _va_to_file_offset(input_bytes, spec.cave_va)
    stub = _build_null_guard_stub(spec)
    trampoline = _build_trampoline(spec.site_va, spec.cave_va, len(spec.site_original))
    null_guard_region_len = max(len(stub), len(_build_obsolete_empty_text_null_guard_stub()))
    cave_after = stub + (b"\x00" * (null_guard_region_len - len(stub)))
    current_site = bytes(patched[site_off:site_off + len(spec.site_original)])
    current_cave = bytes(patched[cave_off:cave_off + null_guard_region_len])

    allowed_sites = {spec.site_original, trampoline}
    allowed_caves = {
        b"\x00" * null_guard_region_len,
        b"\xCC" * null_guard_region_len,
        cave_after,
        _build_obsolete_empty_text_null_guard_stub(),
    }
    if current_site not in allowed_sites and not force:
        raise RuntimeError("Null-guard patch-site bytes do not match expected signature")
    if current_cave not in allowed_caves and not force:
        raise RuntimeError("Null-guard cave bytes are not empty/already patched")

    patched[cave_off:cave_off + null_guard_region_len] = cave_after
    patched[site_off:site_off + len(spec.site_original)] = trampoline
    rows.append(
        {
            "name": spec.name,
            "site_va": f"0x{spec.site_va:08X}",
            "site_file_offset": f"0x{site_off:08X}",
            "site_before": current_site.hex(),
            "site_after": trampoline.hex(),
            "cave_va": f"0x{spec.cave_va:08X}",
            "cave_file_offset": f"0x{cave_off:08X}",
            "cave_before": current_cave.hex(),
            "cave_after": cave_after.hex(),
            "bytes_written": len(spec.site_original) + len(cave_after),
            "purpose": "single retained EXE runtime guard",
        }
    )

    _write_formatter_s3_signing_fallback(
        input_bytes=input_bytes,
        patched=patched,
        rows=rows,
        force=force,
    )

    output_bytes = bytes(patched)
    if not dry_run:
        output_exe.parent.mkdir(parents=True, exist_ok=True)
        output_exe.write_bytes(output_bytes)

    non_nullguard_hooks_remaining = [
        row for row in rows
        if row["name"] != spec.name
        and row.get("purpose") not in {
            "remove obsolete non-nullguard EXE hook",
            "remove obsolete non-nullguard cave bytes",
            "retained signing-news formatter fallback",
        }
    ]
    return {
        "input_exe": str(input_exe),
        "output_exe": str(output_exe),
        "dry_run": dry_run,
        "patch_count": len(rows),
        "patches": rows,
        "retained_exe_patch": spec.name,
        "retained_signing_formatter_patch": "formatter_s3_signing_stars_fallback_FUN_00499D00",
        "obsolete_hooks_removed": sum(1 for row in rows if row.get("purpose") == "remove obsolete non-nullguard EXE hook"),
        "obsolete_cave_ranges_cleared": sum(1 for row in rows if row.get("purpose") == "remove obsolete non-nullguard cave bytes"),
        "non_nullguard_hooks_remaining_in_plan": len(non_nullguard_hooks_remaining),
        "sha256": {"input": _sha256(input_bytes), "output": _sha256(output_bytes)},
        "notes": [
            "EXE patch surface is intentionally reduced to the null guard plus the signing-news {S3} formatter fallback.",
            "Known obsolete SkezMod lookup/search/profile hooks are restored if found.",
            "Known obsolete cave regions are reset to their original filler bytes if found.",
            "Stars search/profile display behaviour is expected to come from the repaired database, not EXE fallbacks.",
            "Signing-news text uses a formatter-local fallback because MANAGPRE event 0x453 can supply a null {S3} club argument after DB hydration has already happened.",
        ],
    }


def apply_skezmod(
    *,
    input_exe: Path,
    output_exe: Path,
    dbdat_dir: Path,
    dry_run: bool,
    force: bool,
    skip_db_repair: bool,
) -> dict[str, Any]:
    exe_report = _apply_exe_cleanup_and_null_guard(
        input_exe=input_exe,
        output_exe=output_exe,
        dry_run=dry_run,
        force=force,
    )
    db_report = None
    if not skip_db_repair:
        db_report = repair_stars_database(dbdat_dir=dbdat_dir, dry_run=dry_run)

    return {
        "patch_name": "skezmod-db-repair-nullguard-signing-fallback",
        "dry_run": dry_run,
        "exe": exe_report,
        "database": db_report,
        "notes": [
            "Stars display fix is DB-first: repair the linked Stars EQ roster id and linked JUG player payloads.",
            "Retained EXE mutations are the FUN_0066F1F0 null text-pointer guard and the scoped signing-news {S3} formatter fallback.",
            "No player ids or search/profile renderer caves are injected into MANAGPRE.EXE.",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run from the root of your Premier Manager 99 install directory. "
            "Repairs the Stars database records and applies the scoped MANAGPRE "
            "null guard plus signing-news formatter fallback."
        )
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate and report only")
    parser.add_argument("--dbdat-dir", default=str(DEFAULT_DBDAT_DIR), help="Path to DBDAT directory, default: DBDAT")
    parser.add_argument(
        "--skip-db-repair",
        action="store_true",
        help="Only apply/validate the EXE null guard and signing-news formatter fallback",
    )
    parser.add_argument(
        "--no-branding",
        action="store_true",
        help="Accepted for compatibility; branding is no longer applied by this patcher",
    )
    parser.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--json-output", help="Optional JSON report output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_exe = DEFAULT_INPUT_EXE
    if not input_exe.exists() and FALLBACK_INPUT_EXE.exists():
        input_exe = FALLBACK_INPUT_EXE
    if not input_exe.exists():
        print(ASCII_BRAND)
        raise SystemExit(
            "EXE not found: MANAGPRE.EXE or managpre.exe\n"
            "Run this from your Premier Manager Ninety Nine install directory."
        )

    staged_exe = input_exe.with_name(DEFAULT_OUTPUT_NAME)
    stale_staged = staged_exe.exists()
    total_steps = 3 if args.dry_run else (8 if stale_staged else 7)

    def stage(step: int, message: str) -> None:
        print(f"[{step}/{total_steps}] {message}")

    print(ASCII_BRAND)
    stage(1, f"Checking source binary: {input_exe}")
    stage(2, f"Checking database directory: {Path(args.dbdat_dir)}")

    if args.dry_run:
        report = apply_skezmod(
            input_exe=input_exe,
            output_exe=staged_exe,
            dbdat_dir=Path(args.dbdat_dir),
            dry_run=True,
            force=bool(args.force),
            skip_db_repair=bool(args.skip_db_repair),
        )
        stage(3, "Dry-run validation complete (no files modified).")
    else:
        apply_step = 4
        if stale_staged:
            stage(3, f"Removing stale staged file: {staged_exe.name}")
            staged_exe.unlink()
            stage(4, f"Creating staged copy: {staged_exe.name}")
            apply_step = 5
        else:
            stage(3, f"Creating staged copy: {staged_exe.name}")

        shutil.copy2(input_exe, staged_exe)
        stage(apply_step, "Applying EXE null guard and Stars DB repair")
        report = apply_skezmod(
            input_exe=staged_exe,
            output_exe=staged_exe,
            dbdat_dir=Path(args.dbdat_dir),
            dry_run=False,
            force=bool(args.force),
            skip_db_repair=bool(args.skip_db_repair),
        )

        stage(apply_step + 1, "Verifying staged patch idempotence/signatures")
        apply_skezmod(
            input_exe=staged_exe,
            output_exe=staged_exe,
            dbdat_dir=Path(args.dbdat_dir),
            dry_run=True,
            force=bool(args.force),
            skip_db_repair=bool(args.skip_db_repair),
        )

        stage(apply_step + 2, "Rotating original MANAGPRE.EXE to backup")
        backup_path = input_exe.with_name(DEFAULT_BACKUP_NAME)
        if backup_path.exists():
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = input_exe.with_name(f"MANAGPRE.original.{stamp}.exe")
        input_exe.rename(backup_path)

        stage(apply_step + 3, "Promoting staged patched binary to MANAGPRE.EXE")
        try:
            staged_exe.rename(input_exe)
        except Exception as exc:
            if backup_path.exists() and not input_exe.exists():
                backup_path.rename(input_exe)
            raise RuntimeError(f"Promotion failed; original restored: {exc}") from exc

        report["exe"]["input_exe"] = str(input_exe)
        report["exe"]["output_exe"] = str(input_exe)
        report["exe"]["backup_exe"] = str(backup_path)
        report["notes"].append("Defensive staged flow completed: copy -> patch -> verify -> rotate -> promote.")

    json_text = json.dumps(report, indent=2)
    if args.json_output:
        out = Path(args.json_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json_text + "\n", encoding="utf-8")

    if args.dry_run:
        print("SkezMod DB Repair Dry-Run OK: no files modified.")
    else:
        print(f"SkezMod DB Repair Applied OK: {report['exe'].get('output_exe', '')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
