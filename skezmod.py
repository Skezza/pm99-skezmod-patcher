#!/usr/bin/env python3
"""
Applies the SkezMod v0.1 MANAGPRE.exe patch set.

First patch-set resolves "Application cannot continue" when hovering
Stars / free-players, e.g. Carlos Valderrama, Alexi Lalas...

Patch behaviour:

- Null check text-pointer dereference in `FUN_0066F1F0`
  (faulting read at `0x0066F208`).

- Tail hook `FUN_004B5C20` (`0x004B5C76`) when team can't be resolved, 
   execution is redirected to a fallback handler located in code cave.

- The fallback handler returns stable non-null records for unresolved IDs:
    - `team_id 0`    → "Unknown club"
    - `team_id 4705` → "Stars"
    - `team_id 4706` → "Free players"

- Apply some lightweight front-end branding: `"PM99 SkezMod 0.1" :-) thx`.

Code cave layout:
- `0x006E5092..0x006E51BF` — fallback handler, static fallbacks
- `0x006E51C0`             — null-guard for `FUN_0066F1F0`

Compatibility warning:
- Tested on No-CD MANAGEPRE (My Abandonware)
- Tested on Original ISO.
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
    "#                 Premier Manager 99 SkezMod 0.1           #\n"
    "############################################################"
)


# Production defaults:
# - run from inside the PM99 install folder.
DEFAULT_INPUT_EXE = Path("MANAGPRE.EXE")
FALLBACK_INPUT_EXE = Path("managpre.exe")
DEFAULT_OUTPUT_NAME = "MANAGPRE.skezmod.exe"
DEFAULT_BACKUP_NAME = "MANAGPRE.original.exe"
IMAGE_BASE = 0x400000

TEAM_ID_STARS = 4705
TEAM_ID_FREE_PLAYERS = 4706
TITLE_ORIGINAL = b"PREMIER MANAGER 99\x00"
TITLE_BRANDING_TEXT = b"PM99 SkezMod 0.1"
TITLE_BRANDING = TITLE_BRANDING_TEXT + (b"\x00" * (len(TITLE_ORIGINAL) - len(TITLE_BRANDING_TEXT)))
if len(TITLE_BRANDING) != len(TITLE_ORIGINAL):
    raise RuntimeError("Branding bytes must preserve original string length")

# .text tail slack used by previous patch iterations and kept stable.
CAVE_BUNDLE_BASE_VA = 0x006E5092
CAVE_BUNDLE_SIZE = 302

# Keep string addresses stable for compatibility with previous variants.
CAVE_EMPTY_STRING_VA = 0x006E5199
CAVE_STARS_STRING_VA = 0x006E519A
CAVE_FREE_STRING_VA = 0x006E51A0
CAVE_UNKNOWN_STRING_VA = 0x006E51AD
CAVE_SEARCH_HOVER_TEAM_VA = 0x006E5145

# RC2-proven null-guard cave location.
CAVE_NULL_GUARD_VA = 0x006E51C0
CAVE_PROFILE_SPECIAL_TEAM_VA = 0x006E51E1
CAVE_PROFILE_SPECIAL_TEAM_SIZE = 31

# Formatter-local fallback for broken "{S3}" team suffixes in signing notices.
CAVE_FORMATTER_S3_STAGE0_VA = 0x006E4251
CAVE_FORMATTER_S3_STAGE0_SIZE = 15
CAVE_FORMATTER_S3_STAGE1_VA = 0x006E42D1
CAVE_FORMATTER_S3_STAGE1_SIZE = 15
CAVE_FORMATTER_S3_STAGE2_VA = 0x006E42F5
CAVE_FORMATTER_S3_STAGE2_SIZE = 11
CAVE_FORMATTER_S3_SKIP_VA = 0x006E4E85
CAVE_FORMATTER_S3_SKIP_SIZE = 11
CAVE_FORMATTER_S3_TEAM_LOOKUP1_VA = 0x006E4DF2
CAVE_FORMATTER_S3_TEAM_LOOKUP1_SIZE = 14
CAVE_FORMATTER_S3_TEAM_LOOKUP2_VA = 0x006E4E22
CAVE_FORMATTER_S3_TEAM_LOOKUP2_SIZE = 14


@dataclass(frozen=True)
class DirectPatch:
    name: str
    site_va: int
    expected: bytes
    replacement: bytes
    alternates: tuple[bytes, ...] = ()


def _sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


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
    rel = to_va - (from_va + instr_len)
    return struct.pack("<i", rel)


def _build_trampoline(src_va: int, dst_va: int, total_len: int) -> bytes:
    if total_len < 5:
        raise ValueError("Trampoline region must be at least 5 bytes")
    rel = dst_va - (src_va + 5)
    return b"\xE9" + struct.pack("<i", rel) + (b"\x90" * (total_len - 5))


def _build_call(src_va: int, dst_va: int) -> bytes:
    return b"\xE8" + _rel32(src_va, 5, dst_va)


def _build_null_text_guard_stub(*, cave_va: int, resume_va: int, empty_text_va: int) -> bytes:
    out = bytearray()

    # Original bytes from 0x0066F1FB up to (but excluding) MOV AL,[ECX].
    out += bytes.fromhex("8b4c242033f68a472033d28be8")
    out += b"\x85\xC9"  # test ecx,ecx

    # jnz continue
    jnz_pos = len(out)
    out += b"\x0F\x85" + b"\x00\x00\x00\x00"

    out += b"\xB9" + struct.pack("<I", empty_text_va)  # mov ecx,empty
    continue_va = cave_va + len(out)

    out += b"\x8A\x01"  # mov al,[ecx]
    jmp_resume_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    out[jnz_pos + 2: jnz_pos + 6] = _rel32(cave_va + jnz_pos, 6, continue_va)
    out[jmp_resume_pos + 1: jmp_resume_pos + 5] = _rel32(cave_va + jmp_resume_pos, 5, resume_va)
    return bytes(out)


def _build_old_null_guard_stub(*, cave_va: int, resume_va: int, null_target_va: int) -> bytes:
    out = bytearray()
    out += bytes.fromhex("8b4c242033f68a472033d28be8")
    out += b"\x85\xC9"
    jz_pos = len(out)
    out += b"\x0F\x84" + b"\x00\x00\x00\x00"
    out += b"\x8A\x01"
    jmp_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"
    out[jz_pos + 2: jz_pos + 6] = _rel32(cave_va + jz_pos, 6, null_target_va)
    out[jmp_pos + 1: jmp_pos + 5] = _rel32(cave_va + jmp_pos, 5, resume_va)
    return bytes(out)


def _build_lookup_result_fallback_helper(
    *,
    cave_va: int,
    epilogue_va: int,
    unknown_rec_va: int,
    stars_rec_va: int,
    free_rec_va: int,
) -> bytes:
    """Validate candidate team record; fallback to safe records on miss/bad text."""
    out = bytearray()

    out += b"\x85\xC0"  # test eax,eax
    jz_fallback_pos = len(out)
    out += b"\x0F\x84" + b"\x00\x00\x00\x00"

    out += b"\x39\x58\x10"  # cmp [eax+0x10],ebx
    jne_fallback_pos = len(out)
    out += b"\x0F\x85" + b"\x00\x00\x00\x00"

    out += b"\x8B\x50\x04"  # mov edx,[eax+0x04]
    out += b"\x85\xD2"  # test edx,edx
    jz_fallback_2_pos = len(out)
    out += b"\x0F\x84" + b"\x00\x00\x00\x00"

    out += b"\x8A\x0A"  # mov cl,[edx]
    out += b"\x84\xC9"  # test cl,cl
    jz_fallback_3_pos = len(out)
    out += b"\x0F\x8E" + b"\x00\x00\x00\x00"  # signed <=0 also rejects high-bit bytes

    out += b"\x80\xF9\x2E"  # cmp cl,'.'
    jbe_fallback_4_pos = len(out)
    out += b"\x0F\x86" + b"\x00\x00\x00\x00"

    jmp_epilogue_match_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    fallback_va = cave_va + len(out)
    out += b"\x85\xDB"  # test ebx,ebx
    je_unknown_pos = len(out)
    out += b"\x0F\x84" + b"\x00\x00\x00\x00"

    out += b"\x81\xFB" + struct.pack("<I", TEAM_ID_STARS)
    je_stars_pos = len(out)
    out += b"\x0F\x84" + b"\x00\x00\x00\x00"

    out += b"\x81\xFB" + struct.pack("<I", TEAM_ID_FREE_PLAYERS)
    je_free_pos = len(out)
    out += b"\x0F\x84" + b"\x00\x00\x00\x00"

    jmp_set_unknown_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    set_unknown_va = cave_va + len(out)
    out += b"\xB8" + struct.pack("<I", unknown_rec_va)
    jmp_epilogue_unknown_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    set_stars_va = cave_va + len(out)
    out += b"\xB8" + struct.pack("<I", stars_rec_va)
    jmp_epilogue_stars_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    set_free_va = cave_va + len(out)
    out += b"\xB8" + struct.pack("<I", free_rec_va)
    jmp_epilogue_free_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    out[jz_fallback_pos + 2: jz_fallback_pos + 6] = _rel32(cave_va + jz_fallback_pos, 6, fallback_va)
    out[jne_fallback_pos + 2: jne_fallback_pos + 6] = _rel32(cave_va + jne_fallback_pos, 6, fallback_va)
    out[jz_fallback_2_pos + 2: jz_fallback_2_pos + 6] = _rel32(cave_va + jz_fallback_2_pos, 6, fallback_va)
    out[jz_fallback_3_pos + 2: jz_fallback_3_pos + 6] = _rel32(cave_va + jz_fallback_3_pos, 6, fallback_va)
    out[jbe_fallback_4_pos + 2: jbe_fallback_4_pos + 6] = _rel32(cave_va + jbe_fallback_4_pos, 6, fallback_va)

    out[jmp_epilogue_match_pos + 1: jmp_epilogue_match_pos + 5] = _rel32(
        cave_va + jmp_epilogue_match_pos, 5, epilogue_va
    )

    out[je_unknown_pos + 2: je_unknown_pos + 6] = _rel32(cave_va + je_unknown_pos, 6, set_unknown_va)
    out[je_stars_pos + 2: je_stars_pos + 6] = _rel32(cave_va + je_stars_pos, 6, set_stars_va)
    out[je_free_pos + 2: je_free_pos + 6] = _rel32(cave_va + je_free_pos, 6, set_free_va)

    out[jmp_set_unknown_pos + 1: jmp_set_unknown_pos + 5] = _rel32(
        cave_va + jmp_set_unknown_pos, 5, set_unknown_va
    )
    out[jmp_epilogue_unknown_pos + 1: jmp_epilogue_unknown_pos + 5] = _rel32(
        cave_va + jmp_epilogue_unknown_pos, 5, epilogue_va
    )
    out[jmp_epilogue_stars_pos + 1: jmp_epilogue_stars_pos + 5] = _rel32(
        cave_va + jmp_epilogue_stars_pos, 5, epilogue_va
    )
    out[jmp_epilogue_free_pos + 1: jmp_epilogue_free_pos + 5] = _rel32(
        cave_va + jmp_epilogue_free_pos, 5, epilogue_va
    )

    return bytes(out)


def _build_formatter_s3_team_lookup_stages(
    *,
    stage0_va: int,
    stage1_va: int,
    stage2_va: int,
    team_lookup_va: int,
    original_push_va: int,
) -> tuple[bytes, bytes, bytes]:
    """For null {S3}, resolve the event team id through the central team lookup."""
    stage0 = bytearray()
    stage0 += b"\x8B\x45\x18"  # mov eax,[ebp+0x18] (original {S3})
    stage0 += b"\x85\xC0"  # test eax,eax
    jz_stage1_pos = len(stage0)
    stage0 += b"\x74\x00"  # null {S3}: look up the event team id
    stage0 += b"\xE9" + _rel32(stage0_va + len(stage0), 5, original_push_va)
    stage0[jz_stage1_pos + 1] = (stage1_va - (stage0_va + jz_stage1_pos + 2)) & 0xFF

    stage1 = bytearray()
    stage1 += b"\xB9\xE0\x4B\x75\x00"  # mov ecx,0x754be0
    stage1 += b"\xFF\x75\x0C"  # push dword ptr [ebp+0x0c] (event/team id)
    stage1 += b"\xE8" + _rel32(stage1_va + len(stage1), 5, team_lookup_va)
    stage1 += b"\xEB\x00"  # jump into stage2
    stage1[-1] = (stage2_va - (stage1_va + len(stage1))) & 0xFF

    stage2 = bytearray()
    stage2 += b"\x8B\x40\x04"  # mov eax,[eax+0x04] (team name pointer)
    stage2 += b"\xE9" + _rel32(stage2_va + len(stage2), 5, original_push_va)
    return bytes(stage0), bytes(stage1), bytes(stage2)


def _build_formatter_s3_zero_team_stars_fallback(
    *,
    stage0_va: int,
    stage1_va: int,
    stage2_va: int,
    skip_va: int,
    team_lookup1_va: int,
    team_lookup2_va: int,
    stars_va: int,
    team_lookup_va: int,
    original_push_va: int,
    original_skip_va: int,
) -> tuple[bytes, bytes, bytes, tuple[tuple[str, int, int, bytes], ...]]:
    """Build a scalable null-{S3} fallback for signing-notice style events.

    Strategy:
    - preserve non-null {S3}
    - if event team id ([ebp+0x0c]) is non-zero, resolve it through the central team lookup
    - if event team id is zero, use Stars for the broken special-team signing feed
    """
    stage0 = bytearray()
    stage0 += b"\x8B\x45\x18"  # mov eax,[ebp+0x18]
    stage0 += b"\x85\xC0"  # test eax,eax
    jz_stage1_pos = len(stage0)
    stage0 += b"\x74\x00"
    stage0 += b"\xE9" + _rel32(stage0_va + len(stage0), 5, original_push_va)
    stage0[jz_stage1_pos + 1] = (stage1_va - (stage0_va + jz_stage1_pos + 2)) & 0xFF

    stage1 = bytearray()
    stage1 += b"\x83\x7D\x0C\x00"  # cmp dword ptr [ebp+0x0c],0
    je_stage2_pos = len(stage1)
    stage1 += b"\x74\x00"  # zero event-team id: Stars
    stage1 += b"\x8B\x45\x0C"  # mov eax,[ebp+0x0c]
    stage1 += b"\xE9" + _rel32(stage1_va + len(stage1), 5, team_lookup1_va)
    stage1[je_stage2_pos + 1] = (stage2_va - (stage1_va + je_stage2_pos + 2)) & 0xFF

    stage2 = bytearray()
    stage2 += b"\xB8" + struct.pack("<I", stars_va)  # mov eax,Stars
    stage2 += b"\xE9" + _rel32(stage2_va + len(stage2), 5, original_push_va)

    skip = bytearray()
    skip += b"\xE9" + _rel32(skip_va, 5, original_skip_va)

    team_lookup1 = bytearray()
    team_lookup1 += b"\xB9\xE0\x4B\x75\x00"  # mov ecx,0x754be0
    team_lookup1 += b"\x50"  # push eax
    team_lookup1 += b"\xE8" + _rel32(team_lookup1_va + len(team_lookup1), 5, team_lookup_va)
    team_lookup1 += b"\xEB\x00"
    team_lookup1[-1] = (team_lookup2_va - (team_lookup1_va + len(team_lookup1))) & 0xFF

    team_lookup2 = bytearray()
    team_lookup2 += b"\x85\xC0"  # test eax,eax
    team_lookup2 += b"\x74\x00"  # jz -> skip
    team_lookup2 += b"\x8B\x40\x04"  # mov eax,[eax+0x04]
    team_lookup2 += b"\xE9" + _rel32(team_lookup2_va + len(team_lookup2), 5, original_push_va)
    team_lookup2[3] = (skip_va - (team_lookup2_va + 4)) & 0xFF

    extras = (
        ("write_formatter_s3_skip_cave", skip_va, CAVE_FORMATTER_S3_SKIP_SIZE, bytes(skip)),
        ("write_formatter_s3_team_lookup1_cave", team_lookup1_va, CAVE_FORMATTER_S3_TEAM_LOOKUP1_SIZE, bytes(team_lookup1)),
        ("write_formatter_s3_team_lookup2_cave", team_lookup2_va, CAVE_FORMATTER_S3_TEAM_LOOKUP2_SIZE, bytes(team_lookup2)),
    )
    return bytes(stage0), bytes(stage1), bytes(stage2), extras


def _build_search_hover_team_fallback(*, cave_va: int, stars_va: int, resume_va: int) -> bytes:
    """Backfill the search hover/status club cell when the special club text is blank."""
    out = bytearray()

    out += b"\x66\x8B\x46\x18"  # mov ax,[esi+0x18]
    out += b"\x66\x3D\xAC\x26"  # cmp ax,0x26ac
    jne_lookup_pos = len(out)
    out += b"\x75\x00"

    out += b"\x8B\x46\x10"  # mov eax,[esi+0x10]
    out += b"\x85\xC0"  # test eax,eax
    jz_stars_pos = len(out)
    out += b"\x74\x00"
    out += b"\x80\x38\x00"  # cmp byte ptr [eax],0
    jz_stars_empty_pos = len(out)
    out += b"\x74\x00"
    jmp_resume_existing_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    lookup_va = cave_va + len(out)
    out += b"\x25\xFF\xFF\x00\x00"  # and eax,0xffff
    out += b"\xB9\xE0\x4B\x75\x00"  # mov ecx,0x754be0
    out += b"\x50"  # push eax
    call_lookup_pos = len(out)
    out += b"\xE8" + b"\x00\x00\x00\x00"
    out += b"\x8B\x40\x04"  # mov eax,[eax+0x4]
    jmp_resume_lookup_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    stars_case_va = cave_va + len(out)
    out += b"\xB8" + struct.pack("<I", stars_va)  # mov eax,Stars
    jmp_resume_stars_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    out[jne_lookup_pos + 1] = (lookup_va - (cave_va + jne_lookup_pos + 2)) & 0xFF
    out[jz_stars_pos + 1] = (stars_case_va - (cave_va + jz_stars_pos + 2)) & 0xFF
    out[jz_stars_empty_pos + 1] = (stars_case_va - (cave_va + jz_stars_empty_pos + 2)) & 0xFF
    out[jmp_resume_existing_pos + 1: jmp_resume_existing_pos + 5] = _rel32(
        cave_va + jmp_resume_existing_pos, 5, resume_va
    )
    out[call_lookup_pos + 1: call_lookup_pos + 5] = _rel32(cave_va + call_lookup_pos, 5, 0x004B5C20)
    out[jmp_resume_lookup_pos + 1: jmp_resume_lookup_pos + 5] = _rel32(
        cave_va + jmp_resume_lookup_pos, 5, resume_va
    )
    out[jmp_resume_stars_pos + 1: jmp_resume_stars_pos + 5] = _rel32(
        cave_va + jmp_resume_stars_pos, 5, resume_va
    )
    return bytes(out)


def _build_profile_special_team_fallback(*, cave_va: int, stars_va: int, resume_va: int) -> bytes:
    """Backfill player-record special club text when the inline pointer is blank."""
    out = bytearray()
    out += b"\x8B\x47\x10"  # mov eax,[edi+0x10]
    out += b"\x85\xC0"  # test eax,eax
    jz_stars_pos = len(out)
    out += b"\x74\x00"
    out += b"\x80\x38\x00"  # cmp byte ptr [eax],0
    jz_stars_empty_pos = len(out)
    out += b"\x74\x00"
    jmp_resume_existing_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    stars_case_va = cave_va + len(out)
    out += b"\xB8" + struct.pack("<I", stars_va)  # mov eax,Stars
    jmp_resume_stars_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    out[jz_stars_pos + 1] = (stars_case_va - (cave_va + jz_stars_pos + 2)) & 0xFF
    out[jz_stars_empty_pos + 1] = (stars_case_va - (cave_va + jz_stars_empty_pos + 2)) & 0xFF
    out[jmp_resume_existing_pos + 1: jmp_resume_existing_pos + 5] = _rel32(
        cave_va + jmp_resume_existing_pos, 5, resume_va
    )
    out[jmp_resume_stars_pos + 1: jmp_resume_stars_pos + 5] = _rel32(
        cave_va + jmp_resume_stars_pos, 5, resume_va
    )
    return bytes(out)


def _build_fake_team_record(*, name_ptr_va: int, team_id: int) -> bytes:
    rec = bytearray(0x14)
    struct.pack_into("<I", rec, 0x04, int(name_ptr_va))
    struct.pack_into("<I", rec, 0x10, int(team_id))
    return bytes(rec)


def _build_bundle() -> tuple[bytes, dict[str, int], tuple[bytes, ...]]:
    strings_blob = b"\x00Stars\x00Free players\x00Unknown club\x00"
    string_addrs = {
        "empty": CAVE_EMPTY_STRING_VA,
        "stars": CAVE_STARS_STRING_VA,
        "free": CAVE_FREE_STRING_VA,
        "unknown": CAVE_UNKNOWN_STRING_VA,
    }

    helper_tmp = _build_lookup_result_fallback_helper(
        cave_va=CAVE_BUNDLE_BASE_VA,
        epilogue_va=0x004B5C7D,
        unknown_rec_va=0,
        stars_rec_va=0,
        free_rec_va=0,
    )
    rec_base_va = CAVE_BUNDLE_BASE_VA + len(helper_tmp)
    unknown_rec_va = rec_base_va
    stars_rec_va = rec_base_va + 0x14
    free_rec_va = rec_base_va + 0x28

    helper_real = _build_lookup_result_fallback_helper(
        cave_va=CAVE_BUNDLE_BASE_VA,
        epilogue_va=0x004B5C7D,
        unknown_rec_va=unknown_rec_va,
        stars_rec_va=stars_rec_va,
        free_rec_va=free_rec_va,
    )
    if len(helper_real) != len(helper_tmp):
        raise RuntimeError("Internal helper sizing mismatch")

    rec_unknown = _build_fake_team_record(name_ptr_va=string_addrs["unknown"], team_id=0)
    rec_stars = _build_fake_team_record(name_ptr_va=string_addrs["stars"], team_id=TEAM_ID_STARS)
    rec_free = _build_fake_team_record(name_ptr_va=string_addrs["free"], team_id=TEAM_ID_FREE_PLAYERS)

    prefix = helper_real + rec_unknown + rec_stars + rec_free
    hover_gap_len = CAVE_SEARCH_HOVER_TEAM_VA - (CAVE_BUNDLE_BASE_VA + len(prefix))
    if hover_gap_len < 0:
        raise RuntimeError("Bundle overflow before search hover fallback cave")
    search_hover_code = _build_search_hover_team_fallback(
        cave_va=CAVE_SEARCH_HOVER_TEAM_VA,
        stars_va=string_addrs["stars"],
        resume_va=0x00406138,
    )
    prefix += (b"\x00" * hover_gap_len) + search_hover_code
    prefix_end_va = CAVE_BUNDLE_BASE_VA + len(prefix)
    pad_len = CAVE_EMPTY_STRING_VA - prefix_end_va
    if pad_len < 0:
        raise RuntimeError(
            f"Bundle overflow before fixed strings: end=0x{prefix_end_va:08X} > strings=0x{CAVE_EMPTY_STRING_VA:08X}"
        )
    bundle = prefix + (b"\x00" * pad_len) + strings_blob
    if len(bundle) > CAVE_BUNDLE_SIZE:
        raise RuntimeError(f"Bundle too large ({len(bundle)} > {CAVE_BUNDLE_SIZE})")
    if len(bundle) < CAVE_BUNDLE_SIZE:
        bundle += b"\x00" * (CAVE_BUNDLE_SIZE - len(bundle))

    # Legacy prefixes from previous experimental variants (accept for idempotent upgrades).
    legacy_bundle_prefixes = (
        bytes.fromhex("e8890bddff85c00f84140000008b4004"),
        bytes.fromhex("e889f6dbff85c00f84130000008a1084d20f840900000080fa2e0f8730000000"),
        bytes.fromhex("e889f6dbff85c00f84130000008a1084d20f8e0900000080fa2e0f8730000000"),
        bytes.fromhex("e889f6dbff85c00f84140000008a1080fa300f820900000080fa7a0f8630000000"),
        bytes.fromhex("0fb7c08b54241485d20f8412000000803a000f8409000000803a2e0f8740000000"),
        bytes.fromhex("0fb7c08b54241485d20f841a0000008a0284c00f84100000003c800f83080000003c2e0f874c000000"),
    )
    return bundle, string_addrs, legacy_bundle_prefixes


def _build_patch_plan(lookup_helper_va: int, *, include_branding: bool) -> list[DirectPatch]:
    orig_search = bytes.fromhex("e8d51204008b4004")
    orig_transfer_a = bytes.fromhex("e8d8b3fbff8b4004")
    orig_transfer_b = bytes.fromhex("e887a6fbff8b4004")

    old_tramp_search = _build_trampoline(0x00474946, 0x006E5092, len(orig_search))
    old_tramp_transfer_a = _build_trampoline(0x004FA843, 0x006E50EB, len(orig_transfer_a))
    old_tramp_transfer_b = _build_trampoline(0x004FB594, 0x006E5142, len(orig_transfer_b))

    old_sign_call_a = _build_call(0x004B8C2E, 0x006E51E1)
    old_sign_call_b = _build_call(0x004B8EFA, 0x006E51E1)
    old_sign_call_a_v2 = _build_call(0x004B8C2E, 0x006E5092)
    old_sign_call_b_v2 = _build_call(0x004B8EFA, 0x006E5092)

    old_sign_wrapper = _build_call(0x004B8C3D, 0x006E5092)
    old_sign_wrapper_b = _build_call(0x004B8C73, 0x006E5092)
    old_sign_wrapper_c = _build_call(0x004B8F09, 0x006E5092)
    old_sign_wrapper_d = _build_call(0x004B8F3F, 0x006E5092)

    old_lookup_bytes = bytes.fromhex("395810740933c0")
    unpatched_lookup_bytes = bytes.fromhex("395810740233c0")
    old_lookup_trampoline = _build_trampoline(0x004B5C76, 0x006E50F4, len(unpatched_lookup_bytes))
    old_lookup_trampoline_v2 = _build_trampoline(0x004B5C76, 0x006E5108, len(unpatched_lookup_bytes))
    old_lookup_trampoline_v3 = _build_trampoline(0x004B5C76, 0x006E50E3, len(unpatched_lookup_bytes))
    old_lookup_trampoline_v4 = _build_trampoline(0x004B5C76, 0x006E50E4, len(unpatched_lookup_bytes))

    old_null_guard_trampoline = _build_trampoline(0x0066F1FB, 0x006E51C0, 15)
    old_hook_block = bytes.fromhex("e878ee2200e9efffffff9090")

    patches: list[DirectPatch] = [
        # Revert old experimental upstream list/profile trampolines.
        DirectPatch(
            name="restore_lookup_search_FUN_00474870",
            site_va=0x00474946,
            expected=orig_search,
            replacement=orig_search,
            alternates=(old_tramp_search,),
        ),
        DirectPatch(
            name="restore_lookup_transfer_FUN_004FA000",
            site_va=0x004FA843,
            expected=orig_transfer_a,
            replacement=orig_transfer_a,
            alternates=(old_tramp_transfer_a,),
        ),
        DirectPatch(
            name="restore_lookup_transfer_FUN_004FAC80",
            site_va=0x004FB594,
            expected=orig_transfer_b,
            replacement=orig_transfer_b,
            alternates=(old_tramp_transfer_b,),
        ),
        # Remove old helper-hooked AND instructions.
        DirectPatch(
            name="restore_signing_multiyear_hook_FUN_004B8B40",
            site_va=0x004B8C2E,
            expected=bytes.fromhex("25ffff0000"),
            replacement=bytes.fromhex("25ffff0000"),
            alternates=(old_sign_call_a, old_sign_call_a_v2),
        ),
        DirectPatch(
            name="restore_signing_multiyear_hook_FUN_004B8E20",
            site_va=0x004B8EFA,
            expected=bytes.fromhex("25ffff0000"),
            replacement=bytes.fromhex("25ffff0000"),
            alternates=(old_sign_call_b, old_sign_call_b_v2),
        ),
        # Explicitly remove RC1 source-wrapper hooks.
        DirectPatch(
            name="restore_source_wrapper_FUN_004B8B40_multiyear",
            site_va=0x004B8C3D,
            expected=_build_call(0x004B8C3D, 0x004A4720),
            replacement=_build_call(0x004B8C3D, 0x004A4720),
            alternates=(old_sign_wrapper,),
        ),
        DirectPatch(
            name="restore_source_wrapper_FUN_004B8B40_oneyear",
            site_va=0x004B8C73,
            expected=_build_call(0x004B8C73, 0x004A4720),
            replacement=_build_call(0x004B8C73, 0x004A4720),
            alternates=(old_sign_wrapper_b,),
        ),
        DirectPatch(
            name="restore_source_wrapper_FUN_004B8E20_multiyear",
            site_va=0x004B8F09,
            expected=_build_call(0x004B8F09, 0x004A4720),
            replacement=_build_call(0x004B8F09, 0x004A4720),
            alternates=(old_sign_wrapper_c,),
        ),
        DirectPatch(
            name="restore_source_wrapper_FUN_004B8E20_oneyear",
            site_va=0x004B8F3F,
            expected=_build_call(0x004B8F3F, 0x004A4720),
            replacement=_build_call(0x004B8F3F, 0x004A4720),
            alternates=(old_sign_wrapper_d,),
        ),
        # Stable RC2+ fallback at lookup tail.
        DirectPatch(
            name="lookup_result_fallback_FUN_004B5C20",
            site_va=0x004B5C76,
            expected=unpatched_lookup_bytes,
            replacement=_build_trampoline(0x004B5C76, lookup_helper_va, len(unpatched_lookup_bytes)),
            alternates=(
                old_lookup_bytes,
                old_lookup_trampoline,
                old_lookup_trampoline_v2,
                old_lookup_trampoline_v3,
                old_lookup_trampoline_v4,
            ),
        ),
        DirectPatch(
            name="clear_obsolete_lookup_hook_block",
            site_va=0x004B5C84,
            expected=bytes.fromhex("909090909090909090909090"),
            replacement=bytes.fromhex("909090909090909090909090"),
            alternates=(old_hook_block,),
        ),
        # Proven null guard.
        DirectPatch(
            name="defense_in_depth_textptr_normalize_FUN_0066F1F0",
            site_va=0x0066F1FB,
            expected=bytes.fromhex("8b4c242033f68a472033d28be88a01"),
            replacement=_build_trampoline(0x0066F1FB, CAVE_NULL_GUARD_VA, 15),
            alternates=(old_null_guard_trampoline,),
        ),
        DirectPatch(
            name="formatter_s3_team_lookup_FUN_00499D00",
            site_va=0x00499DA1,
            expected=bytes.fromhex("8b451885c00f84c4000000"),
            replacement=_build_trampoline(0x00499DA1, CAVE_FORMATTER_S3_STAGE0_VA, 11),
        ),
        DirectPatch(
            name="search_hover_blank_special_club_stars_FUN_00405F30",
            site_va=0x00406116,
            expected=bytes.fromhex(
                "668b4618663dac2675058b4610eb1325ffff0000b9e04b750050e8ebfa0a008b4004"
            ),
            replacement=_build_trampoline(0x00406116, CAVE_SEARCH_HOVER_TEAM_VA, 34),
        ),
        DirectPatch(
            name="profile_blank_special_club_stars_FUN_0043EBD0",
            site_va=0x0043F20F,
            expected=bytes.fromhex("8b4710eb21"),
            replacement=_build_trampoline(0x0043F20F, CAVE_PROFILE_SPECIAL_TEAM_VA, 5),
        ),
    ]

    if include_branding:
        # Lightweight branding surface: title strings in .rdata.
        patches.extend(
            [
                DirectPatch(
                    name="brand_title_string_primary",
                    site_va=0x006FC658,
                    expected=TITLE_ORIGINAL,
                    replacement=TITLE_BRANDING,
                ),
                DirectPatch(
                    name="brand_title_string_secondary",
                    site_va=0x006FC670,
                    expected=TITLE_ORIGINAL,
                    replacement=TITLE_BRANDING,
                ),
            ]
        )

    return patches


def apply_patch(
    *,
    input_exe: Path,
    output_exe: Path,
    dry_run: bool,
    force: bool,
    no_branding: bool,
) -> dict[str, Any]:
    input_bytes = input_exe.read_bytes()
    patched = bytearray(input_bytes)

    bundle, string_addrs, legacy_bundle_prefixes = _build_bundle()
    lookup_helper_va = CAVE_BUNDLE_BASE_VA
    patches = _build_patch_plan(lookup_helper_va=lookup_helper_va, include_branding=not no_branding)
    rows: list[dict[str, Any]] = []

    # Write shared fallback bundle.
    bundle_off = _va_to_file_offset(input_bytes, CAVE_BUNDLE_BASE_VA)
    current_bundle = input_bytes[bundle_off: bundle_off + CAVE_BUNDLE_SIZE]

    all_zero = current_bundle == (b"\x00" * CAVE_BUNDLE_SIZE)
    all_cc = current_bundle == (b"\xCC" * CAVE_BUNDLE_SIZE)
    old_bundle_like = any(current_bundle.startswith(prefix) for prefix in legacy_bundle_prefixes)
    new_bundle = current_bundle == bundle
    if not force and not (all_zero or all_cc or old_bundle_like or new_bundle):
        raise RuntimeError(
            "Bundle cave bytes are not recognized (neither pristine nor known previous patch). "
            "Use --force only after manual verification."
        )

    patched[bundle_off: bundle_off + CAVE_BUNDLE_SIZE] = bundle
    rows.append(
        {
            "name": "write_shared_fallback_bundle_cave",
            "site_va": f"0x{CAVE_BUNDLE_BASE_VA:08X}",
            "site_file_offset": f"0x{bundle_off:08X}",
            "site_before": current_bundle[:64].hex(),
            "site_after": bundle[:64].hex(),
            "bytes_written": CAVE_BUNDLE_SIZE,
        }
    )

    for spec in patches:
        site_off = _va_to_file_offset(input_bytes, spec.site_va)
        current_site = input_bytes[site_off: site_off + len(spec.expected)]
        allowed = {spec.expected, spec.replacement, *spec.alternates}
        if current_site not in allowed and not force:
            raise RuntimeError(
                f"Patch-site bytes do not match expected signature for {spec.name}. "
                "Use --force only after manual verification."
            )
        patched[site_off: site_off + len(spec.expected)] = spec.replacement
        rows.append(
            {
                "name": spec.name,
                "site_va": f"0x{spec.site_va:08X}",
                "site_file_offset": f"0x{site_off:08X}",
                "site_before": current_site.hex(),
                "site_after": spec.replacement.hex(),
            }
        )

    null_stub = _build_null_text_guard_stub(
        cave_va=CAVE_NULL_GUARD_VA,
        resume_va=0x0066F20A,
        empty_text_va=string_addrs["empty"],
    )
    old_null_stub = _build_old_null_guard_stub(
        cave_va=CAVE_NULL_GUARD_VA,
        resume_va=0x0066F20A,
        null_target_va=0x0066F243,
    )

    null_off = _va_to_file_offset(input_bytes, CAVE_NULL_GUARD_VA)
    current_null = input_bytes[null_off: null_off + len(null_stub)]
    old_prefix_ok = current_null.startswith(old_null_stub) and all(b == 0 for b in current_null[len(old_null_stub):])

    allowed_null = {b"\x00" * len(null_stub), null_stub}
    if (current_null not in allowed_null) and (not old_prefix_ok) and (not force):
        raise RuntimeError(
            "Null-guard cave bytes are not empty/known. Use --force only after manual verification."
        )

    patched[null_off: null_off + len(null_stub)] = null_stub
    rows.append(
        {
            "name": "write_null_guard_cave",
            "site_va": f"0x{CAVE_NULL_GUARD_VA:08X}",
            "site_file_offset": f"0x{null_off:08X}",
            "site_before": current_null.hex(),
            "site_after": null_stub.hex(),
            "bytes_written": len(null_stub),
        }
    )

    profile_special_stub = _build_profile_special_team_fallback(
        cave_va=CAVE_PROFILE_SPECIAL_TEAM_VA,
        stars_va=string_addrs["stars"],
        resume_va=0x0043F235,
    )
    if len(profile_special_stub) > CAVE_PROFILE_SPECIAL_TEAM_SIZE:
        raise RuntimeError(
            f"Profile special-team cave overflow ({len(profile_special_stub)} > {CAVE_PROFILE_SPECIAL_TEAM_SIZE})"
        )
    profile_special_blob = profile_special_stub + (
        b"\x00" * (CAVE_PROFILE_SPECIAL_TEAM_SIZE - len(profile_special_stub))
    )
    profile_special_off = _va_to_file_offset(input_bytes, CAVE_PROFILE_SPECIAL_TEAM_VA)
    current_profile_special = input_bytes[
        profile_special_off: profile_special_off + CAVE_PROFILE_SPECIAL_TEAM_SIZE
    ]
    allowed_profile_special = {b"\x00" * CAVE_PROFILE_SPECIAL_TEAM_SIZE, profile_special_blob}
    if (current_profile_special not in allowed_profile_special) and (not force):
        raise RuntimeError(
            "Profile special-team cave bytes are not empty/known. Use --force only after manual verification."
        )
    patched[profile_special_off: profile_special_off + CAVE_PROFILE_SPECIAL_TEAM_SIZE] = profile_special_blob
    rows.append(
        {
            "name": "write_profile_special_team_cave",
            "site_va": f"0x{CAVE_PROFILE_SPECIAL_TEAM_VA:08X}",
            "site_file_offset": f"0x{profile_special_off:08X}",
            "site_before": current_profile_special.hex(),
            "site_after": profile_special_blob.hex(),
            "bytes_written": CAVE_PROFILE_SPECIAL_TEAM_SIZE,
        }
    )

    formatter_s3_stage0, formatter_s3_stage1, formatter_s3_stage2, formatter_s3_extra_specs = _build_formatter_s3_zero_team_stars_fallback(
        stage0_va=CAVE_FORMATTER_S3_STAGE0_VA,
        stage1_va=CAVE_FORMATTER_S3_STAGE1_VA,
        stage2_va=CAVE_FORMATTER_S3_STAGE2_VA,
        skip_va=CAVE_FORMATTER_S3_SKIP_VA,
        team_lookup1_va=CAVE_FORMATTER_S3_TEAM_LOOKUP1_VA,
        team_lookup2_va=CAVE_FORMATTER_S3_TEAM_LOOKUP2_VA,
        stars_va=string_addrs["stars"],
        team_lookup_va=0x004B5C20,
        original_push_va=0x00499E62,
        original_skip_va=0x00499E70,
    )
    old_formatter_s3_stage0, old_formatter_s3_stage1, old_formatter_s3_stage2 = _build_formatter_s3_team_lookup_stages(
        stage0_va=CAVE_FORMATTER_S3_STAGE0_VA,
        stage1_va=CAVE_FORMATTER_S3_STAGE1_VA,
        stage2_va=CAVE_FORMATTER_S3_STAGE2_VA,
        team_lookup_va=0x004B5C20,
        original_push_va=0x00499E62,
    )
    formatter_s3_specs = (
        ("write_formatter_s3_stage0_cave", CAVE_FORMATTER_S3_STAGE0_VA, CAVE_FORMATTER_S3_STAGE0_SIZE, formatter_s3_stage0, old_formatter_s3_stage0),
        ("write_formatter_s3_stage1_cave", CAVE_FORMATTER_S3_STAGE1_VA, CAVE_FORMATTER_S3_STAGE1_SIZE, formatter_s3_stage1, old_formatter_s3_stage1),
        ("write_formatter_s3_stage2_cave", CAVE_FORMATTER_S3_STAGE2_VA, CAVE_FORMATTER_S3_STAGE2_SIZE, formatter_s3_stage2, old_formatter_s3_stage2),
    ) + tuple(
        (name, cave_va, cave_size, cave_code, b"")
        for name, cave_va, cave_size, cave_code in formatter_s3_extra_specs
    )
    for name, cave_va, cave_size, cave_code, old_cave_code in formatter_s3_specs:
        if len(cave_code) > cave_size:
            raise RuntimeError(f"{name} overflow ({len(cave_code)} > {cave_size})")
        cave_blob = cave_code + (b"\xCC" * (cave_size - len(cave_code)))
        cave_off = _va_to_file_offset(input_bytes, cave_va)
        current_cave = input_bytes[cave_off: cave_off + cave_size]
        allowed_caves = {b"\xCC" * cave_size, cave_blob}
        if old_cave_code:
            allowed_caves.add(old_cave_code + (b"\xCC" * (cave_size - len(old_cave_code))))
        if (not force) and current_cave not in allowed_caves:
            raise RuntimeError(
                f"{name} cave bytes are not recognized. Use --force only after manual verification."
            )
        patched[cave_off: cave_off + cave_size] = cave_blob
        rows.append(
            {
                "name": name,
                "site_va": f"0x{cave_va:08X}",
                "site_file_offset": f"0x{cave_off:08X}",
                "site_before": current_cave.hex(),
                "site_after": cave_blob.hex(),
                "bytes_written": cave_size,
            }
        )

    output_bytes = bytes(patched)

    target_out = output_exe

    backup_path: Path | None = None
    if not dry_run:
        target_out.parent.mkdir(parents=True, exist_ok=True)
        target_out.write_bytes(output_bytes)

    return {
        "patch_name": "skezmod",
        "input_exe": str(input_exe),
        "output_exe": str(target_out),
        "backup_exe": str(backup_path) if backup_path else None,
        "dry_run": bool(dry_run),
        "patch_count": len(rows),
        "patches": rows,
        "addresses": {
            "bundle_base": f"0x{CAVE_BUNDLE_BASE_VA:08X}",
            "bundle_size": CAVE_BUNDLE_SIZE,
            "lookup_helper": f"0x{lookup_helper_va:08X}",
            "null_guard": f"0x{CAVE_NULL_GUARD_VA:08X}",
            "profile_special_team_fallback": f"0x{CAVE_PROFILE_SPECIAL_TEAM_VA:08X}",
            "formatter_s3_stage0": f"0x{CAVE_FORMATTER_S3_STAGE0_VA:08X}",
            "formatter_s3_stage1": f"0x{CAVE_FORMATTER_S3_STAGE1_VA:08X}",
            "formatter_s3_stage2": f"0x{CAVE_FORMATTER_S3_STAGE2_VA:08X}",
            "search_hover_team_fallback": f"0x{CAVE_SEARCH_HOVER_TEAM_VA:08X}",
            "empty": f"0x{string_addrs['empty']:08X}",
            "stars": f"0x{string_addrs['stars']:08X}",
            "free": f"0x{string_addrs['free']:08X}",
            "unknown": f"0x{string_addrs['unknown']:08X}",
        },
        "sha256": {
            "input": _sha256(input_bytes),
            "output": _sha256(output_bytes),
        },
        "notes": [
            "SkezMod v0.1 patch set (includes Stars hover fix from RC2+).",
            "Keeps RC2 null-guard path for 0x0066F208 dereference.",
            "Adds FUN_004B5C20 miss fallback to safe non-null records (Unknown/Stars/Free players).",
            "Adds formatter-local {S3} fallback: non-null S3 is preserved, nonzero event team ids use central lookup, zero-team signing notices use Stars.",
            "Adds search hover/status fallback: blank 0x26AC club text -> Stars.",
            "Adds player-record fallback: blank 0x26AC club text -> Stars.",
            "RC1 source-wrapper hooks are explicitly removed/restored to original calls.",
            (
                "Title branding patches disabled via --no-branding; binary title strings left unchanged."
                if no_branding
                else "Applies title branding strings: 'PM99 SkezMod 0.1'."
            ),
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run from the root of your Premier Manager 99 install directory.\n"
            "Default command: ./skezmod.py"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate and report only")
    parser.add_argument(
        "--no-branding",
        action="store_true",
        help="Do not apply EXE title branding patches; keep original title strings",
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
            f"{input_exe.resolve()}\n"
            "Run this from your Premier Manager Ninety Nine install directory."
        )

    staged_exe = input_exe.with_name(DEFAULT_OUTPUT_NAME)
    stale_staged = staged_exe.exists()
    total_steps = 2 if args.dry_run else (7 if stale_staged else 6)

    def stage(step: int, message: str) -> None:
        print(f"[{step}/{total_steps}] {message}")

    print(ASCII_BRAND)
    stage(1, f"Checking source binary: {input_exe}")

    if args.dry_run:
        report = apply_patch(
            input_exe=input_exe,
            output_exe=staged_exe,
            dry_run=True,
            force=bool(args.force),
            no_branding=bool(args.no_branding),
        )
        stage(2, "Dry-run validation complete (no files modified).")
    else:
        apply_step = 3
        if stale_staged:
            stage(2, f"Removing stale staged file: {staged_exe.name}")
            staged_exe.unlink()
            stage(3, f"Creating staged copy: {staged_exe.name}")
            apply_step = 4
        else:
            stage(2, f"Creating staged copy: {staged_exe.name}")

        shutil.copy2(input_exe, staged_exe)

        stage(apply_step, "Applying Stars Patch to staged copy")
        report = apply_patch(
            input_exe=staged_exe,
            output_exe=staged_exe,
            dry_run=False,
            force=bool(args.force),
            no_branding=bool(args.no_branding),
        )

        stage(apply_step + 1, "Verifying staged patch idempotence/signatures")
        apply_patch(
            input_exe=staged_exe,
            output_exe=staged_exe,
            dry_run=True,
            force=bool(args.force),
            no_branding=bool(args.no_branding),
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
            # Best-effort rollback to avoid leaving the install without MANAGPRE.EXE.
            if backup_path.exists() and not input_exe.exists():
                backup_path.rename(input_exe)
            raise RuntimeError(f"Promotion failed; original restored: {exc}") from exc

        report["input_exe"] = str(input_exe)
        report["output_exe"] = str(input_exe)
        report["backup_exe"] = str(backup_path)
        report["notes"].append(
            "Defensive staged flow completed: copy -> patch -> verify -> rotate -> promote."
        )

    json_text = json.dumps(report, indent=2)
    if args.json_output:
        out = Path(args.json_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json_text + "\n", encoding="utf-8")

    if args.dry_run:
        print("Stars Patch Dry-Run OK: no files modified.")
    else:
        print(f"Stars Patch Applied OK: {report.get('output_exe', '')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
