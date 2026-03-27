#!/usr/bin/env python3
"""Patch MANAGPRE.EXE with Valderrama-safe guard and source-club fallbacks.

Patch contract (MANAGPRE only):
- Keep the proven null-pointer defense at FUN_0066f1f0 (0x0066F208 crash guard).
- Add conservative lookup-result fallback for unresolved/invalid club names at
  FUN_004B5C20 tail hook (0x004B5C76):
  - team_id 0    -> "Unknown club"
  - team_id 4705 -> "Stars"
  - team_id 4706 -> "Free players"
- Add targeted search-window team-string normalization in FUN_00474870
  pre-sprintf path (0x0047494B), forcing a non-empty text for Stars/Free/Unknown.
- Add field-level empty-text fallback in search hover path
  (0x0041E74B..0x0041E750) so the final draw pointer resolves to "Unknown club"
  only when the lookup result is an empty string.
- Guard FUN_00499D00 raw %s token branches ({D1}, {S2}, {S3}) against low
  numeric IDs so formatter paths do not treat IDs as pointers.
- Revert older experimental upstream trampolines so the script is idempotent over
  previous patch variants.

This script intentionally avoids variable-length/data-file edits.
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


REPO_ROOT = Path(__file__).resolve().parents[2]


def _resolve_pm99_root() -> Path:
    rel_exe = Path(".local") / "premier-manager-ninety-nine" / "MANAGPRE.EXE"
    candidates = (REPO_ROOT, REPO_ROOT.parents[1])
    for base in candidates:
        if (base / rel_exe).exists():
            return base
    return REPO_ROOT.parents[1]


PM99_ROOT = _resolve_pm99_root()
DEFAULT_INPUT_EXE = PM99_ROOT / ".local" / "premier-manager-ninety-nine" / "MANAGPRE.EXE"
DEFAULT_OUTPUT_EXE = Path("/tmp") / "MANAGPRE.valderrama_guard.EXE"
STABLE_BASELINE_EXE = (
    PM99_ROOT
    / ".local"
    / "premier-manager-ninety-nine"
    / "MANAGPRE.EXE.stable_unknownclub_20260310_130159"
)
IMAGE_BASE = 0x400000

TEAM_ID_STARS = 4705
TEAM_ID_FREE_PLAYERS = 4706

# Slack region at tail of .text (file-backed): 0x006E5092..0x006E51BF (302 bytes)
CAVE_BUNDLE_BASE_VA = 0x006E5092
CAVE_BUNDLE_SIZE = 302

# Keep these string addresses stable so legacy patched bytes remain compatible.
CAVE_EMPTY_STRING_VA = 0x006E5199
CAVE_STARS_STRING_VA = 0x006E519A
CAVE_FREE_STRING_VA = 0x006E51A0
CAVE_UNKNOWN_STRING_VA = 0x006E51AD

# Spare tail-cave slot used for club-name pointer guard helper.
CAVE_NAME_PTR_GUARD_HELPER_VA = 0x006E51E1
CAVE_NAME_PTR_GUARD_HELPER_SIZE = 31
FORMATTTER_ARG3_GUARD_VA = CAVE_NAME_PTR_GUARD_HELPER_VA
FORMATTTER_ARG3_GUARD_SIZE = CAVE_NAME_PTR_GUARD_HELPER_SIZE
FORMATTTER_ARG3_CALL_THUNK_VA = 0x006E518B
FORMATTTER_ARG3_CALL_THUNK_SIZE = 6

# Local NOP-sled cave in FUN_00499D00 reused for post-FUN_0049A0E0 formatter wrapper.
CAVE_LE_DE_WRAPPER_VA = 0x00499E91
CAVE_LE_DE_WRAPPER_SIZE = 15

# Local alignment caves used to normalize NULL/empty token text in FUN_00499D00.
CAVE_TOKEN_NULL_NORM_HELPER_VA = 0x00404A41
CAVE_TOKEN_NULL_NORM_HELPER_SIZE = 15
CAVE_TOKEN_NULL_PUSH_HELPER_VA = 0x004049D4
CAVE_TOKEN_NULL_PUSH_HELPER_SIZE = 12

# Local two-stage caves for {D1} token raw %s pointer guard.
CAVE_D1_PTR_STAGE1_VA = 0x00468C81
CAVE_D1_PTR_STAGE1_SIZE = 15
CAVE_D1_PTR_STAGE2_VA = 0x00468F61
CAVE_D1_PTR_STAGE2_SIZE = 15

# Local legacy helper cave (kept for idempotent cleanup of older variants).
CAVE_LOOKUP_MISS_HELPER_VA = 0x0046B781
CAVE_LOOKUP_MISS_HELPER_SIZE = 15

# .text zero-cave used by hover/search draw sanitization helper.
CAVE_HOVER_DRAW_HELPER_VA = 0x005FC92F
CAVE_HOVER_DRAW_HELPER_SIZE = 24

# Null guard cave remains at proven location.
CAVE_NULL_GUARD_VA = 0x006E51C0

# Secondary object-chain null guard for crash at 0x0064CFD6.
SECONDARY_CHAIN_GUARD_SITE_VA = 0x0064CFD6
SECONDARY_CHAIN_GUARD_SITE_LEN = 15
SECONDARY_CHAIN_GUARD_STAGE0_VA = 0x0064CFFA  # 6-byte local NOP cave
SECONDARY_CHAIN_GUARD_STAGE0_SIZE = 6
SECONDARY_CHAIN_GUARD_STAGE1_VA = 0x0064CE25  # 11-byte local NOP cave
SECONDARY_CHAIN_GUARD_STAGE1_SIZE = 11
SECONDARY_CHAIN_GUARD_STAGE2_VA = 0x0064D077  # 9-byte local NOP cave
SECONDARY_CHAIN_GUARD_STAGE2_SIZE = 9

# Search-hover field-level empty-text fallback stages (0x0041E74B/0x0041E750).
CAVE_HOVER_FIELD_STAGE1_VA = 0x006E4191  # 15-byte INT3 cave
CAVE_HOVER_FIELD_STAGE1_SIZE = 15
CAVE_HOVER_FIELD_STAGE2_VA = 0x006E4251  # 15-byte INT3 cave
CAVE_HOVER_FIELD_STAGE2_SIZE = 15
CAVE_HOVER_FIELD_STAGE3_VA = 0x006E42D1  # 15-byte INT3 cave
CAVE_HOVER_FIELD_STAGE3_SIZE = 15
# Dedicated runtime-probe helper cave (kept isolated from production helpers).
CAVE_RUNTIME_PROBE_HELPER_VA = 0x006E42F5  # 11-byte INT3 cave
CAVE_RUNTIME_PROBE_HELPER_SIZE = 11
# Field-local draw-call wrappers (dedicated INT3 caves; avoid shared lookup paths).
CAVE_BIO_DRAW_WRAPPER_VA = 0x006C4241
CAVE_BIO_DRAW_WRAPPER_SIZE = 15
CAVE_HOVER_DRAW_WRAPPER_VA = 0x006C42D2
CAVE_HOVER_DRAW_WRAPPER_SIZE = 14

PATCH_MODES = ("stable", "instrument", "final")
PROBE_IDS = (
    "hover_field_stage3",
    "bio_copy_src_43f24f",
    "postcall_68e52",
    "postcall_43bd46",
    "lookup_call_68167",
    "lookup_call_681db",
    "lookup_call_6824b",
)
SESSION1_PROBE_SEQUENCE = (
    "hover_field_stage3",
    "bio_copy_src_43f24f",
    "postcall_68e52",
    "postcall_43bd46",
    "lookup_call_68167",
    "lookup_call_681db",
    "lookup_call_6824b",
)
TRACE_BREAKPOINTS_BY_FIELD: dict[str, tuple[int, ...]] = {
    "search_hover": (
        0x0041E74B,
        0x0041E756,
        0x00468E4D,
        0x00468E52,
        0x0049A478,
        0x0049A486,
    ),
    "player_bio": (
        0x0043BD41,
        0x0043BD46,
        0x0043F24F,
        0x0049A478,
        0x0049A486,
    ),
}

# Known-bad signature that caused arg-shift crash at 0x0049A48D.
KNOWN_BAD_LOOKUP_MISS_SIG = bytes.fromhex("8b442414e802faffff5f5e5d5bc20800")


@dataclass(frozen=True)
class DirectPatch:
    name: str
    site_va: int
    expected: bytes
    replacement: bytes
    alternates: tuple[bytes, ...] = ()
    known_bad: tuple[bytes, ...] = ()


def _sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _is_runtime_probe_id(probe_id: str | None) -> bool:
    return bool(probe_id) and probe_id.startswith("runtime_")


def _parse_va(text: str, *, arg_name: str) -> int:
    try:
        value = int(text, 0)
    except ValueError as exc:
        raise ValueError(f"{arg_name} must be a valid integer/hex literal, got: {text!r}") from exc
    if value < IMAGE_BASE:
        raise ValueError(f"{arg_name} must be a virtual address >= 0x{IMAGE_BASE:08X}, got 0x{value:08X}")
    return value


def _parse_hex_bytes(text: str, *, arg_name: str) -> bytes:
    cleaned = text.strip().replace(" ", "")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{arg_name} must be valid hex bytes, got: {text!r}") from exc
    return data


def _build_ownership_manifest(*, script_path: Path, input_exe: Path) -> dict[str, Any]:
    base_cmd = f"python3 {script_path}"
    probe_cmds = [
        f"{base_cmd} --input-exe {input_exe} --in-place --mode instrument --probe-id {probe_id}"
        for probe_id in SESSION1_PROBE_SEQUENCE
    ]
    runtime_probe_example = (
        f"{base_cmd} --input-exe {input_exe} --in-place --mode instrument "
        "--probe-id runtime_search_hover_owner "
        "--runtime-probe-site-va 0x00400000 "
        "--runtime-probe-expected-hex e800000000 "
        "--runtime-probe-original-target-va 0x0049A410 "
        "--runtime-probe-pop-bytes 4"
    )
    winedbg_breakpoints = {
        field: [f"break *0x{va:08X}" for va in addrs]
        for field, addrs in TRACE_BREAKPOINTS_BY_FIELD.items()
    }
    return {
        "summary": "Runtime ownership tracing manifest for last binary pass (2 sessions hard stop).",
        "session_1": {
            "reset_to_stable": f"{base_cmd} --input-exe {input_exe} --in-place --mode stable",
            "probe_sequence": list(SESSION1_PROBE_SEQUENCE),
            "probe_commands": probe_cmds,
            "proof_rule": (
                "Owner proven only if marker appears in exactly one target field in 2 consecutive clean launches, "
                "then disappears after stable->final reset."
            ),
            "revert_to_final": [
                f"{base_cmd} --input-exe {input_exe} --in-place --mode stable",
                f"{base_cmd} --input-exe {input_exe} --in-place --mode final",
            ],
        },
        "session_2": {
            "reset_to_stable": f"{base_cmd} --input-exe {input_exe} --in-place --mode stable",
            "winedbg_breakpoint_recipes": winedbg_breakpoints,
            "runtime_probe_promotion_example": runtime_probe_example,
            "stop_gate": "If no exact owner is proven for unresolved field(s) by end of Session 2: stop binary hunting.",
        },
    }


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


def _build_null_text_guard_stub(*, cave_va: int, resume_va: int, fallback_text_va: int) -> bytes:
    """Replays overwritten setup and normalizes NULL text ptr to a fallback label."""
    out = bytearray()

    # Original bytes from 0x0066F1FB up to (but excluding) MOV AL,[ECX].
    out += bytes.fromhex("8b4c242033f68a472033d28be8")

    # test ecx,ecx
    out += b"\x85\xC9"

    # jnz continue
    jnz_pos = len(out)
    out += b"\x0F\x85" + b"\x00\x00\x00\x00"

    # mov ecx, fallback_text
    out += b"\xB9" + struct.pack("<I", fallback_text_va)

    continue_va = cave_va + len(out)

    # original faulting read
    out += b"\x8A\x01"

    # jmp resume
    jmp_resume_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    out[jnz_pos + 2: jnz_pos + 6] = _rel32(cave_va + jnz_pos, 6, continue_va)
    out[jmp_resume_pos + 1: jmp_resume_pos + 5] = _rel32(cave_va + jmp_resume_pos, 5, resume_va)
    return bytes(out)


def _build_old_null_guard_stub(*, cave_va: int, resume_va: int, null_target_va: int) -> bytes:
    """Legacy v1 guard accepted for idempotent upgrades."""
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


def _build_search_window_team_prepush_helper(
    *,
    cave_va: int,
    stars_va: int,
    free_va: int,
    unknown_va: int,
) -> bytes:
    """Prepare FUN_00474870 sprintf args with ID-aware team-name fallback.

    Hook contract at 0x0047494B:
    - Input:
      - EAX: team record pointer from FUN_004B5C20
      - ESI: player record pointer
    - Output:
      - Pushes team_name, [esi+0x0c], [esi+0x08] (original order), then RET.
    """
    out = bytearray()

    # Capture CALL return address so we can rebuild stack as:
    # [esp] return, [esp+4] arg3, [esp+8] arg2, [esp+12] arg1
    out += b"\x59"  # pop ecx

    out += b"\x66\x81\x7E\x18" + struct.pack("<H", TEAM_ID_STARS)
    je_stars_pos = len(out)
    out += b"\x74\x00"

    out += b"\x66\x81\x7E\x18" + struct.pack("<H", TEAM_ID_FREE_PLAYERS)
    je_free_pos = len(out)
    out += b"\x74\x00"

    out += b"\x66\x83\x7E\x18\x00"
    je_unknown_pos = len(out)
    out += b"\x74\x00"

    # Default branch: use looked-up team text if valid, otherwise Unknown.
    out += b"\x85\xC0"  # test eax,eax
    jz_unknown_2_pos = len(out)
    out += b"\x74\x00"
    out += b"\x8B\x40\x04"  # mov eax,[eax+0x04]
    out += b"\x85\xC0"  # test eax,eax
    jz_unknown_3_pos = len(out)
    out += b"\x74\x00"
    out += b"\x8A\x10"  # mov dl,[eax]
    out += b"\x84\xD2"  # test dl,dl
    jz_unknown_4_pos = len(out)
    out += b"\x74\x00"
    out += b"\x80\xFA\x2E"  # cmp dl,'.'
    jbe_unknown_5_pos = len(out)
    out += b"\x76\x00"
    out += b"\x80\xFA\x7A"  # cmp dl,'z'
    ja_unknown_6_pos = len(out)
    out += b"\x77\x00"
    jmp_have_1_pos = len(out)
    out += b"\xEB\x00"

    set_stars_va = cave_va + len(out)
    out += b"\xB8" + struct.pack("<I", stars_va)
    jmp_have_2_pos = len(out)
    out += b"\xEB\x00"

    set_free_va = cave_va + len(out)
    out += b"\xB8" + struct.pack("<I", free_va)
    jmp_have_3_pos = len(out)
    out += b"\xEB\x00"

    set_unknown_va = cave_va + len(out)
    out += b"\xB8" + struct.pack("<I", unknown_va)

    have_va = cave_va + len(out)
    out += b"\x8B\x56\x0C"  # mov edx,[esi+0x0c]
    out += b"\x50"  # push eax (arg1 team name)
    out += b"\x8B\x46\x08"  # mov eax,[esi+0x08]
    out += b"\x52"  # push edx (arg2)
    out += b"\x50"  # push eax (arg3)
    out += b"\x51"  # push ecx (saved return address)
    out += b"\xC3"  # ret

    out[je_stars_pos + 1] = (set_stars_va - (cave_va + je_stars_pos + 2)) & 0xFF
    out[je_free_pos + 1] = (set_free_va - (cave_va + je_free_pos + 2)) & 0xFF
    out[je_unknown_pos + 1] = (set_unknown_va - (cave_va + je_unknown_pos + 2)) & 0xFF
    out[jz_unknown_2_pos + 1] = (set_unknown_va - (cave_va + jz_unknown_2_pos + 2)) & 0xFF
    out[jz_unknown_3_pos + 1] = (set_unknown_va - (cave_va + jz_unknown_3_pos + 2)) & 0xFF
    out[jz_unknown_4_pos + 1] = (set_unknown_va - (cave_va + jz_unknown_4_pos + 2)) & 0xFF
    out[jbe_unknown_5_pos + 1] = (set_unknown_va - (cave_va + jbe_unknown_5_pos + 2)) & 0xFF
    out[ja_unknown_6_pos + 1] = (set_unknown_va - (cave_va + ja_unknown_6_pos + 2)) & 0xFF
    out[jmp_have_1_pos + 1] = (have_va - (cave_va + jmp_have_1_pos + 2)) & 0xFF
    out[jmp_have_2_pos + 1] = (have_va - (cave_va + jmp_have_2_pos + 2)) & 0xFF
    out[jmp_have_3_pos + 1] = (have_va - (cave_va + jmp_have_3_pos + 2)) & 0xFF

    return bytes(out)


def _build_team_name_ptr_guard_helper(*, cave_va: int, fallback_text_va: int) -> bytes:
    """Normalize team-record -> team-name pointer at FUN_00499D00 token branches.

    Input:
    - EAX: candidate team-record pointer
    Output:
    - EAX: validated non-empty team-name pointer, else fallback_text_va
    """
    out = bytearray()

    out += b"\x85\xC0"  # test eax,eax
    jz_fallback_pos = len(out)
    out += b"\x74\x00"
    out += b"\x8B\x40\x04"  # mov eax,[eax+0x04]
    out += b"\x85\xC0"  # test eax,eax
    jz_fallback_0_pos = len(out)
    out += b"\x74\x00"
    out += b"\x8A\x10"  # mov dl,[eax]
    out += b"\x84\xD2"  # test dl,dl
    jz_fallback_2_pos = len(out)
    out += b"\x7E\x00"  # jle fallback (zero/high-bit bytes are invalid)
    out += b"\x80\xFA\x2E"  # cmp dl,'.'
    jbe_fallback_3_pos = len(out)
    out += b"\x76\x00"
    ret_va = cave_va + len(out)
    out += b"\xC3"  # ret
    fallback_va = cave_va + len(out)
    out += b"\xB8" + struct.pack("<I", fallback_text_va)  # mov eax,<fallback text>
    out += b"\xC3"

    out[jz_fallback_pos + 1] = (fallback_va - (cave_va + jz_fallback_pos + 2)) & 0xFF
    out[jz_fallback_0_pos + 1] = (fallback_va - (cave_va + jz_fallback_0_pos + 2)) & 0xFF
    out[jz_fallback_2_pos + 1] = (fallback_va - (cave_va + jz_fallback_2_pos + 2)) & 0xFF
    out[jbe_fallback_3_pos + 1] = (fallback_va - (cave_va + jbe_fallback_3_pos + 2)) & 0xFF

    return bytes(out)


def _build_search_token_le_de_call_wrapper(*, cave_va: int, original_lookup_va: int) -> bytes:
    """Wrapper for 0x00499E0A call site ({LE}/{DE} token branch).

    Behavior:
    - call original FUN_004A4720
    - if EAX == NULL, fall back to pre-pushed team base-name pointer ([esp+0x10])
    - return EAX to caller
    """
    out = bytearray()

    call_pos = len(out)
    out += b"\xE8" + b"\x00\x00\x00\x00"  # call original lookup
    out += b"\x85\xC0"  # test eax,eax
    jnz_ret_pos = len(out)
    out += b"\x75\x00"
    out += b"\x8B\x44\x24\x10"  # mov eax,[esp+0x10]
    ret_va = cave_va + len(out)
    out += b"\xC3"

    out[call_pos + 1: call_pos + 5] = _rel32(cave_va + call_pos, 5, original_lookup_va)
    out[jnz_ret_pos + 1] = (ret_va - (cave_va + jnz_ret_pos + 2)) & 0xFF
    return bytes(out)


def _build_lowptr_string_guard_helper(*, fallback_text_va: int, min_ptr: int = 0x00010000) -> bytes:
    """Guard helper for raw %s arguments that may actually be small numeric IDs.

    Input:
    - EAX: candidate pointer
    Output:
    - EAX unchanged if >= min_ptr, otherwise fallback_text_va
    """
    out = bytearray()
    out += b"\x3D" + struct.pack("<I", min_ptr)  # cmp eax,<min ptr>
    out += b"\x73\x05"  # jae ret_ok
    out += b"\xB8" + struct.pack("<I", fallback_text_va)  # mov eax,<fallback text>
    out += b"\xC3"  # ret
    return bytes(out)


def _build_token_null_norm_helper(*, fallback_text_va: int) -> bytes:
    """Normalize EAX when token source pointer is NULL/empty; no stack side effects."""
    out = bytearray()
    out += b"\x85\xC0"  # test eax,eax
    out += b"\x74\x05"  # jz set-fallback
    out += b"\x80\x38\x00"  # cmp byte ptr [eax],0
    out += b"\x75\x05"  # jnz ret
    out += b"\xB8" + struct.pack("<I", fallback_text_va)  # mov eax,<fallback>
    out += b"\xC3"  # ret
    return bytes(out)


def _build_token_null_push_helper(*, norm_helper_va: int, cave_va: int) -> bytes:
    """Normalize EAX via helper, then push EAX for inline sprintf token paths."""
    out = bytearray()
    out += b"\xE8" + _rel32(cave_va, 5, norm_helper_va)  # call normalizer
    # Preserve caller return address while leaving normalized EAX pushed for caller:
    # before: [esp]=ret
    # after:  ret to caller, stack top in caller becomes normalized arg
    out += b"\x87\x04\x24"  # xchg eax,[esp]
    out += b"\x50"  # push eax (original return address)
    out += b"\xC3"  # ret
    return bytes(out)


def _build_search_token_d1_ptr_stage1(
    *,
    cave_va: int,
    lowptr_guard_va: int,
    stage2_va: int,
) -> bytes:
    """Stage1 for FUN_00499D00 {D1} branch low-pointer guard.

    Rebuilds:
    - mov eax,[ebp+0x10]
    - normalize via shared low-pointer helper
    - push eax
    - jump stage2
    """
    out = bytearray()
    out += b"\x8B\x45\x10"  # mov eax,[ebp+0x10]
    out += b"\xE8" + _rel32(cave_va + len(out), 5, lowptr_guard_va)  # call lowptr guard
    out += b"\x50"  # push eax
    out += b"\xE9" + _rel32(cave_va + len(out), 5, stage2_va)  # jmp stage2
    return bytes(out)


def _build_search_token_d1_ptr_stage2(*, cave_va: int, resume_va: int) -> bytes:
    """Stage2 for FUN_00499D00 {D1} branch.

    Rebuilds:
    - push 0x0072D414
    - jump back to 0x00499E68
    """
    out = bytearray()
    out += b"\x68" + struct.pack("<I", 0x0072D414)  # push 0x72d414
    out += b"\xE9" + _rel32(cave_va + len(out), 5, resume_va)  # jmp resume
    return bytes(out)


def _build_lookup_nonempty_wrapper_stage1(
    *,
    cave_va: int,
    stage2_va: int,
) -> bytes:
    """Post-call sanitizer stage1 for FUN_0049A410 results.

    Behavior:
    - always dispatch to stage2, which performs full first-byte validation.
    """
    out = bytearray()
    out += b"\xE9" + _rel32(cave_va + len(out), 5, stage2_va)  # jmp stage2
    out += b"\xC3"  # legacy-size filler / safety return
    return bytes(out)


def _build_lookup_nonempty_wrapper_stage2(*, unknown_va: int, sanitize_helper_va: int, cave_va: int) -> bytes:
    """Stage2 dispatcher for FUN_0049A410 return.

    Input:
    - EAX: returned string pointer from FUN_0049A410
    Output:
    - NULL -> returns static "Unknown club" pointer
    - non-NULL -> tail-jumps to sanitize helper (may copy fallback in-place)
    """
    out = bytearray()
    out += b"\x85\xC0"  # test eax,eax
    out += b"\x75\x06"  # jnz sanitize-path
    out += b"\xB8" + struct.pack("<I", unknown_va)  # mov eax,<unknown>
    out += b"\xC3"  # ret
    out += b"\xE9" + _rel32(cave_va + len(out), 5, sanitize_helper_va)  # jmp sanitize-helper
    return bytes(out)


def _build_stack_slot_fill_bridge(*, cave_va: int, stack_disp: int, sanitize_helper_va: int) -> bytes:
    """Load a caller stack-slot pointer into EAX and tail-jump to fill helper."""
    if not 0 <= stack_disp <= 0xFF:
        raise ValueError(f"stack_disp out of range: {stack_disp}")
    out = bytearray()
    out += b"\x8B\x44\x24" + bytes((stack_disp,))  # mov eax,[esp+disp8]
    out += b"\xE9" + _rel32(cave_va + len(out), 5, sanitize_helper_va)  # jmp fill helper
    return bytes(out)


def _build_lookup_nonempty_sanitize_helper(*, unknown_va: int) -> bytes:
    """Validate first byte of EAX string and copy fallback text if invalid.

    Input:
    - EAX: destination/output text pointer (non-NULL)
    Output:
    - EAX unchanged if first byte looks valid
    - otherwise writes "Unknown club" into EAX via lstrcpyA and returns EAX
    """
    out = bytearray()
    out += b"\x8A\x10"  # mov dl,[eax]
    out += b"\x84\xD2"  # test dl,dl
    jz_copy_pos = len(out)
    out += b"\x74\x00"
    out += b"\x80\xFA\x2E"  # cmp dl,'.'
    jbe_copy_pos = len(out)
    out += b"\x76\x00"
    out += b"\x80\xFA\x7A"  # cmp dl,'z'
    ja_copy_pos = len(out)
    out += b"\x77\x00"
    out += b"\xC3"  # ret (valid)

    copy_va = len(out)
    out += b"\x68" + struct.pack("<I", unknown_va)  # push "Unknown club"
    out += b"\x50"  # push eax (dest)
    out += b"\xFF\x15" + struct.pack("<I", 0x006E6108)  # call dword ptr [lstrcpyA]
    out += b"\xC3"

    out[jz_copy_pos + 1] = (copy_va - (jz_copy_pos + 2)) & 0xFF
    out[jbe_copy_pos + 1] = (copy_va - (jbe_copy_pos + 2)) & 0xFF
    out[ja_copy_pos + 1] = (copy_va - (ja_copy_pos + 2)) & 0xFF
    return bytes(out)


def _build_lookup_caller_nonempty_wrapper(
    *,
    cave_va: int,
    lookup_va: int,
    stage2_va: int,
    unknown_va: int,
) -> bytes:
    """Post-call helper: EAX points to destination buffer from FUN_0049A410.

    If destination is empty, copy "Unknown club" in place; always return EAX.
    Extra parameters are retained for call-site compatibility with older script
    revisions that built a two-stage wrapper in this cave.
    """
    del cave_va, lookup_va, stage2_va
    out = bytearray()
    out += b"\x85\xC0"  # test eax,eax
    out += b"\x74\x10"  # jz done
    out += b"\x80\x38\x41"  # cmp byte ptr [eax],0x41
    out += b"\x72\x09"  # jb fallback
    out += b"\x80\x38\x7A"  # cmp byte ptr [eax],0x7a
    out += b"\x76\x07"  # jbe done
    out += b"\x68" + struct.pack("<I", unknown_va)  # push "Unknown club"
    out += b"\x50"  # push eax
    out += b"\xFF\x15" + struct.pack("<I", 0x006E6108)  # call dword ptr [lstrcpyA]
    out += b"\xC3"  # ret
    return bytes(out)


def _build_source_ptr_fallback_helper(*, unknown_va: int) -> bytes:
    """Normalize source-string pointer in EAX for hover-draw path.

    Returns:
    - EAX unchanged when it looks like a plausible text pointer.
    - EAX = "Unknown club" pointer when NULL/low/empty-ish.

    Important: no destination-memory writes are performed here.
    """
    out = bytearray()
    out += b"\x85\xC0"  # test eax,eax
    jz_set_pos = len(out)
    out += b"\x74\x00"  # jz set_unknown
    out += b"\x3D\x00\x00\x01\x00"  # cmp eax,0x10000
    jb_set_pos = len(out)
    out += b"\x72\x00"  # jb set_unknown
    out += b"\x80\x38\x2E"  # cmp byte ptr [eax],'.'
    ja_done_pos = len(out)
    out += b"\x77\x00"  # ja done

    set_unknown_pos = len(out)
    out += b"\xB8" + struct.pack("<I", unknown_va)  # mov eax,unknown
    done_pos = len(out)
    out += b"\xC3"  # ret

    out[jz_set_pos + 1] = (set_unknown_pos - (jz_set_pos + 2)) & 0xFF
    out[jb_set_pos + 1] = (set_unknown_pos - (jb_set_pos + 2)) & 0xFF
    out[ja_done_pos + 1] = (done_pos - (ja_done_pos + 2)) & 0xFF
    return bytes(out)


def _build_lstrcpy_src_empty_fallback_helper(*, unknown_va: int) -> bytes:
    """lstrcpyA shim used at source-copy callsites.

    Reads source pointer from [esp+8]. If source is NULL/low-address or appears
    empty (<= '.'), rewrites source arg to "Unknown club" and tail-jumps to lstrcpyA.
    """
    out = bytearray()
    out += b"\x8B\x44\x24\x08"  # mov eax,[esp+8]
    out += b"\x3D\x00\x00\x01\x00"  # cmp eax,0x10000
    out += b"\x72\x05"  # jb fallback
    out += b"\x80\x38\x2E"  # cmp byte ptr [eax],'.'
    out += b"\x77\x08"  # ja copy_call
    out += b"\xC7\x44\x24\x08" + struct.pack("<I", unknown_va)  # fallback: mov dword ptr [esp+8],unknown
    out += b"\xFF\x25" + struct.pack("<I", 0x006E6108)  # jmp dword ptr [lstrcpyA]
    return bytes(out)


def _build_lstrcpy_force_src_helper(*, marker_va: int) -> bytes:
    """lstrcpyA shim used for instrumentation probes.

    Always rewrites source argument ([esp+8]) to marker_va, then tail-jumps to
    lstrcpyA.
    """
    out = bytearray()
    out += b"\xC7\x44\x24\x08" + struct.pack("<I", marker_va)  # mov dword ptr [esp+8],marker
    out += b"\xFF\x25" + struct.pack("<I", 0x006E6108)  # jmp dword ptr [lstrcpyA]
    return bytes(out)


def _build_search_hover_field_stage3_force_marker(*, cave_va: int, resume_va: int, marker_va: int) -> bytes:
    """Instrumentation stage3: force EAX to marker pointer and resume draw path."""
    out = bytearray()
    out += b"\xB8" + struct.pack("<I", marker_va)  # mov eax,marker
    out += b"\xE9" + _rel32(cave_va + len(out), 5, resume_va)  # jmp resume
    return bytes(out)


def _build_return_marker_ptr_bridge(*, marker_va: int) -> bytes:
    """Minimal callsite bridge for instrumentation probes."""
    return b"\xB8" + struct.pack("<I", marker_va) + b"\xC3"  # mov eax,marker ; ret


def _build_return_marker_ptr_stdcall2(*, marker_va: int) -> bytes:
    """Instrumentation helper for stdcall-style callsites with two args.

    Returns marker pointer in EAX and pops 8 bytes of arguments.
    """
    return b"\xB8" + struct.pack("<I", marker_va) + b"\xC2\x08\x00"


def _build_return_marker_ptr_ret_n(*, marker_va: int, pop_bytes: int) -> bytes:
    """Return marker pointer in EAX and emit ret style matching callsite stack discipline.

    pop_bytes:
    - 0  -> ret
    - 4  -> ret 4
    - 8  -> ret 8
    """
    if pop_bytes == 0:
        return b"\xB8" + struct.pack("<I", marker_va) + b"\xC3"
    if pop_bytes in (4, 8):
        return b"\xB8" + struct.pack("<I", marker_va) + b"\xC2" + struct.pack("<H", pop_bytes)
    raise ValueError(f"Unsupported pop_bytes for runtime probe helper: {pop_bytes}")


def _probe_unknown_text(probe_id: str | None) -> str:
    if not probe_id:
        return "Unknown club"
    marker = f"[PRB:{probe_id}]"
    if len(marker) > 18:
        marker = marker[:18]
    return marker


def _reject_known_bad_signature(
    *,
    current: bytes,
    known_bad: tuple[bytes, ...],
    context: str,
    force_known_legacy: bool,
) -> None:
    if force_known_legacy:
        return
    if any(current == sig or current.startswith(sig) for sig in known_bad):
        raise RuntimeError(
            f"{context} matches known-bad legacy signature. "
            "Use --force-known-legacy only for controlled migration."
        )


def _build_post_formatter_sanitize_wrapper(
    *,
    cave_va: int,
    formatter_va: int,
    sanitize_helper_va: int,
) -> bytes:
    """Wrapper used at FUN_0049A0E0+0x23 (0x0049A103).

    Stack contract at entry:
    - [esp+0x00] = return address to 0x0049A108
    - [esp+0x04] = arg1/destination buffer pointer for FUN_00499D00
    - [esp+0x08] = arg2 token source pointer
    - [esp+0x0c] = arg3 format/template pointer

    Behavior:
    - call original formatter
    - sanitize destination text in-place (Unknown club fallback on invalid/empty)
    - return to caller; caller still performs original `add esp,0xc`.
    """
    out = bytearray()
    out += b"\xE8" + _rel32(cave_va + len(out), 5, formatter_va)  # call FUN_00499D00
    out += b"\x8B\x44\x24\x04"  # mov eax,[esp+0x04] (destination buffer)
    out += b"\xE8" + _rel32(cave_va + len(out), 5, sanitize_helper_va)  # call sanitizer/copy helper
    out += b"\xC3"  # ret
    return bytes(out)


def _build_lookup_found_unknown_wrapper(*, cave_va: int, lookup_va: int, unknown_va: int) -> bytes:
    """Hover post-call helper at 0x0041E750.

    - Preserves original `add esi,0x903c`.
    - If EAX points to empty text, replace draw pointer with static
      "Unknown club" (pointer-only fallback; no destination write).
    """
    del cave_va, lookup_va
    out = bytearray()
    out += b"\x81\xC6\x3C\x90\x00\x00"  # add esi,0x903c
    out += b"\x80\x38\x41"  # cmp byte ptr [eax],0x41
    out += b"\x72\x05"  # jb set_unknown
    out += b"\x80\x38\x7A"  # cmp byte ptr [eax],0x7a
    out += b"\x76\x05"  # jbe done
    out += b"\xB8" + struct.pack("<I", unknown_va)  # mov eax,unknown
    out += b"\xC3"  # ret
    return bytes(out)


def _build_sprintf_arg3_guard_stage0(
    *,
    cave_va: int,
    stage_call_va: int,
    stage_set_va: int,
) -> bytes:
    """Stage0 dispatcher for low-pointer arg3 sanitizer wrapper."""
    out = bytearray()
    out += b"\x66\x83\x7C\x24\x0E\x00"  # cmp word ptr [esp+0x0e],0
    rel8_to_call = stage_call_va - (cave_va + len(out) + 2)
    if not -128 <= rel8_to_call <= 127:
        raise RuntimeError(f"Stage0 rel8-to-call out of range: {rel8_to_call}")
    out += b"\x75" + bytes((rel8_to_call & 0xFF,))  # jnz stage_call
    out += b"\xE9" + _rel32(cave_va + len(out), 5, stage_set_va)  # jmp stage_set
    if len(out) > CAVE_D1_PTR_STAGE1_SIZE:
        raise RuntimeError(
            f"Arg3 guard stage0 overflow ({len(out)} > {CAVE_D1_PTR_STAGE1_SIZE})"
        )
    return bytes(out)


def _build_sprintf_arg3_guard_stage_call() -> bytes:
    """Tail-call original formatter function pointer."""
    return b"\xFF\x25" + struct.pack("<I", 0x006E64C8)  # jmp dword ptr [0x006e64c8]


def _build_sprintf_arg3_guard_stage_set(*, unknown_va: int, stage_call_va: int, cave_va: int) -> bytes:
    """Write fallback pointer into arg3 then jump to stage_call."""
    out = bytearray()
    out += b"\xC7\x44\x24\x0C" + struct.pack("<I", unknown_va)  # mov dword ptr [esp+0x0c],unknown
    out += b"\xE9" + _rel32(cave_va + len(out), 5, stage_call_va)  # jmp stage_call
    return bytes(out)


def _build_formatter_arg3_guard_wrapper(*, cave_va: int, stage_call_va: int, unknown_va: int) -> bytes:
    """Guard arg3 for '%s' formatter shape at selected callsites.

    If format string is 0x00734ACC and arg3 points below a conservative floor
    (low numeric id / low sentinel pointer region), replace arg3 with
    "Unknown club", then tail-call original formatter thunk.
    """
    # Keep this floor above low numeric IDs while also catching known low
    # sentinel strings in the 0x006E51xx cave region.
    min_valid_ptr = 0x006E6000

    out = bytearray()
    out += b"\x81\x7C\x24\x08" + struct.pack("<I", 0x00734ACC)  # cmp dword ptr [esp+8],0x734acc
    jne_fmt_pos = len(out)
    out += b"\x75\x00"  # jne call_dispatch
    out += b"\x81\x7C\x24\x0C" + struct.pack("<I", min_valid_ptr)  # cmp dword ptr [esp+0xc],<floor>
    jae_dispatch_pos = len(out)
    out += b"\x73\x00"  # jae call_dispatch
    out += b"\xC7\x44\x24\x0C" + struct.pack("<I", unknown_va)  # mov dword ptr [esp+0xc],unknown
    call_dispatch_va = cave_va + len(out)
    rel8_dispatch = stage_call_va - (cave_va + len(out) + 2)
    if not -128 <= rel8_dispatch <= 127:
        raise RuntimeError(f"Formatter arg3 wrapper short-jmp(dispatch) rel8 out of range: {rel8_dispatch}")
    out += b"\xEB" + bytes((rel8_dispatch & 0xFF,))  # jmp short stage_call
    rel8_fmt = call_dispatch_va - (cave_va + jne_fmt_pos + 2)
    rel8_jae = call_dispatch_va - (cave_va + jae_dispatch_pos + 2)
    if not -128 <= rel8_fmt <= 127:
        raise RuntimeError(f"Formatter arg3 wrapper jne(fmt) rel8 out of range: {rel8_fmt}")
    if not -128 <= rel8_jae <= 127:
        raise RuntimeError(
            f"Formatter arg3 wrapper jae(ptr-floor) rel8 out of range: {rel8_jae}"
        )
    out[jne_fmt_pos + 1] = rel8_fmt & 0xFF
    out[jae_dispatch_pos + 1] = rel8_jae & 0xFF
    return bytes(out)


def _build_formatter_arg3_call_thunk() -> bytes:
    """Tail-call original formatter function pointer."""
    return b"\xFF\x25" + struct.pack("<I", 0x006E64C8)  # jmp dword ptr [0x006e64c8]


def _build_lookup_miss_unknown_helper(*, unknown_va: int) -> bytes:
    """Helper for FUN_0049A410 miss epilogue.

    Input:
    - EAX: destination output buffer
    Behavior:
    - Copy "Unknown club" into destination and return destination pointer.
    """
    out = bytearray()
    out += b"\x68" + struct.pack("<I", unknown_va)  # push "Unknown club"
    out += b"\x50"  # push eax
    out += b"\xFF\x15" + struct.pack("<I", 0x006E6108)  # call dword ptr [lstrcpyA]
    out += b"\xC3"
    return bytes(out)


def _build_search_empty_template_fallback_helper(*, unknown_va: int) -> bytes:
    """FUN_0049A0E0 empty-template path helper.

    Writes "Unknown club" into caller output buffer and returns it.
    """
    out = bytearray()
    out += b"\x8B\x74\x24\x08"  # mov esi,[esp+0x8]
    out += b"\x68" + struct.pack("<I", unknown_va)  # push unknown string
    out += b"\x56"  # push esi
    out += b"\xFF\x15" + struct.pack("<I", 0x006E6108)  # call dword ptr [lstrcpyA]
    out += b"\x5E"  # pop esi
    out += b"\xC2\x08\x00"  # ret 8
    return bytes(out)


def _build_search_hover_field_stage1(*, cave_va: int, stage2_va: int) -> bytes:
    """Stage1 for FUN_0041E720 field-level hover fallback.

    Replays original lookup call then jumps to stage2.
    """
    out = bytearray()
    out += b"\xE8" + _rel32(cave_va + len(out), 5, 0x0049A410)  # call FUN_0049A410
    out += b"\xE9" + _rel32(cave_va + len(out), 5, stage2_va)  # jmp stage2
    return bytes(out)


def _build_search_hover_field_stage2(*, cave_va: int, stage3_va: int) -> bytes:
    """Stage2 for FUN_0041E720 field-level hover fallback.

    Replays overwritten add-ESI sequence then jumps to stage3.
    """
    out = bytearray()
    out += b"\x81\xC6\x3C\x90\x00\x00"  # add esi,0x903c
    out += b"\xE9" + _rel32(cave_va + len(out), 5, stage3_va)  # jmp stage3
    return bytes(out)


def _build_search_hover_field_stage3(*, cave_va: int, resume_va: int, sanitize_helper_va: int) -> bytes:
    """Stage3 for FUN_0041E720 field-level hover fallback.

    Run shared destination sanitizer and then resume at original draw push
    sequence (0x0041E756).
    """
    out = bytearray()
    out += b"\xE8" + _rel32(cave_va + len(out), 5, sanitize_helper_va)  # call sanitizer
    out += b"\xE9" + _rel32(cave_va + len(out), 5, resume_va)  # jmp 0x0041E756
    return bytes(out)


def _build_force_unknown_stackarg_tailjmp_wrapper(
    *,
    cave_va: int,
    target_va: int,
    unknown_va: int,
    arg_disp: int,
) -> bytes:
    """Force a stack argument to Unknown-club pointer, then tail-jump.

    Used for field-local draw calls only:
    - bio draw wrapper:   arg_disp=0x04
    - hover draw wrapper: arg_disp=0x08
    """
    if not 0 <= arg_disp <= 0x7F:
        raise ValueError(f"arg_disp out of range for wrapper: {arg_disp}")
    out = bytearray()
    out += b"\xC7\x44\x24" + bytes((arg_disp,)) + struct.pack("<I", unknown_va)
    out += b"\xE9" + _rel32(cave_va + len(out), 5, target_va)
    return bytes(out)


def _build_secondary_chain_guard_dispatch(*, site_va: int, stage0_va: int) -> bytes:
    """Guard dispatcher at 0x0064CFD6 (15-byte overwrite window).

    Original overwritten sequence:
    - mov eax,[ebp]
    - push ecx
    - push ebp
    - call dword ptr [eax+0x58]
    - mov edx,[esp+0xA4]

    New behavior:
    - if ebp == NULL -> continue with original tail setup (mov edx,[esp+0xA4])
    - else -> jump to stage0->stage1->stage2 call chain, then rejoin tail setup
    """
    out = bytearray()
    out += b"\x85\xED"  # test ebp,ebp
    jnz_pos = len(out)
    out += b"\x75\x00"  # jnz stage0
    out += b"\x8B\x94\x24\xA4\x00\x00\x00"  # mov edx,[esp+0xA4]
    out += b"\x90" * 4
    jnz_from = site_va + jnz_pos
    jnz_next = jnz_from + 2
    rel8 = stage0_va - jnz_next
    if not -128 <= rel8 <= 127:
        raise RuntimeError(f"Secondary guard jnz rel8 out of range: {rel8}")
    out[jnz_pos + 1] = rel8 & 0xFF
    if len(out) != SECONDARY_CHAIN_GUARD_SITE_LEN:
        raise RuntimeError(
            f"Secondary guard dispatch size mismatch ({len(out)} != {SECONDARY_CHAIN_GUARD_SITE_LEN})"
        )
    return bytes(out)


def _build_secondary_chain_guard_stage0(*, cave_va: int, stage1_va: int) -> bytes:
    """Stage0 stub: bridge from short JNZ to near JMP."""
    out = bytearray()
    out += b"\xE9" + _rel32(cave_va, 5, stage1_va)  # jmp stage1
    return bytes(out)


def _build_secondary_chain_guard_stage1(*, cave_va: int, stage2_va: int) -> bytes:
    """Stage1 stub: restore argument setup and jump to stage2 call stub."""
    out = bytearray()
    out += b"\x8B\x45\x00"  # mov eax,[ebp]
    out += b"\x51"  # push ecx
    out += b"\x55"  # push ebp
    out += b"\xE9" + _rel32(cave_va + len(out), 5, stage2_va)  # jmp stage2
    return bytes(out)


def _build_secondary_chain_guard_stage2(*, cave_va: int, resume_va: int) -> bytes:
    """Stage2 stub: perform original virtual call and jump back."""
    out = bytearray()
    out += b"\xFF\x50\x58"  # call dword ptr [eax+0x58]
    out += b"\xE9" + _rel32(cave_va + len(out), 5, resume_va)  # jmp resume
    return bytes(out)


def _build_lookup_result_fallback_helper(
    *,
    cave_va: int,
    epilogue_va: int,
    unknown_rec_va: int,
    stars_rec_va: int,
    free_rec_va: int,
) -> bytes:
    """Helper for 0x004B5C20 tail result handling.

    Input registers at hook point:
    - EAX: candidate team-record pointer
    - EBX: requested team ID

    Behavior:
    - if candidate is NULL -> fallback mapping
    - if candidate ID matches AND candidate name pointer/text is valid -> keep EAX
    - else fallback records for unresolved IDs (0, 4705, 4706)
    - all unresolved IDs degrade to unknown-club record (never NULL)
    - always jump to original epilogue at 0x004B5C7D
    """
    out = bytearray()

    out += b"\x85\xC0"  # test eax,eax
    jz_fallback_pos = len(out)
    out += b"\x0F\x84" + b"\x00\x00\x00\x00"

    out += b"\x39\x58\x10"  # cmp dword ptr [eax+0x10],ebx
    jne_fallback_pos = len(out)
    out += b"\x0F\x85" + b"\x00\x00\x00\x00"

    out += b"\x8B\x50\x04"  # mov edx,[eax+0x04]
    out += b"\x85\xD2"  # test edx,edx
    jz_fallback_2_pos = len(out)
    out += b"\x0F\x84" + b"\x00\x00\x00\x00"

    out += b"\x8A\x0A"  # mov cl,[edx]
    out += b"\x84\xC9"  # test cl,cl
    jz_fallback_3_pos = len(out)
    # JLE after TEST treats zero or high-bit bytes (>=0x80) as invalid text.
    out += b"\x0F\x8E" + b"\x00\x00\x00\x00"

    out += b"\x80\xF9\x2E"  # cmp cl,'.'
    jbe_fallback_4_pos = len(out)
    out += b"\x0F\x86" + b"\x00\x00\x00\x00"

    # matched and valid -> keep EAX
    jmp_epilogue_match_pos = len(out)
    out += b"\xE9" + b"\x00\x00\x00\x00"

    fallback_va = cave_va + len(out)

    out += b"\x85\xDB"  # test ebx,ebx
    je_unknown_pos = len(out)
    out += b"\x0F\x84" + b"\x00\x00\x00\x00"

    out += b"\x81\xFB" + struct.pack("<I", TEAM_ID_STARS)  # cmp ebx,4705
    je_stars_pos = len(out)
    out += b"\x0F\x84" + b"\x00\x00\x00\x00"

    out += b"\x81\xFB" + struct.pack("<I", TEAM_ID_FREE_PLAYERS)  # cmp ebx,4706
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


def _build_fake_team_record(*, name_ptr_va: int, team_id: int) -> bytes:
    """Minimal fake team record used for text-only fallback paths.

    Layout used by observed callers:
    - +0x04 : char* team-name pointer
    - +0x10 : uint32 team_id
    """
    rec = bytearray(0x14)
    struct.pack_into("<I", rec, 0x04, int(name_ptr_va))
    struct.pack_into("<I", rec, 0x10, int(team_id))
    return bytes(rec)


def _build_bundle(*, unknown_text: str = "Unknown club") -> tuple[bytes, dict[str, int], bytes]:
    if "\x00" in unknown_text:
        raise ValueError("unknown_text may not contain NUL bytes")
    encoded_unknown = unknown_text.encode("ascii")
    if len(encoded_unknown) > 18:
        raise ValueError(f"unknown_text too long ({len(encoded_unknown)} > 18)")
    strings_blob = b"\x00Stars\x00Free players\x00" + encoded_unknown + b"\x00"

    # String addresses are fixed contract points.
    string_addrs = {
        "empty": CAVE_EMPTY_STRING_VA,
        "stars": CAVE_STARS_STRING_VA,
        "free": CAVE_FREE_STRING_VA,
        "unknown": CAVE_UNKNOWN_STRING_VA,
    }

    # Build helpers once to lock lengths.
    search_tmp = _build_search_window_team_prepush_helper(
        cave_va=CAVE_BUNDLE_BASE_VA,
        stars_va=0,
        free_va=0,
        unknown_va=0,
    )

    lookup_tmp = _build_lookup_result_fallback_helper(
        cave_va=CAVE_BUNDLE_BASE_VA + len(search_tmp),
        epilogue_va=0x004B5C7D,
        unknown_rec_va=0,
        stars_rec_va=0,
        free_rec_va=0,
    )

    rec_base_va = CAVE_BUNDLE_BASE_VA + len(search_tmp) + len(lookup_tmp)
    unknown_rec_va = rec_base_va
    stars_rec_va = rec_base_va + 0x14
    free_rec_va = rec_base_va + 0x28

    search_real = _build_search_window_team_prepush_helper(
        cave_va=CAVE_BUNDLE_BASE_VA,
        stars_va=string_addrs["stars"],
        free_va=string_addrs["free"],
        unknown_va=string_addrs["unknown"],
    )

    lookup_real = _build_lookup_result_fallback_helper(
        cave_va=CAVE_BUNDLE_BASE_VA + len(search_real),
        epilogue_va=0x004B5C7D,
        unknown_rec_va=unknown_rec_va,
        stars_rec_va=stars_rec_va,
        free_rec_va=free_rec_va,
    )

    if len(search_tmp) != len(search_real) or len(lookup_tmp) != len(lookup_real):
        raise RuntimeError("Internal helper sizing mismatch")

    rec_unknown = _build_fake_team_record(name_ptr_va=string_addrs["unknown"], team_id=0)
    rec_stars = _build_fake_team_record(name_ptr_va=string_addrs["stars"], team_id=TEAM_ID_STARS)
    rec_free = _build_fake_team_record(name_ptr_va=string_addrs["free"], team_id=TEAM_ID_FREE_PLAYERS)

    prefix = search_real + lookup_real + rec_unknown + rec_stars + rec_free
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

    legacy_bundle_prefixes = (
        bytes.fromhex("e8890bddff85c00f84140000008b4004"),
        bytes.fromhex("e889f6dbff85c00f84130000008a1084d20f840900000080fa2e0f8730000000"),
        bytes.fromhex("e889f6dbff85c00f84130000008a1084d20f8e0900000080fa2e0f8730000000"),
        bytes.fromhex("e889f6dbff85c00f84140000008a1080fa300f820900000080fa7a0f8630000000"),
        bytes.fromhex("0fb7c08b54241485d20f8412000000803a000f8409000000803a2e0f8740000000"),
        bytes.fromhex("0fb7c08b54241485d20f841a0000008a0284c00f84100000003c800f83080000003c2e0f874c000000"),
        bytes.fromhex("85c074118a1084d2740b80fa2e760680fa7a7701"),
        bytes.fromhex("66817e186112741466817e186212741366837e180074138b4004eb13"),
        bytes.fromhex("5966817e186112741c66817e186212741b66837e1800741b85c07417"),
        bytes.fromhex("5966817e186112742c66817e186212742b66837e1800742b85c07427"),
    )
    return bundle, string_addrs, legacy_bundle_prefixes


def _build_patch_plan(
    search_text_helper_va: int,
    name_ptr_guard_helper_va: int,
    lookup_helper_va: int,
    hover_draw_helper_va: int,
    hover_field_stage1_va: int,
    mode: str,
    probe_id: str | None,
    lookup_call_probe_helper_va: int,
    runtime_probe_helper_va: int,
    runtime_probe: dict[str, Any] | None,
) -> list[DirectPatch]:
    orig_search_call = bytes.fromhex("e8d5120400")
    orig_transfer_a = bytes.fromhex("e8d8b3fbff8b4004")
    orig_transfer_b = bytes.fromhex("e887a6fbff8b4004")

    old_tramp_search = _build_trampoline(0x00474946, 0x006E5092, len(orig_search_call))
    old_tramp_search_legacy8 = _build_trampoline(0x00474946, 0x006E5092, 8)
    old_tramp_transfer_a = _build_trampoline(0x004FA843, 0x006E50EB, len(orig_transfer_a))
    old_tramp_transfer_b = _build_trampoline(0x004FB594, 0x006E5142, len(orig_transfer_b))

    old_sign_call_a = _build_call(0x004B8C2E, 0x006E51E1)
    old_sign_call_b = _build_call(0x004B8EFA, 0x006E51E1)
    old_sign_call_a_v2 = _build_call(0x004B8C2E, 0x006E5092)
    old_sign_call_b_v2 = _build_call(0x004B8EFA, 0x006E5092)

    old_lookup_bytes = bytes.fromhex("395810740933c0")
    unpatched_lookup_bytes = bytes.fromhex("395810740233c0")
    old_lookup_trampoline = _build_trampoline(0x004B5C76, 0x006E50F4, len(unpatched_lookup_bytes))
    old_lookup_trampoline_v2 = _build_trampoline(0x004B5C76, 0x006E5108, len(unpatched_lookup_bytes))
    old_lookup_trampoline_v3 = _build_trampoline(0x004B5C76, 0x006E50E3, len(unpatched_lookup_bytes))
    old_lookup_trampoline_v4 = _build_trampoline(0x004B5C76, 0x006E50E4, len(unpatched_lookup_bytes))
    old_lookup_trampoline_v5 = _build_trampoline(0x004B5C76, 0x006E50CB, len(unpatched_lookup_bytes))

    old_null_guard_trampoline = _build_trampoline(0x0066F1FB, 0x006E51C0, 15)
    secondary_chain_dispatch = _build_secondary_chain_guard_dispatch(
        site_va=SECONDARY_CHAIN_GUARD_SITE_VA,
        stage0_va=SECONDARY_CHAIN_GUARD_STAGE0_VA,
    )

    old_hook_block = bytes.fromhex("e878ee2200e9efffffff9090")
    old_search_499d00_a = _build_call(0x00499DCF, search_text_helper_va) + (b"\x90" * 6)
    old_search_499d00_b = _build_call(0x00499DED, search_text_helper_va) + (b"\x90" * 2)
    old_token_hook_499e5b = _build_trampoline(0x00499E5B, name_ptr_guard_helper_va, 8)
    search_name_resolve_call_499dcf = _build_call(0x00499DCF, name_ptr_guard_helper_va) + (b"\x90" * 6)
    search_name_resolve_call_499ded = _build_call(0x00499DED, name_ptr_guard_helper_va) + (b"\x90" * 2)
    search_name_resolve_call_499e5b = _build_call(0x00499E5B, name_ptr_guard_helper_va) + b"\x50\x90\x90"
    token_null_norm_499dd2 = _build_call(0x00499DD2, CAVE_TOKEN_NULL_NORM_HELPER_VA) + (b"\x90" * 3)
    token_null_push_499df0 = _build_call(0x00499DF0, CAVE_TOKEN_NULL_PUSH_HELPER_VA)
    token_null_push_499e5e = _build_call(0x00499E5E, CAVE_TOKEN_NULL_PUSH_HELPER_VA)
    token_null_norm_499dd2_legacy = _build_call(0x00499DD2, 0x004049D4) + (b"\x90" * 3)
    token_null_push_499df0_legacy = _build_call(0x00499DF0, 0x00404A41)
    token_null_push_499e5e_legacy = _build_call(0x00499E5E, 0x00404A41)
    token_null_branch_499dcf = bytes.fromhex("8b4004") + token_null_norm_499dd2
    token_null_branch_499ded = bytes.fromhex("8b4004") + token_null_push_499df0
    token_null_branch_499e5b = bytes.fromhex("8b4004") + token_null_push_499e5e
    token_null_branch_499dcf_legacy = bytes.fromhex("8b4004") + token_null_norm_499dd2_legacy
    token_null_branch_499ded_legacy = bytes.fromhex("8b4004") + token_null_push_499df0_legacy
    token_null_branch_499e5b_legacy = bytes.fromhex("8b4004") + token_null_push_499e5e_legacy
    search_d1_ptr_guard_499d53 = _build_trampoline(0x00499D53, CAVE_D1_PTR_STAGE1_VA, 14)
    load_ebx_fmt_guard_499d28 = bytes.fromhex("bb") + struct.pack("<I", FORMATTTER_ARG3_GUARD_VA) + b"\x90"
    load_ebp_fmt_guard_4afc16 = bytes.fromhex("bd") + struct.pack("<I", FORMATTTER_ARG3_GUARD_VA) + b"\x90"
    load_ebx_fmt_guard_569d5b = bytes.fromhex("bb") + struct.pack("<I", FORMATTTER_ARG3_GUARD_VA) + b"\x90"
    load_edi_fmt_guard_5ba278 = bytes.fromhex("bf") + struct.pack("<I", FORMATTTER_ARG3_GUARD_VA) + b"\x90"
    load_ebx_fmt_guard_5ba7bc = bytes.fromhex("bb") + struct.pack("<I", FORMATTTER_ARG3_GUARD_VA) + b"\x90"
    call_fmt_guard_5b55f1 = _build_call(0x005B55F1, FORMATTTER_ARG3_GUARD_VA) + b"\x90"
    call_fmt_guard_5b5bdf = _build_call(0x005B5BDF, FORMATTTER_ARG3_GUARD_VA) + b"\x90"
    call_fmt_guard_5b8175 = _build_call(0x005B8175, FORMATTTER_ARG3_GUARD_VA) + b"\x90"
    call_fmt_guard_5c2853 = _build_call(0x005C2853, FORMATTTER_ARG3_GUARD_VA) + b"\x90"
    search_s2_ptr_guard_499d91 = (
        bytes.fromhex("8b4514")
        + _build_call(0x00499D94, CAVE_LE_DE_WRAPPER_VA)
        + b"\xE9"
        + _rel32(0x00499D99, 5, 0x00499E62)
        + (b"\x90" * 3)
    )
    search_s3_ptr_guard_499da1 = (
        bytes.fromhex("8b4518")
        + _build_call(0x00499DA4, CAVE_LE_DE_WRAPPER_VA)
        + b"\xE9"
        + _rel32(0x00499DA9, 5, 0x00499E62)
        + (b"\x90" * 3)
    )
    bad_lookup_miss_unknown_49a486 = (
        bytes.fromhex("8b442414")
        + _build_call(0x0049A48A, CAVE_LE_DE_WRAPPER_VA)
        + bytes.fromhex("5f5e5d5bc20800")
    )
    old_lookup_miss_unknown_49a486 = (
        bytes.fromhex("8b442414")
        + _build_call(0x0049A48A, 0x00468C81)
        + bytes.fromhex("5f5e5d5bc20800")
    )
    lookup_miss_unknown_49a486 = (
        bytes.fromhex("8b442414")
        + _build_call(0x0049A48A, CAVE_LOOKUP_MISS_HELPER_VA)
        + bytes.fromhex("5f5e5d5bc20800")
    )
    lookup_found_nonempty_49a478 = _build_call(0x0049A478, hover_draw_helper_va)
    empty_template_unknown_49a111 = (
        bytes.fromhex("8b442408")
        + _build_call(0x0049A115, CAVE_LOOKUP_MISS_HELPER_VA)
        + bytes.fromhex("5ec20800")
    )
    local_lookup_fill_post_68e52 = _build_call(0x00468E52, CAVE_D1_PTR_STAGE2_VA)
    local_lookup_fill_post_43bd46 = _build_call(0x0043BD46, CAVE_LE_DE_WRAPPER_VA) + (b"\x90" * 3)
    lookup_probe_call_68167 = _build_call(0x00468167, lookup_call_probe_helper_va)
    lookup_probe_call_681db = _build_call(0x004681DB, lookup_call_probe_helper_va)
    lookup_probe_call_6824b = _build_call(0x0046824B, lookup_call_probe_helper_va)
    lookup_call_probe_ids = {"lookup_call_68167", "lookup_call_681db", "lookup_call_6824b"}
    lookup_miss_epilogue_replacement = (
        bytes.fromhex("8b7424145f8bc6c606005e5d5bc20800")
        if (mode == "instrument" and probe_id in lookup_call_probe_ids)
        else lookup_miss_unknown_49a486
    )
    lookup_call_68167_replacement = (
        lookup_probe_call_68167
        if (mode == "instrument" and probe_id == "lookup_call_68167")
        else _build_call(0x00468167, 0x0049A410)
    )
    lookup_call_681db_replacement = (
        lookup_probe_call_681db
        if (mode == "instrument" and probe_id == "lookup_call_681db")
        else _build_call(0x004681DB, 0x0049A410)
    )
    lookup_call_6824b_replacement = (
        lookup_probe_call_6824b
        if (mode == "instrument" and probe_id == "lookup_call_6824b")
        else _build_call(0x0046824B, 0x0049A410)
    )
    hover_field_hook_41e74b = _build_trampoline(0x0041E74B, hover_field_stage1_va, 11)
    bio_copy_src_fallback_43f24f = _build_call(0x0043F24F, FORMATTTER_ARG3_GUARD_VA) + b"\x90"
    restore_hover_draw_call_41e756 = b"\x50\x56" + _build_call(0x0041E758, 0x0040D3E0)
    force_hover_draw_call_41e758 = _build_call(0x0041E758, CAVE_HOVER_DRAW_WRAPPER_VA)
    force_bio_draw_call_41f739 = _build_call(0x0041F739, CAVE_BIO_DRAW_WRAPPER_VA)
    patches = [
        # Revert old experimental upstream list/profile trampolines.
        DirectPatch(
            name="restore_lookup_search_FUN_00474870",
            site_va=0x00474946,
            expected=orig_search_call,
            replacement=orig_search_call,
            alternates=(old_tramp_search, old_tramp_search_legacy8),
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
        # Restore old helper-hooked AND instructions (idempotent upgrade path).
        DirectPatch(
            name="restore_signing_multiyear_hook_FUN_004b8b40",
            site_va=0x004B8C2E,
            expected=bytes.fromhex("25ffff0000"),
            replacement=bytes.fromhex("25ffff0000"),
            alternates=(old_sign_call_a, old_sign_call_a_v2),
        ),
        DirectPatch(
            name="restore_signing_multiyear_hook_FUN_004b8e20",
            site_va=0x004B8EFA,
            expected=bytes.fromhex("25ffff0000"),
            replacement=bytes.fromhex("25ffff0000"),
            alternates=(old_sign_call_b, old_sign_call_b_v2),
        ),
        # Restore source-wrapper calls to original function (remove RC1 wrappers).
        DirectPatch(
            name="restore_source_wrapper_FUN_004b8b40_multiyear",
            site_va=0x004B8C3D,
            expected=_build_call(0x004B8C3D, 0x004A4720),
            replacement=_build_call(0x004B8C3D, 0x004A4720),
            alternates=(_build_call(0x004B8C3D, 0x006E5092),),
        ),
        DirectPatch(
            name="restore_source_wrapper_FUN_004b8b40_oneyear",
            site_va=0x004B8C73,
            expected=_build_call(0x004B8C73, 0x004A4720),
            replacement=_build_call(0x004B8C73, 0x004A4720),
            alternates=(_build_call(0x004B8C73, 0x006E5092),),
        ),
        DirectPatch(
            name="restore_source_wrapper_FUN_004b8e20_multiyear",
            site_va=0x004B8F09,
            expected=_build_call(0x004B8F09, 0x004A4720),
            replacement=_build_call(0x004B8F09, 0x004A4720),
            alternates=(_build_call(0x004B8F09, 0x006E5092),),
        ),
        DirectPatch(
            name="restore_source_wrapper_FUN_004b8e20_oneyear",
            site_va=0x004B8F3F,
            expected=_build_call(0x004B8F3F, 0x004A4720),
            replacement=_build_call(0x004B8F3F, 0x004A4720),
            alternates=(_build_call(0x004B8F3F, 0x006E5092),),
        ),
        # Restore {LE}/{DE} connector lookup call to original helper.
        DirectPatch(
            name="search_token_LE_DE_wrapper_call_FUN_00499d00",
            site_va=0x00499E0A,
            expected=_build_call(0x00499E0A, 0x004A4720),
            replacement=_build_call(0x00499E0A, 0x004A4720),
            alternates=(
                _build_call(0x00499E0A, CAVE_LE_DE_WRAPPER_VA),
                _build_call(0x00499E0A, name_ptr_guard_helper_va),
            ),
        ),
        # Restore {DE}/{LE}/{EN} token branches to original bytes.
        DirectPatch(
            name="search_token_name_ptr_guard_FUN_00499d00_A",
            site_va=0x00499DCF,
            expected=bytes.fromhex("8b400485c00f8496000000"),
            replacement=bytes.fromhex("8b400485c00f8496000000"),
            alternates=(
                token_null_branch_499dcf_legacy,
                old_search_499d00_a,
                search_name_resolve_call_499dcf,
                token_null_branch_499dcf,
            ),
        ),
        DirectPatch(
            name="search_token_name_ptr_guard_FUN_00499d00_B",
            site_va=0x00499DED,
            expected=bytes.fromhex("8b400485c0747c506a"),
            replacement=bytes.fromhex("8b400485c0747c506a"),
            alternates=(
                token_null_branch_499ded_legacy + b"\x6a",
                old_search_499d00_b + b"\x6a\x00",
                search_name_resolve_call_499ded + b"\x6a\x00",
                token_null_branch_499ded + b"\x6a",
                bytes.fromhex("8b400485c0747c6a00"),
                bytes.fromhex("8b400485c0747c6a6a"),
            ),
        ),
        DirectPatch(
            name="search_token_name_ptr_guard_FUN_00499d00_C",
            site_va=0x00499E5B,
            expected=bytes.fromhex("8b400485c0740e50"),
            replacement=bytes.fromhex("8b400485c0740e50"),
            alternates=(
                token_null_branch_499e5b_legacy,
                old_token_hook_499e5b,
                search_name_resolve_call_499e5b,
                token_null_branch_499e5b,
            ),
        ),
        # Guard {D1} raw formatter pointer that can contain small numeric IDs.
        DirectPatch(
            name="restore_search_token_D1_ptr_path_FUN_00499d00",
            site_va=0x00499D53,
            expected=bytes.fromhex("8b4510506814d47200e907010000"),
            replacement=bytes.fromhex("8b4510506814d47200e907010000"),
            alternates=(search_d1_ptr_guard_499d53,),
        ),
        # Guard S2/S3 raw formatter pointers that can contain small numeric IDs.
        DirectPatch(
            name="search_token_S2_ptr_guard_FUN_00499d00",
            site_va=0x00499D91,
            expected=bytes.fromhex("8b451485c00f84d4000000e9c1000000"),
            replacement=bytes.fromhex("8b451485c00f84d4000000e9c1000000"),
            alternates=(search_s2_ptr_guard_499d91,),
        ),
        DirectPatch(
            name="search_token_S3_ptr_guard_FUN_00499d00",
            site_va=0x00499DA1,
            expected=bytes.fromhex("8b451885c00f84c4000000e9b1000000"),
            replacement=bytes.fromhex("8b451885c00f84c4000000e9b1000000"),
            alternates=(search_s3_ptr_guard_499da1,),
        ),
        # Keep global formatter call site at original target (avoid broad side effects).
        DirectPatch(
            name="restore_search_formatter_call_FUN_0049a0e0",
            site_va=0x0049A103,
            expected=_build_call(0x0049A103, 0x00499D00),
            replacement=_build_call(0x0049A103, 0x00499D00),
            alternates=(
                _build_call(0x0049A103, name_ptr_guard_helper_va),
                _build_call(0x0049A103, CAVE_LE_DE_WRAPPER_VA),
            ),
        ),
        # Keep global formatter empty-template branch at original bytes.
        DirectPatch(
            name="restore_search_formatter_empty_template_branch_FUN_0049a0e0",
            site_va=0x0049A111,
            expected=bytes.fromhex("8b7424088bc6c606005ec20800"),
            replacement=bytes.fromhex("8b7424088bc6c606005ec20800"),
            alternates=(
                empty_template_unknown_49a111,
                _build_trampoline(0x0049A111, CAVE_HOVER_DRAW_HELPER_VA, 13),
            ),
        ),
        # Keep FUN_0049A410 found-path call at original bytes.
        DirectPatch(
            name="restore_search_lookup_found_call_FUN_0049a410",
            site_va=0x0049A478,
            expected=_build_call(0x0049A478, 0x0049A0E0),
            replacement=_build_call(0x0049A478, 0x0049A0E0),
            alternates=(
                lookup_found_nonempty_49a478,
                _build_call(0x0049A478, CAVE_LOOKUP_MISS_HELPER_VA),
            ),
        ),
        # FUN_0049A410 miss-epilogue fallback:
        # write "Unknown club" into destination buffer on lookup miss.
        DirectPatch(
            name="search_lookup_miss_unknown_epilogue_FUN_0049a410",
            site_va=0x0049A486,
            expected=bytes.fromhex("8b7424145f8bc6c606005e5d5bc20800"),
            replacement=lookup_miss_epilogue_replacement,
            known_bad=(KNOWN_BAD_LOOKUP_MISS_SIG,),
            alternates=(
                lookup_miss_unknown_49a486,
                old_lookup_miss_unknown_49a486,
                bad_lookup_miss_unknown_49a486,
                _build_trampoline(0x0049A486, CAVE_HOVER_DRAW_HELPER_VA, 16),
                (
                    bytes.fromhex("8b442414")
                    + _build_call(0x0049A48A, name_ptr_guard_helper_va)
                    + bytes.fromhex("5f5e5d5bc20800")
                ),
            ),
        ),
        # Restore FUN_0049A410 callsites that were wrapped via callee-entry hook experiments.
        DirectPatch(
            name="restore_search_profile_lookup_call_FUN_00468c90_A",
            site_va=0x00468167,
            expected=_build_call(0x00468167, 0x0049A410),
            replacement=lookup_call_68167_replacement,
            alternates=(
                _build_call(0x00468167, CAVE_D1_PTR_STAGE1_VA),
                lookup_probe_call_68167,
                _build_call(0x00468167, CAVE_TOKEN_NULL_NORM_HELPER_VA),
            ),
        ),
        DirectPatch(
            name="restore_search_profile_lookup_call_FUN_00468c90_B",
            site_va=0x004681DB,
            expected=_build_call(0x004681DB, 0x0049A410),
            replacement=lookup_call_681db_replacement,
            alternates=(
                _build_call(0x004681DB, CAVE_D1_PTR_STAGE1_VA),
                lookup_probe_call_681db,
                _build_call(0x004681DB, CAVE_TOKEN_NULL_NORM_HELPER_VA),
            ),
        ),
        DirectPatch(
            name="restore_search_profile_lookup_call_FUN_00468c90_C",
            site_va=0x0046824B,
            expected=_build_call(0x0046824B, 0x0049A410),
            replacement=lookup_call_6824b_replacement,
            alternates=(
                _build_call(0x0046824B, CAVE_D1_PTR_STAGE1_VA),
                lookup_probe_call_6824b,
                _build_call(0x0046824B, CAVE_TOKEN_NULL_NORM_HELPER_VA),
            ),
        ),
        DirectPatch(
            name="search_profile_lookup_nonempty_call_FUN_00468c90_D",
            site_va=0x00468E4D,
            expected=_build_call(0x00468E4D, 0x0049A410),
            replacement=_build_call(0x00468E4D, 0x0049A410),
            alternates=(
                _build_call(0x00468E4D, CAVE_D1_PTR_STAGE1_VA),
                _build_call(0x00468E4D, CAVE_HOVER_DRAW_HELPER_VA),
                _build_call(0x00468E4D, FORMATTTER_ARG3_GUARD_VA),
            ),
        ),
        DirectPatch(
            name="search_profile_lookup_nonempty_call_FUN_0043bd10",
            site_va=0x0043BD41,
            expected=_build_call(0x0043BD41, 0x0049A410),
            replacement=_build_call(0x0043BD41, 0x0049A410),
            alternates=(
                _build_call(0x0043BD41, 0x0049A410),
                _build_call(0x0043BD41, CAVE_LE_DE_WRAPPER_VA),
                _build_call(0x0043BD41, CAVE_D1_PTR_STAGE1_VA),
                _build_call(0x0043BD41, CAVE_HOVER_DRAW_HELPER_VA),
                _build_call(0x0043BD41, FORMATTTER_ARG3_GUARD_VA),
            ),
        ),
        # Keep caller post-call gate at original bytes for crash safety.
        DirectPatch(
            name="search_profile_lookup_nonempty_postcall_FUN_00468c90",
            site_va=0x00468E52,
            expected=bytes.fromhex("8038007420"),
            replacement=bytes.fromhex("8038007420"),
            alternates=(
                local_lookup_fill_post_68e52,
                _build_call(0x00468E52, CAVE_HOVER_DRAW_HELPER_VA),
                _build_call(0x00468E52, CAVE_D1_PTR_STAGE1_VA),
                _build_call(0x00468E52, FORMATTTER_ARG3_GUARD_VA),
            ),
        ),
        DirectPatch(
            name="search_profile_lookup_nonempty_postcall_FUN_0043bd10",
            site_va=0x0043BD46,
            expected=bytes.fromhex("8a44240c84c0744a"),
            replacement=bytes.fromhex("8a44240c84c0744a"),
            alternates=(
                local_lookup_fill_post_43bd46,
                _build_call(0x0043BD46, CAVE_HOVER_DRAW_HELPER_VA) + (b"\x90" * 3),
                _build_call(0x0043BD46, CAVE_D1_PTR_STAGE1_VA) + (b"\x90" * 3),
                _build_call(0x0043BD46, FORMATTTER_ARG3_GUARD_VA) + (b"\x90" * 3),
            ),
        ),
        # Bio/search window copy-site fallback: if source text is empty, force Unknown club.
        DirectPatch(
            name="search_profile_bio_copy_src_fallback_FUN_0043f24f",
            site_va=0x0043F24F,
            expected=bytes.fromhex("ff1508616e00"),
            replacement=bio_copy_src_fallback_43f24f,
            alternates=(
                _build_call(0x0043F24F, FORMATTTER_ARG3_GUARD_VA) + b"\x90",
                _build_call(0x0043F24F, CAVE_HOVER_DRAW_HELPER_VA) + b"\x90",
            ),
        ),
        # Search-hover field-level write hook:
        # - replay lookup
        # - replay add esi,0x903c
        # - force Unknown club only when returned text is empty
        # - resume original draw push/call path at 0x0041E756
        DirectPatch(
            name="search_hover_field_empty_fallback_FUN_0041e720",
            site_va=0x0041E74B,
            expected=_build_call(0x0041E74B, 0x0049A410) + bytes.fromhex("81c63c900000"),
            replacement=hover_field_hook_41e74b,
            alternates=(
                _build_call(0x0041E74B, hover_draw_helper_va) + bytes.fromhex("81c63c900000"),
                _build_call(0x0041E74B, CAVE_D1_PTR_STAGE1_VA) + bytes.fromhex("81c63c900000"),
                _build_call(0x0041E74B, FORMATTTER_ARG3_GUARD_VA) + bytes.fromhex("81c63c900000"),
                _build_call(0x0041E74B, 0x0049A410) + (_build_call(0x0041E750, hover_draw_helper_va) + b"\x90"),
            ),
        ),
        # Keep original draw call sequence intact at 0x0041E756.
        DirectPatch(
            name="restore_search_hover_draw_call_FUN_0041e720",
            site_va=0x0041E756,
            expected=restore_hover_draw_call_41e756,
            replacement=restore_hover_draw_call_41e756,
            alternates=(
                _build_call(0x0041E756, hover_draw_helper_va) + (b"\x90" * 2),
                b"\x50\x56" + force_hover_draw_call_41e758,
            ),
        ),
        # Keep bio star-slot renderer call on original target (wrapper path was unproven).
        DirectPatch(
            name="restore_bio_star_slot_draw_call_FUN_0041ee00",
            site_va=0x0041F739,
            expected=_build_call(0x0041F739, 0x00674430),
            replacement=_build_call(0x0041F739, 0x00674430),
            alternates=(force_bio_draw_call_41f739,),
        ),
        # Actual Search Player window path.
        DirectPatch(
            name="search_window_team_text_prepush_FUN_00474870",
            site_va=0x0047494B,
            expected=bytes.fromhex("8b40048b560c508b46085250"),
            replacement=_build_call(0x0047494B, search_text_helper_va) + (b"\x90" * 7),
        ),
        # Restore selected formatter callsites to original import thunk.
        DirectPatch(
            name="formatter_arg3_guard_load_FUN_00499d00",
            site_va=0x00499D28,
            expected=bytes.fromhex("8b1dc8646e00"),
            replacement=bytes.fromhex("8b1dc8646e00"),
            alternates=(load_ebx_fmt_guard_499d28,),
        ),
        DirectPatch(
            name="formatter_arg3_guard_load_FUN_004afc10",
            site_va=0x004AFC16,
            expected=bytes.fromhex("8b2dc8646e00"),
            replacement=bytes.fromhex("8b2dc8646e00"),
            alternates=(load_ebp_fmt_guard_4afc16,),
        ),
        DirectPatch(
            name="formatter_arg3_guard_load_FUN_00569d10",
            site_va=0x00569D5B,
            expected=bytes.fromhex("8b1dc8646e00"),
            replacement=bytes.fromhex("8b1dc8646e00"),
            alternates=(load_ebx_fmt_guard_569d5b,),
        ),
        DirectPatch(
            name="formatter_arg3_guard_load_FUN_005ba250",
            site_va=0x005BA278,
            expected=bytes.fromhex("8b3dc8646e00"),
            replacement=bytes.fromhex("8b3dc8646e00"),
            alternates=(load_edi_fmt_guard_5ba278,),
        ),
        DirectPatch(
            name="formatter_arg3_guard_load_FUN_005ba7a0",
            site_va=0x005BA7BC,
            expected=bytes.fromhex("8b1dc8646e00"),
            replacement=bytes.fromhex("8b1dc8646e00"),
            alternates=(load_ebx_fmt_guard_5ba7bc,),
        ),
        DirectPatch(
            name="formatter_arg3_guard_call_FUN_005b55c0",
            site_va=0x005B55F1,
            expected=bytes.fromhex("ff15c8646e00"),
            replacement=bytes.fromhex("ff15c8646e00"),
            alternates=(call_fmt_guard_5b55f1,),
        ),
        DirectPatch(
            name="formatter_arg3_guard_call_FUN_005b5b40",
            site_va=0x005B5BDF,
            expected=bytes.fromhex("ff15c8646e00"),
            replacement=bytes.fromhex("ff15c8646e00"),
            alternates=(call_fmt_guard_5b5bdf,),
        ),
        DirectPatch(
            name="formatter_arg3_guard_call_FUN_005b7e60",
            site_va=0x005B8175,
            expected=bytes.fromhex("ff15c8646e00"),
            replacement=bytes.fromhex("ff15c8646e00"),
            alternates=(call_fmt_guard_5b8175,),
        ),
        DirectPatch(
            name="formatter_arg3_guard_call_FUN_005c2820",
            site_va=0x005C2853,
            expected=bytes.fromhex("ff15c8646e00"),
            replacement=bytes.fromhex("ff15c8646e00"),
            alternates=(call_fmt_guard_5c2853,),
        ),
        # Keep menu/profile formatter call at original target.
        DirectPatch(
            name="restore_menu_formatter_call_FUN_004960c0",
            site_va=0x00496358,
            expected=_build_call(0x00496358, 0x0049A0E0),
            replacement=_build_call(0x00496358, 0x0049A0E0),
            alternates=(_build_call(0x00496358, name_ptr_guard_helper_va),),
        ),
        # Restore menu render draw call bytes (remove local draw wrapper experiments).
        DirectPatch(
            name="restore_menu_team_draw_call_FUN_004960c0",
            site_va=0x0049635D,
            expected=b"\x50\x57" + _build_call(0x0049635F, 0x0040D3E0),
            replacement=b"\x50\x57" + _build_call(0x0049635F, 0x0040D3E0),
            alternates=(_build_call(0x0049635D, name_ptr_guard_helper_va) + (b"\x90" * 2),),
        ),
        # Lookup-result fallback hook at FUN_004b5c20 tail.
        DirectPatch(
            name="lookup_result_fallback_FUN_004b5c20",
            site_va=0x004B5C76,
            expected=unpatched_lookup_bytes,
            replacement=_build_trampoline(0x004B5C76, lookup_helper_va, len(unpatched_lookup_bytes)),
            alternates=(
                old_lookup_bytes,
                old_lookup_trampoline,
                old_lookup_trampoline_v2,
                old_lookup_trampoline_v3,
                old_lookup_trampoline_v4,
                old_lookup_trampoline_v5,
            ),
        ),
        # Clean obsolete hook block bytes (idempotent).
        DirectPatch(
            name="clear_obsolete_lookup_hook_block",
            site_va=0x004B5C84,
            expected=bytes.fromhex("909090909090909090909090"),
            replacement=bytes.fromhex("909090909090909090909090"),
            alternates=(old_hook_block,),
        ),
        # Proven null-guard trampoline site.
        DirectPatch(
            name="defense_in_depth_textptr_normalize_FUN_0066f1f0",
            site_va=0x0066F1FB,
            expected=bytes.fromhex("8b4c242033f68a472033d28be88a01"),
            replacement=_build_trampoline(0x0066F1FB, CAVE_NULL_GUARD_VA, 15),
            alternates=(old_null_guard_trampoline,),
        ),
        # Guard secondary object-chain dereference used in menu/search callbacks.
        DirectPatch(
            name="defense_in_depth_secondary_chain_guard_FUN_0064ce30",
            site_va=SECONDARY_CHAIN_GUARD_SITE_VA,
            expected=bytes.fromhex("8b45005155ff50588b9424a4000000"),
            replacement=secondary_chain_dispatch,
            alternates=(bytes.fromhex("85ed7405e946feffffe90100000090"),),
        ),
    ]

    if mode == "instrument" and runtime_probe is not None:
        runtime_site_va = int(runtime_probe["site_va"])
        runtime_expected = bytes(runtime_probe["expected"])
        runtime_original_target = runtime_probe.get("original_target_va")
        runtime_replacement = _build_call(runtime_site_va, runtime_probe_helper_va)
        runtime_alternates: tuple[bytes, ...] = (runtime_replacement,)
        if runtime_original_target is not None:
            runtime_alternates = runtime_alternates + (
                _build_call(runtime_site_va, int(runtime_original_target)),
            )
        patches.append(
            DirectPatch(
                name=f"runtime_owner_probe_{probe_id}",
                site_va=runtime_site_va,
                expected=runtime_expected,
                replacement=runtime_replacement,
                alternates=runtime_alternates,
            )
        )

    return patches


def _write_output_bytes(
    *,
    input_exe: Path,
    output_exe: Path | None,
    in_place: bool,
    dry_run: bool,
    make_backup: bool,
    output_bytes: bytes,
) -> tuple[Path, Path | None]:
    target_out: Path
    if in_place:
        target_out = input_exe
    else:
        target_out = output_exe or DEFAULT_OUTPUT_EXE

    backup_path: Path | None = None
    if not dry_run:
        target_out.parent.mkdir(parents=True, exist_ok=True)
        if in_place and make_backup:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = target_out.with_name(f"{target_out.name}.bak_valderrama_upstream_{stamp}")
            shutil.copy2(target_out, backup_path)
        target_out.write_bytes(output_bytes)
    return target_out, backup_path


def apply_patch(
    *,
    input_exe: Path,
    output_exe: Path | None,
    in_place: bool,
    dry_run: bool,
    force: bool,
    make_backup: bool,
    mode: str,
    probe_id: str | None,
    force_known_legacy: bool,
    runtime_probe_site_va: int | None,
    runtime_probe_expected: bytes | None,
    runtime_probe_original_target_va: int | None,
    runtime_probe_pop_bytes: int | None,
) -> dict[str, Any]:
    runtime_probe: dict[str, Any] | None = None
    if mode not in PATCH_MODES:
        raise ValueError(f"Unsupported mode: {mode}")
    if mode == "instrument":
        if not probe_id:
            raise ValueError(
                f"--probe-id is required in instrument mode. Allowed built-ins: {', '.join(PROBE_IDS)}; "
                "runtime probe ids must start with 'runtime_'."
            )
        if (probe_id not in PROBE_IDS) and (not _is_runtime_probe_id(probe_id)):
            raise ValueError(
                f"Unknown probe id {probe_id!r}. Allowed built-ins: {', '.join(PROBE_IDS)}; "
                "runtime probe ids must start with 'runtime_'."
            )
        if _is_runtime_probe_id(probe_id):
            if runtime_probe_site_va is None or runtime_probe_expected is None:
                raise ValueError(
                    "Runtime probe ids require --runtime-probe-site-va and --runtime-probe-expected-hex."
                )
            if len(runtime_probe_expected) != 5:
                raise ValueError(
                    "--runtime-probe-expected-hex must be exactly 5 bytes (CALL rel32 site)."
                )
            runtime_probe = {
                "site_va": runtime_probe_site_va,
                "expected": runtime_probe_expected,
                "original_target_va": runtime_probe_original_target_va,
                "pop_bytes": int(runtime_probe_pop_bytes if runtime_probe_pop_bytes is not None else 4),
            }
            if runtime_probe["pop_bytes"] not in (0, 4, 8):
                raise ValueError("--runtime-probe-pop-bytes must be one of: 0, 4, 8.")
        elif (
            runtime_probe_site_va is not None
            or runtime_probe_expected is not None
            or runtime_probe_original_target_va is not None
            or runtime_probe_pop_bytes is not None
        ):
            raise ValueError(
                "Runtime probe args are only valid with runtime_* probe ids."
            )
    elif probe_id is not None:
        raise ValueError("--probe-id is only valid with --mode instrument")
    elif (
        runtime_probe_site_va is not None
        or runtime_probe_expected is not None
        or runtime_probe_original_target_va is not None
        or runtime_probe_pop_bytes is not None
    ):
        raise ValueError("Runtime probe args are only valid with --mode instrument runtime_* probe ids.")

    input_bytes = input_exe.read_bytes()
    if mode == "stable":
        if not STABLE_BASELINE_EXE.exists():
            raise FileNotFoundError(
                f"Stable baseline not found: {STABLE_BASELINE_EXE}"
            )
        output_bytes = STABLE_BASELINE_EXE.read_bytes()
        target_out, backup_path = _write_output_bytes(
            input_exe=input_exe,
            output_exe=output_exe,
            in_place=in_place,
            dry_run=dry_run,
            make_backup=make_backup,
            output_bytes=output_bytes,
        )
        return {
            "input_exe": str(input_exe),
            "output_exe": str(target_out),
            "backup_exe": str(backup_path) if backup_path else None,
            "dry_run": bool(dry_run),
            "mode": mode,
            "probe_id": probe_id,
            "patch_count": 0,
            "patches": [],
            "sha256": {
                "input": _sha256(input_bytes),
                "output": _sha256(output_bytes),
            },
            "notes": [
                "Stable mode selected: output bytes copied from canonical stable baseline image.",
                f"Baseline source: {STABLE_BASELINE_EXE}",
            ],
        }

    patched = bytearray(input_bytes)

    bundle, string_addrs, legacy_bundle_prefixes = _build_bundle(
        unknown_text=_probe_unknown_text(probe_id if mode == "instrument" else None),
    )

    search_text_helper_va = CAVE_BUNDLE_BASE_VA
    search_text_helper_len = len(
        _build_search_window_team_prepush_helper(
            cave_va=CAVE_BUNDLE_BASE_VA,
            stars_va=string_addrs["stars"],
            free_va=string_addrs["free"],
            unknown_va=string_addrs["unknown"],
        )
    )
    name_ptr_guard_helper_va = CAVE_NAME_PTR_GUARD_HELPER_VA
    lookup_helper_va = CAVE_BUNDLE_BASE_VA + search_text_helper_len

    patches = _build_patch_plan(
        search_text_helper_va=search_text_helper_va,
        name_ptr_guard_helper_va=name_ptr_guard_helper_va,
        lookup_helper_va=lookup_helper_va,
        hover_draw_helper_va=CAVE_HOVER_DRAW_HELPER_VA,
        hover_field_stage1_va=CAVE_HOVER_FIELD_STAGE1_VA,
        mode=mode,
        probe_id=probe_id,
        lookup_call_probe_helper_va=CAVE_LOOKUP_MISS_HELPER_VA,
        runtime_probe_helper_va=CAVE_RUNTIME_PROBE_HELPER_VA,
        runtime_probe=runtime_probe,
    )

    rows: list[dict[str, Any]] = []

    # Write bundle cave region.
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

    # Apply direct patch sites.
    for spec in patches:
        if len(spec.expected) != len(spec.replacement):
            raise RuntimeError(
                f"Internal patch size mismatch for {spec.name}: "
                f"expected={len(spec.expected)} replacement={len(spec.replacement)}"
            )
        site_off = _va_to_file_offset(input_bytes, spec.site_va)
        current_site = input_bytes[site_off: site_off + len(spec.expected)]
        if spec.known_bad:
            _reject_known_bad_signature(
                current=current_site,
                known_bad=spec.known_bad,
                context=f"{spec.name} (0x{spec.site_va:08X})",
                force_known_legacy=force_known_legacy,
            )
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

    # Write staged search-hover field-level fallback caves.
    hover_field_stage1 = _build_search_hover_field_stage1(
        cave_va=CAVE_HOVER_FIELD_STAGE1_VA,
        stage2_va=CAVE_HOVER_FIELD_STAGE2_VA,
    )
    if len(hover_field_stage1) > CAVE_HOVER_FIELD_STAGE1_SIZE:
        raise RuntimeError(
            f"Search-hover stage1 overflow ({len(hover_field_stage1)} > {CAVE_HOVER_FIELD_STAGE1_SIZE})"
        )
    hover_field_stage1_blob = hover_field_stage1 + (
        b"\x90" * (CAVE_HOVER_FIELD_STAGE1_SIZE - len(hover_field_stage1))
    )
    hover_field_stage1_off = _va_to_file_offset(input_bytes, CAVE_HOVER_FIELD_STAGE1_VA)
    current_hover_field_stage1 = input_bytes[
        hover_field_stage1_off: hover_field_stage1_off + CAVE_HOVER_FIELD_STAGE1_SIZE
    ]
    hover_field_stage1_empty = current_hover_field_stage1 in {
        b"\xCC" * CAVE_HOVER_FIELD_STAGE1_SIZE,
        b"\x90" * CAVE_HOVER_FIELD_STAGE1_SIZE,
        b"\x00" * CAVE_HOVER_FIELD_STAGE1_SIZE,
    }
    if (
        (not force)
        and (not hover_field_stage1_empty)
        and (current_hover_field_stage1 != hover_field_stage1_blob)
    ):
        raise RuntimeError(
            "Search-hover stage1 cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        hover_field_stage1_off: hover_field_stage1_off + CAVE_HOVER_FIELD_STAGE1_SIZE
    ] = hover_field_stage1_blob
    rows.append(
        {
            "name": "write_search_hover_field_stage1_cave",
            "site_va": f"0x{CAVE_HOVER_FIELD_STAGE1_VA:08X}",
            "site_file_offset": f"0x{hover_field_stage1_off:08X}",
            "site_before": current_hover_field_stage1.hex(),
            "site_after": hover_field_stage1_blob.hex(),
            "bytes_written": CAVE_HOVER_FIELD_STAGE1_SIZE,
        }
    )

    hover_field_stage2 = _build_search_hover_field_stage2(
        cave_va=CAVE_HOVER_FIELD_STAGE2_VA,
        stage3_va=CAVE_HOVER_FIELD_STAGE3_VA,
    )
    if len(hover_field_stage2) > CAVE_HOVER_FIELD_STAGE2_SIZE:
        raise RuntimeError(
            f"Search-hover stage2 overflow ({len(hover_field_stage2)} > {CAVE_HOVER_FIELD_STAGE2_SIZE})"
        )
    hover_field_stage2_blob = hover_field_stage2 + (
        b"\x90" * (CAVE_HOVER_FIELD_STAGE2_SIZE - len(hover_field_stage2))
    )
    hover_field_stage2_off = _va_to_file_offset(input_bytes, CAVE_HOVER_FIELD_STAGE2_VA)
    current_hover_field_stage2 = input_bytes[
        hover_field_stage2_off: hover_field_stage2_off + CAVE_HOVER_FIELD_STAGE2_SIZE
    ]
    hover_field_stage2_empty = current_hover_field_stage2 in {
        b"\xCC" * CAVE_HOVER_FIELD_STAGE2_SIZE,
        b"\x90" * CAVE_HOVER_FIELD_STAGE2_SIZE,
        b"\x00" * CAVE_HOVER_FIELD_STAGE2_SIZE,
    }
    if (
        (not force)
        and (not hover_field_stage2_empty)
        and (current_hover_field_stage2 != hover_field_stage2_blob)
    ):
        raise RuntimeError(
            "Search-hover stage2 cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        hover_field_stage2_off: hover_field_stage2_off + CAVE_HOVER_FIELD_STAGE2_SIZE
    ] = hover_field_stage2_blob
    rows.append(
        {
            "name": "write_search_hover_field_stage2_cave",
            "site_va": f"0x{CAVE_HOVER_FIELD_STAGE2_VA:08X}",
            "site_file_offset": f"0x{hover_field_stage2_off:08X}",
            "site_before": current_hover_field_stage2.hex(),
            "site_after": hover_field_stage2_blob.hex(),
            "bytes_written": CAVE_HOVER_FIELD_STAGE2_SIZE,
        }
    )

    hover_field_stage3_default = _build_search_hover_field_stage3(
        cave_va=CAVE_HOVER_FIELD_STAGE3_VA,
        resume_va=0x0041E756,
        sanitize_helper_va=CAVE_HOVER_DRAW_HELPER_VA,
    )
    hover_field_stage3_probe = _build_search_hover_field_stage3_force_marker(
        cave_va=CAVE_HOVER_FIELD_STAGE3_VA,
        resume_va=0x0041E756,
        marker_va=string_addrs["unknown"],
    )
    if mode == "instrument" and probe_id == "hover_field_stage3":
        hover_field_stage3 = hover_field_stage3_probe
    else:
        hover_field_stage3 = _build_search_hover_field_stage3(
            cave_va=CAVE_HOVER_FIELD_STAGE3_VA,
            resume_va=0x0041E756,
            sanitize_helper_va=CAVE_HOVER_DRAW_HELPER_VA,
        )
    if len(hover_field_stage3) > CAVE_HOVER_FIELD_STAGE3_SIZE:
        raise RuntimeError(
            f"Search-hover stage3 overflow ({len(hover_field_stage3)} > {CAVE_HOVER_FIELD_STAGE3_SIZE})"
        )
    hover_field_stage3_blob = hover_field_stage3 + (
        b"\x90" * (CAVE_HOVER_FIELD_STAGE3_SIZE - len(hover_field_stage3))
    )
    hover_field_stage3_default_blob = hover_field_stage3_default + (
        b"\x90" * (CAVE_HOVER_FIELD_STAGE3_SIZE - len(hover_field_stage3_default))
    )
    hover_field_stage3_probe_blob = hover_field_stage3_probe + (
        b"\x90" * (CAVE_HOVER_FIELD_STAGE3_SIZE - len(hover_field_stage3_probe))
    )
    hover_field_stage3_legacy_blob = bytes.fromhex("8038007505b8ad516e00e976a4d3ff")
    hover_field_stage3_off = _va_to_file_offset(input_bytes, CAVE_HOVER_FIELD_STAGE3_VA)
    current_hover_field_stage3 = input_bytes[
        hover_field_stage3_off: hover_field_stage3_off + CAVE_HOVER_FIELD_STAGE3_SIZE
    ]
    hover_field_stage3_empty = current_hover_field_stage3 in {
        b"\xCC" * CAVE_HOVER_FIELD_STAGE3_SIZE,
        b"\x90" * CAVE_HOVER_FIELD_STAGE3_SIZE,
        b"\x00" * CAVE_HOVER_FIELD_STAGE3_SIZE,
    }
    if (
        (not force)
        and (not hover_field_stage3_empty)
        and (current_hover_field_stage3 != hover_field_stage3_blob)
        and (current_hover_field_stage3 != hover_field_stage3_default_blob)
        and (current_hover_field_stage3 != hover_field_stage3_probe_blob)
        and (current_hover_field_stage3 != hover_field_stage3_legacy_blob)
    ):
        raise RuntimeError(
            "Search-hover stage3 cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        hover_field_stage3_off: hover_field_stage3_off + CAVE_HOVER_FIELD_STAGE3_SIZE
    ] = hover_field_stage3_blob
    rows.append(
        {
            "name": "write_search_hover_field_stage3_cave",
            "site_va": f"0x{CAVE_HOVER_FIELD_STAGE3_VA:08X}",
            "site_file_offset": f"0x{hover_field_stage3_off:08X}",
            "site_before": current_hover_field_stage3.hex(),
            "site_after": hover_field_stage3_blob.hex(),
            "bytes_written": CAVE_HOVER_FIELD_STAGE3_SIZE,
        }
    )

    # Write secondary-chain null-guard stage caves near FUN_0064ce30.
    secondary_stage0 = _build_secondary_chain_guard_stage0(
        cave_va=SECONDARY_CHAIN_GUARD_STAGE0_VA,
        stage1_va=SECONDARY_CHAIN_GUARD_STAGE1_VA,
    )
    if len(secondary_stage0) > SECONDARY_CHAIN_GUARD_STAGE0_SIZE:
        raise RuntimeError(
            f"Secondary guard stage0 overflow ({len(secondary_stage0)} > {SECONDARY_CHAIN_GUARD_STAGE0_SIZE})"
        )
    secondary_stage0_blob = secondary_stage0 + (
        b"\x90" * (SECONDARY_CHAIN_GUARD_STAGE0_SIZE - len(secondary_stage0))
    )
    secondary_stage0_off = _va_to_file_offset(input_bytes, SECONDARY_CHAIN_GUARD_STAGE0_VA)
    current_secondary_stage0 = input_bytes[
        secondary_stage0_off: secondary_stage0_off + SECONDARY_CHAIN_GUARD_STAGE0_SIZE
    ]
    secondary_stage0_empty = current_secondary_stage0 == (b"\x90" * SECONDARY_CHAIN_GUARD_STAGE0_SIZE)
    if (not force) and (not secondary_stage0_empty) and (current_secondary_stage0 != secondary_stage0_blob):
        raise RuntimeError(
            "Secondary guard stage0 cave bytes are not recognized. "
            "Use --force only after manual verification."
        )
    patched[
        secondary_stage0_off: secondary_stage0_off + SECONDARY_CHAIN_GUARD_STAGE0_SIZE
    ] = secondary_stage0_blob
    rows.append(
        {
            "name": "write_secondary_chain_guard_stage0_cave",
            "site_va": f"0x{SECONDARY_CHAIN_GUARD_STAGE0_VA:08X}",
            "site_file_offset": f"0x{secondary_stage0_off:08X}",
            "site_before": current_secondary_stage0.hex(),
            "site_after": secondary_stage0_blob.hex(),
            "bytes_written": SECONDARY_CHAIN_GUARD_STAGE0_SIZE,
        }
    )

    secondary_stage1 = _build_secondary_chain_guard_stage1(
        cave_va=SECONDARY_CHAIN_GUARD_STAGE1_VA,
        stage2_va=SECONDARY_CHAIN_GUARD_STAGE2_VA,
    )
    if len(secondary_stage1) > SECONDARY_CHAIN_GUARD_STAGE1_SIZE:
        raise RuntimeError(
            f"Secondary guard stage1 overflow ({len(secondary_stage1)} > {SECONDARY_CHAIN_GUARD_STAGE1_SIZE})"
        )
    secondary_stage1_blob = secondary_stage1 + (
        b"\x90" * (SECONDARY_CHAIN_GUARD_STAGE1_SIZE - len(secondary_stage1))
    )
    secondary_stage1_off = _va_to_file_offset(input_bytes, SECONDARY_CHAIN_GUARD_STAGE1_VA)
    current_secondary_stage1 = input_bytes[
        secondary_stage1_off: secondary_stage1_off + SECONDARY_CHAIN_GUARD_STAGE1_SIZE
    ]
    secondary_stage1_empty = current_secondary_stage1 == (b"\x90" * SECONDARY_CHAIN_GUARD_STAGE1_SIZE)
    if (not force) and (not secondary_stage1_empty) and (current_secondary_stage1 != secondary_stage1_blob):
        raise RuntimeError(
            "Secondary guard stage1 cave bytes are not recognized. "
            "Use --force only after manual verification."
        )
    patched[
        secondary_stage1_off: secondary_stage1_off + SECONDARY_CHAIN_GUARD_STAGE1_SIZE
    ] = secondary_stage1_blob
    rows.append(
        {
            "name": "write_secondary_chain_guard_stage1_cave",
            "site_va": f"0x{SECONDARY_CHAIN_GUARD_STAGE1_VA:08X}",
            "site_file_offset": f"0x{secondary_stage1_off:08X}",
            "site_before": current_secondary_stage1.hex(),
            "site_after": secondary_stage1_blob.hex(),
            "bytes_written": SECONDARY_CHAIN_GUARD_STAGE1_SIZE,
        }
    )

    secondary_stage2 = _build_secondary_chain_guard_stage2(
        cave_va=SECONDARY_CHAIN_GUARD_STAGE2_VA,
        resume_va=0x0064CFDA,
    )
    if len(secondary_stage2) > SECONDARY_CHAIN_GUARD_STAGE2_SIZE:
        raise RuntimeError(
            f"Secondary guard stage2 overflow ({len(secondary_stage2)} > {SECONDARY_CHAIN_GUARD_STAGE2_SIZE})"
        )
    secondary_stage2_blob = secondary_stage2 + (
        b"\x90" * (SECONDARY_CHAIN_GUARD_STAGE2_SIZE - len(secondary_stage2))
    )
    secondary_stage2_off = _va_to_file_offset(input_bytes, SECONDARY_CHAIN_GUARD_STAGE2_VA)
    current_secondary_stage2 = input_bytes[
        secondary_stage2_off: secondary_stage2_off + SECONDARY_CHAIN_GUARD_STAGE2_SIZE
    ]
    secondary_stage2_empty = current_secondary_stage2 == (b"\x90" * SECONDARY_CHAIN_GUARD_STAGE2_SIZE)
    secondary_stage2_legacy = bytes.fromhex("ff5058e966ffffff90")
    if (
        (not force)
        and (not secondary_stage2_empty)
        and (current_secondary_stage2 != secondary_stage2_blob)
        and (current_secondary_stage2 != secondary_stage2_legacy)
    ):
        raise RuntimeError(
            "Secondary guard stage2 cave bytes are not recognized. "
            "Use --force only after manual verification."
        )
    patched[
        secondary_stage2_off: secondary_stage2_off + SECONDARY_CHAIN_GUARD_STAGE2_SIZE
    ] = secondary_stage2_blob
    rows.append(
        {
            "name": "write_secondary_chain_guard_stage2_cave",
            "site_va": f"0x{SECONDARY_CHAIN_GUARD_STAGE2_VA:08X}",
            "site_file_offset": f"0x{secondary_stage2_off:08X}",
            "site_before": current_secondary_stage2.hex(),
            "site_after": secondary_stage2_blob.hex(),
            "bytes_written": SECONDARY_CHAIN_GUARD_STAGE2_SIZE,
        }
    )

    # Write caller-specific FUN_0049A410 post-call non-empty sanitizer stages.
    lookup_nonempty_stage1 = _build_lookup_nonempty_wrapper_stage1(
        cave_va=CAVE_D1_PTR_STAGE1_VA,
        stage2_va=CAVE_D1_PTR_STAGE2_VA,
    )
    if len(lookup_nonempty_stage1) > CAVE_D1_PTR_STAGE1_SIZE:
        raise RuntimeError(
            f"Lookup non-empty stage1 overflow ({len(lookup_nonempty_stage1)} > {CAVE_D1_PTR_STAGE1_SIZE})"
        )
    lookup_nonempty_stage1_blob = lookup_nonempty_stage1 + (
        b"\x90" * (CAVE_D1_PTR_STAGE1_SIZE - len(lookup_nonempty_stage1))
    )
    lookup_nonempty_stage1_off = _va_to_file_offset(input_bytes, CAVE_D1_PTR_STAGE1_VA)
    current_lookup_nonempty_stage1 = input_bytes[
        lookup_nonempty_stage1_off: lookup_nonempty_stage1_off + CAVE_D1_PTR_STAGE1_SIZE
    ]
    lookup_nonempty_stage1_legacy_d1 = _build_search_token_d1_ptr_stage1(
        cave_va=CAVE_D1_PTR_STAGE1_VA,
        lowptr_guard_va=CAVE_LE_DE_WRAPPER_VA,
        stage2_va=CAVE_D1_PTR_STAGE2_VA,
    )
    # Previous broken entry-wrapper variant (called FUN_0049A410 from this cave),
    # kept as a known upgrade signature.
    lookup_nonempty_stage1_legacy_entry_wrap = (
        b"\xE8" + _rel32(CAVE_D1_PTR_STAGE1_VA, 5, 0x0049A410)
        + b"\xE9" + _rel32(CAVE_D1_PTR_STAGE1_VA + 5, 5, CAVE_D1_PTR_STAGE2_VA)
    )
    lookup_nonempty_stage1_legacy_v1 = bytes.fromhex("85c074088038007505e9d2020000c3")
    lookup_nonempty_stage1_legacy_v2 = bytes.fromhex("85c074058038007505e9d2020000c3")
    lookup_nonempty_stage1_legacy_v3 = bytes.fromhex("85c0740680382e7602c3e9d1020000")
    lookup_nonempty_stage1_legacy_force_unknown = (
        b"\xE9" + _rel32(CAVE_D1_PTR_STAGE1_VA, 5, CAVE_D1_PTR_STAGE2_VA) + b"\xC3"
    )
    lookup_nonempty_stage1_legacy_ok = (
        current_lookup_nonempty_stage1.startswith(lookup_nonempty_stage1_legacy_d1)
        or current_lookup_nonempty_stage1.startswith(lookup_nonempty_stage1_legacy_entry_wrap)
        or current_lookup_nonempty_stage1.startswith(lookup_nonempty_stage1_legacy_v1)
        or current_lookup_nonempty_stage1.startswith(lookup_nonempty_stage1_legacy_v2)
        or current_lookup_nonempty_stage1.startswith(lookup_nonempty_stage1_legacy_v3)
        or current_lookup_nonempty_stage1.startswith(lookup_nonempty_stage1_legacy_force_unknown)
    )
    _reject_known_bad_signature(
        current=current_lookup_nonempty_stage1,
        known_bad=(lookup_nonempty_stage1_legacy_entry_wrap,),
        context="lookup_nonempty_stage1 cave",
        force_known_legacy=force_known_legacy,
    )
    lookup_nonempty_stage1_empty = current_lookup_nonempty_stage1 in {
        b"\x90" * CAVE_D1_PTR_STAGE1_SIZE,
        b"\x00" * CAVE_D1_PTR_STAGE1_SIZE,
    }
    if (
        (not force)
        and (not lookup_nonempty_stage1_empty)
        and (current_lookup_nonempty_stage1 != lookup_nonempty_stage1_blob)
        and (not lookup_nonempty_stage1_legacy_ok)
    ):
        raise RuntimeError(
            "Lookup non-empty stage1 cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        lookup_nonempty_stage1_off: lookup_nonempty_stage1_off + CAVE_D1_PTR_STAGE1_SIZE
    ] = lookup_nonempty_stage1_blob
    rows.append(
        {
            "name": "write_lookup_nonempty_stage1_cave",
            "site_va": f"0x{CAVE_D1_PTR_STAGE1_VA:08X}",
            "site_file_offset": f"0x{lookup_nonempty_stage1_off:08X}",
            "site_before": current_lookup_nonempty_stage1.hex(),
            "site_after": lookup_nonempty_stage1_blob.hex(),
            "bytes_written": CAVE_D1_PTR_STAGE1_SIZE,
        }
    )

    lookup_nonempty_stage2_default = _build_stack_slot_fill_bridge(
        cave_va=CAVE_D1_PTR_STAGE2_VA,
        stack_disp=0x3C,
        sanitize_helper_va=CAVE_HOVER_DRAW_HELPER_VA,
    )
    lookup_nonempty_stage2_probe = _build_return_marker_ptr_bridge(
        marker_va=string_addrs["unknown"],
    )
    if mode == "instrument" and probe_id == "postcall_68e52":
        lookup_nonempty_stage2 = lookup_nonempty_stage2_probe
    else:
        lookup_nonempty_stage2 = lookup_nonempty_stage2_default
    if len(lookup_nonempty_stage2) > CAVE_D1_PTR_STAGE2_SIZE:
        raise RuntimeError(
            f"Lookup non-empty stage2 overflow ({len(lookup_nonempty_stage2)} > {CAVE_D1_PTR_STAGE2_SIZE})"
        )
    lookup_nonempty_stage2_blob = lookup_nonempty_stage2 + (
        b"\x90" * (CAVE_D1_PTR_STAGE2_SIZE - len(lookup_nonempty_stage2))
    )
    lookup_nonempty_stage2_default_blob = lookup_nonempty_stage2_default + (
        b"\x90" * (CAVE_D1_PTR_STAGE2_SIZE - len(lookup_nonempty_stage2_default))
    )
    lookup_nonempty_stage2_probe_blob = lookup_nonempty_stage2_probe + (
        b"\x90" * (CAVE_D1_PTR_STAGE2_SIZE - len(lookup_nonempty_stage2_probe))
    )
    lookup_nonempty_stage2_off = _va_to_file_offset(input_bytes, CAVE_D1_PTR_STAGE2_VA)
    current_lookup_nonempty_stage2 = input_bytes[
        lookup_nonempty_stage2_off: lookup_nonempty_stage2_off + CAVE_D1_PTR_STAGE2_SIZE
    ]
    lookup_nonempty_stage2_legacy_d1 = _build_search_token_d1_ptr_stage2(
        cave_va=CAVE_D1_PTR_STAGE2_VA,
        resume_va=0x00499E68,
    )
    lookup_nonempty_stage2_legacy_prev = _build_lookup_nonempty_wrapper_stage2(
        unknown_va=string_addrs["unknown"],
        sanitize_helper_va=FORMATTTER_ARG3_GUARD_VA,
        cave_va=CAVE_D1_PTR_STAGE2_VA,
    )
    lookup_nonempty_stage2_legacy_prev_5fc92f = _build_lookup_nonempty_wrapper_stage2(
        unknown_va=string_addrs["unknown"],
        sanitize_helper_va=CAVE_HOVER_DRAW_HELPER_VA,
        cave_va=CAVE_D1_PTR_STAGE2_VA,
    )
    lookup_nonempty_stage2_legacy_entry_wrap = bytes.fromhex("85c074058038007505b8ad516e00c3")
    lookup_nonempty_stage2_legacy_v1 = bytes.fromhex("68ad516e0050ff1508616e00c39090")
    lookup_nonempty_stage2_legacy_v2 = bytes.fromhex("85c07506b8ad516e00c3e911280000")
    lookup_nonempty_stage2_legacy_ok = (
        current_lookup_nonempty_stage2.startswith(lookup_nonempty_stage2_legacy_d1)
        or current_lookup_nonempty_stage2.startswith(lookup_nonempty_stage2_legacy_prev)
        or current_lookup_nonempty_stage2.startswith(lookup_nonempty_stage2_legacy_prev_5fc92f)
        or current_lookup_nonempty_stage2.startswith(lookup_nonempty_stage2_legacy_entry_wrap)
        or current_lookup_nonempty_stage2.startswith(lookup_nonempty_stage2_legacy_v1)
        or current_lookup_nonempty_stage2.startswith(lookup_nonempty_stage2_legacy_v2)
    )
    _reject_known_bad_signature(
        current=current_lookup_nonempty_stage2,
        known_bad=(lookup_nonempty_stage2_legacy_entry_wrap,),
        context="lookup_nonempty_stage2 cave",
        force_known_legacy=force_known_legacy,
    )
    lookup_nonempty_stage2_empty = current_lookup_nonempty_stage2 in {
        b"\x90" * CAVE_D1_PTR_STAGE2_SIZE,
        b"\x00" * CAVE_D1_PTR_STAGE2_SIZE,
    }
    if (
        (not force)
        and (not lookup_nonempty_stage2_empty)
        and (current_lookup_nonempty_stage2 != lookup_nonempty_stage2_blob)
        and (current_lookup_nonempty_stage2 != lookup_nonempty_stage2_default_blob)
        and (current_lookup_nonempty_stage2 != lookup_nonempty_stage2_probe_blob)
        and (not lookup_nonempty_stage2_legacy_ok)
    ):
        raise RuntimeError(
            "Lookup non-empty stage2 cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        lookup_nonempty_stage2_off: lookup_nonempty_stage2_off + CAVE_D1_PTR_STAGE2_SIZE
    ] = lookup_nonempty_stage2_blob
    rows.append(
        {
            "name": "write_lookup_nonempty_stage2_cave",
            "site_va": f"0x{CAVE_D1_PTR_STAGE2_VA:08X}",
            "site_file_offset": f"0x{lookup_nonempty_stage2_off:08X}",
            "site_before": current_lookup_nonempty_stage2.hex(),
            "site_after": lookup_nonempty_stage2_blob.hex(),
            "bytes_written": CAVE_D1_PTR_STAGE2_SIZE,
        }
    )

    # Reuse shared cave slot for lstrcpyA source-copy shim.
    fmt_guard_wrapper_default = _build_lstrcpy_src_empty_fallback_helper(
        unknown_va=string_addrs["unknown"],
    )
    if mode == "instrument" and probe_id == "bio_copy_src_43f24f":
        fmt_guard_wrapper = _build_lstrcpy_force_src_helper(
            marker_va=string_addrs["unknown"],
        )
    else:
        fmt_guard_wrapper = fmt_guard_wrapper_default
    if len(fmt_guard_wrapper) > FORMATTTER_ARG3_GUARD_SIZE:
        raise RuntimeError(
            f"Lookup caller wrapper overflow ({len(fmt_guard_wrapper)} > {FORMATTTER_ARG3_GUARD_SIZE})"
        )
    fmt_guard_wrapper_blob = fmt_guard_wrapper + (
        b"\x90" * (FORMATTTER_ARG3_GUARD_SIZE - len(fmt_guard_wrapper))
    )
    fmt_guard_wrapper_default_blob = fmt_guard_wrapper_default + (
        b"\x90" * (FORMATTTER_ARG3_GUARD_SIZE - len(fmt_guard_wrapper_default))
    )
    fmt_guard_wrapper_off = _va_to_file_offset(input_bytes, FORMATTTER_ARG3_GUARD_VA)
    current_fmt_guard_wrapper = input_bytes[
        fmt_guard_wrapper_off: fmt_guard_wrapper_off + FORMATTTER_ARG3_GUARD_SIZE
    ]
    known_bad_fmt_guard_prefixes = (
        # Malformed short-jump wrappers that caused c0000096 at 0x006E51F9.
        bytes.fromhex("817c2408cc4a7300751066837c240e007508c744240cad516e00e98bffffff"),
        bytes.fromhex("817c2408cc4a73007512817c240c00606e007308c744240cad516e00eb8c90"),
    )
    _reject_known_bad_signature(
        current=current_fmt_guard_wrapper,
        known_bad=known_bad_fmt_guard_prefixes,
        context="formatter arg3 wrapper cave",
        force_known_legacy=force_known_legacy,
    )
    fmt_guard_wrapper_empty = current_fmt_guard_wrapper in {
        b"\x90" * FORMATTTER_ARG3_GUARD_SIZE,
        b"\x00" * FORMATTTER_ARG3_GUARD_SIZE,
    }
    fmt_guard_wrapper_legacy_prefixes = (
        # Previous sanitizer form.
        bytes.fromhex("8a1084d2740a80fa2e760580fa7a7701c368ad516e0050ff1508616e00c3"),
        bytes.fromhex("8a1084d2740b80fa2e760680fa7a7701c368ad516e0050ff1508616e00c390"),
        # Current v4 post-call helper form at 0x006E51E1.
        bytes.fromhex("85c07410803841720980387a760768ad516e0050ff1508616e00c3"),
        # Previous source-empty shim form (NUL-only fallback).
        bytes.fromhex("8b44240885c074058038007508c7442408ad516e00ff2508616e00"),
        # Previous source-empty shim form (<= '.' fallback; prior final baseline).
        bytes.fromhex("8b44240885c0740780382e76027800c7442408ad516e00ff2508616e00"),
        # Legacy pointer-guard helper variants.
        bytes.fromhex("85c074138b400485c0740c8a1084d27e0680fa2e7601c3b8ad516e00c39090"),
        bytes.fromhex("8b4510e80812030050e9d202000090"),
        # Instrument probe helper (force source pointer to marker text).
        _build_lstrcpy_force_src_helper(marker_va=string_addrs["unknown"]),
        # Legacy formatter wrappers from earlier experiments.
        bytes.fromhex("817c2408cc4a7300751066837c240e007508c744240cad516e00e98bffffff"),
        bytes.fromhex("817c2408cc4a73007512817c240c00606e007308c744240cad516e00eb8c90"),
        # 2026-03-22 fix-forward migration target:
        # buggy wrapper (JNE +0x0A / JNE +0x02) is now auto-migrated without --force.
        bytes.fromhex("817c2408cc4a7300750a66837c240e007502c744240cad516e00eb8e909090"),
        # 2026-03-10 caller-wrapper v1 at 0x005FC92F (arg-shift crash at 0x0049A48D).
        bytes.fromhex("e8dcdae9ff803800750c68ad516e0050ff1508616e00c300"),
        # 2026-03-10 caller-wrapper v2 at 0x006E51E1 (EDX return-save; random return crash).
        bytes.fromhex("5a68ec516e00e92452dbff52803800750c68ad516e0050ff1508616e00c390"),
        # 2026-03-10 caller-wrapper v3 at 0x006E51E1 (EBX return-save; zero-only fallback).
        bytes.fromhex("5b68ec516e00e92452dbff53803800750c68ad516e0050ff1508616e00c390"),
        # 2026-03-10 caller-wrapper v4 at 0x006E51E1 (EBX return-save; stage2 jmp).
        bytes.fromhex("5b68ec516e00e92452dbff53e93d77f1ff"),
        # 2026-03-10 post-call fill helper v1 at 0x006E51E1 (NUL-only).
        bytes.fromhex("50803800750c68ad516e0050ff1508616e0058c3"),
        # 2026-03-10 post-call fill helper v2 at 0x006E51E1 (<=0x20 fallback).
        bytes.fromhex("5085c07411803820770c68ad516e0050ff1508616e0058c3"),
        # 2026-03-10 post-call fill helper v3 at 0x006E51E1 (<=0x2e fallback).
        bytes.fromhex("5085c0741180382e770c68ad516e0050ff1508616e0058c3"),
    )
    if (
        (not force)
        and (not fmt_guard_wrapper_empty)
        and (current_fmt_guard_wrapper != fmt_guard_wrapper_blob)
        and (current_fmt_guard_wrapper != fmt_guard_wrapper_default_blob)
        and all(not current_fmt_guard_wrapper.startswith(prefix) for prefix in fmt_guard_wrapper_legacy_prefixes)
    ):
        raise RuntimeError(
            "Lookup caller wrapper cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        fmt_guard_wrapper_off: fmt_guard_wrapper_off + FORMATTTER_ARG3_GUARD_SIZE
    ] = fmt_guard_wrapper_blob
    rows.append(
        {
            "name": "write_lstrcpy_src_empty_fallback_helper_cave",
            "site_va": f"0x{FORMATTTER_ARG3_GUARD_VA:08X}",
            "site_file_offset": f"0x{fmt_guard_wrapper_off:08X}",
            "site_before": current_fmt_guard_wrapper.hex(),
            "site_after": fmt_guard_wrapper_blob.hex(),
            "bytes_written": FORMATTTER_ARG3_GUARD_SIZE,
        }
    )

    fmt_guard_thunk = _build_formatter_arg3_call_thunk()
    if len(fmt_guard_thunk) > FORMATTTER_ARG3_CALL_THUNK_SIZE:
        raise RuntimeError(
            f"Formatter arg3 call thunk overflow ({len(fmt_guard_thunk)} > {FORMATTTER_ARG3_CALL_THUNK_SIZE})"
        )
    fmt_guard_thunk_blob = fmt_guard_thunk + (
        b"\x90" * (FORMATTTER_ARG3_CALL_THUNK_SIZE - len(fmt_guard_thunk))
    )
    fmt_guard_thunk_off = _va_to_file_offset(input_bytes, FORMATTTER_ARG3_CALL_THUNK_VA)
    current_fmt_guard_thunk = input_bytes[
        fmt_guard_thunk_off: fmt_guard_thunk_off + FORMATTTER_ARG3_CALL_THUNK_SIZE
    ]
    fmt_guard_thunk_empty = current_fmt_guard_thunk in {
        b"\x90" * FORMATTTER_ARG3_CALL_THUNK_SIZE,
        b"\x00" * FORMATTTER_ARG3_CALL_THUNK_SIZE,
    }
    if (
        (not force)
        and (not fmt_guard_thunk_empty)
        and (current_fmt_guard_thunk != fmt_guard_thunk_blob)
    ):
        raise RuntimeError(
            "Formatter arg3 call-thunk cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        fmt_guard_thunk_off: fmt_guard_thunk_off + FORMATTTER_ARG3_CALL_THUNK_SIZE
    ] = fmt_guard_thunk_blob
    rows.append(
        {
            "name": "write_formatter_arg3_guard_call_thunk_cave",
            "site_va": f"0x{FORMATTTER_ARG3_CALL_THUNK_VA:08X}",
            "site_file_offset": f"0x{fmt_guard_thunk_off:08X}",
            "site_before": current_fmt_guard_thunk.hex(),
            "site_after": fmt_guard_thunk_blob.hex(),
            "bytes_written": FORMATTTER_ARG3_CALL_THUNK_SIZE,
        }
    )

    # Write caller-local adapter for FUN_0043BD10 post-call site:
    # load local_420 pointer ([esp+0x10] at helper entry) and tail-jump to fill helper.
    le_de_helper_default = _build_stack_slot_fill_bridge(
        cave_va=CAVE_LE_DE_WRAPPER_VA,
        stack_disp=0x10,
        sanitize_helper_va=CAVE_HOVER_DRAW_HELPER_VA,
    )
    if mode == "instrument" and probe_id == "postcall_43bd46":
        le_de_helper = _build_return_marker_ptr_bridge(
            marker_va=string_addrs["unknown"],
        )
    else:
        le_de_helper = le_de_helper_default
    if len(le_de_helper) > CAVE_LE_DE_WRAPPER_SIZE:
        raise RuntimeError(
            f"FUN_0043BD10 postcall wrapper overflow ({len(le_de_helper)} > {CAVE_LE_DE_WRAPPER_SIZE})"
        )
    le_de_blob = le_de_helper + (b"\x90" * (CAVE_LE_DE_WRAPPER_SIZE - len(le_de_helper)))
    le_de_default_blob = le_de_helper_default + (
        b"\x90" * (CAVE_LE_DE_WRAPPER_SIZE - len(le_de_helper_default))
    )

    le_de_off = _va_to_file_offset(input_bytes, CAVE_LE_DE_WRAPPER_VA)
    current_le_de = input_bytes[le_de_off: le_de_off + CAVE_LE_DE_WRAPPER_SIZE]
    le_de_is_empty = current_le_de in {
        b"\x00" * CAVE_LE_DE_WRAPPER_SIZE,
        b"\x90" * CAVE_LE_DE_WRAPPER_SIZE,
    }
    le_de_legacy_prefixes = (
        b"\xE9",  # old long jmp experiments
        # Previous low-pointer helper forms used in S2/S3 token experiments.
        _build_search_token_le_de_call_wrapper(
            cave_va=CAVE_LE_DE_WRAPPER_VA,
            original_lookup_va=0x004A4720,
        ),
        _build_lowptr_string_guard_helper(
            fallback_text_va=string_addrs["unknown"],
        ),
        bytes.fromhex("e811a9000085c075048b442410c3"),
        bytes.fromhex("68ad516e0050ff1508616e00c39090"),
        bytes.fromhex("3d000001007305b8ad516e00c3"),
        # Current FUN_0043BD10 post-call wrapper variant (sanitize helper at 0x006E51E1).
        bytes.fromhex("e87a0500008b442404e842b32400c3"),
        # Current FUN_0043BD10 post-call wrapper variant (sanitize helper at 0x005FC92F).
        _build_post_formatter_sanitize_wrapper(
            cave_va=CAVE_LE_DE_WRAPPER_VA,
            formatter_va=0x0049A410,
            sanitize_helper_va=CAVE_HOVER_DRAW_HELPER_VA,
        ),
        # Instrument probe helper (force EAX return pointer to marker text).
        _build_return_marker_ptr_bridge(marker_va=string_addrs["unknown"]),
        # 2026-03-10 local wrapper signature (rolled back).
        bytes.fromhex("e86afeffff8b442404e842b32400c3"),
    )
    le_de_is_known = any(current_le_de.startswith(prefix) for prefix in le_de_legacy_prefixes)
    if (
        (not force)
        and (not le_de_is_empty)
        and (not le_de_is_known)
        and (current_le_de != le_de_blob)
        and (current_le_de != le_de_default_blob)
    ):
        raise RuntimeError(
            "LE/DE wrapper cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )

    patched[le_de_off: le_de_off + CAVE_LE_DE_WRAPPER_SIZE] = le_de_blob
    rows.append(
        {
            "name": "write_search_profile_postcall_wrapper_cave",
            "site_va": f"0x{CAVE_LE_DE_WRAPPER_VA:08X}",
            "site_file_offset": f"0x{le_de_off:08X}",
            "site_before": current_le_de.hex(),
            "site_after": le_de_blob.hex(),
            "bytes_written": CAVE_LE_DE_WRAPPER_SIZE,
        }
    )

    # Write FUN_0049A410 miss helper cave (default fallback or probe bridge).
    lookup_call_probe_ids = {"lookup_call_68167", "lookup_call_681db", "lookup_call_6824b"}
    lookup_miss_helper_default = _build_lookup_miss_unknown_helper(
        unknown_va=string_addrs["unknown"],
    )
    lookup_miss_helper_probe_builtin = _build_return_marker_ptr_stdcall2(
        marker_va=string_addrs["unknown"],
    )
    lookup_miss_helper_probe_runtime = (
        _build_return_marker_ptr_ret_n(
            marker_va=string_addrs["unknown"],
            pop_bytes=int(runtime_probe["pop_bytes"]),
        )
        if (mode == "instrument" and runtime_probe is not None)
        else None
    )
    if mode == "instrument" and probe_id in lookup_call_probe_ids:
        lookup_miss_helper = lookup_miss_helper_probe_builtin
    elif mode == "instrument" and lookup_miss_helper_probe_runtime is not None:
        lookup_miss_helper = lookup_miss_helper_probe_runtime
    else:
        lookup_miss_helper = lookup_miss_helper_default
    if len(lookup_miss_helper) > CAVE_LOOKUP_MISS_HELPER_SIZE:
        raise RuntimeError(
            f"Lookup miss helper overflow ({len(lookup_miss_helper)} > {CAVE_LOOKUP_MISS_HELPER_SIZE})"
        )
    lookup_miss_blob = lookup_miss_helper + (
        b"\x90" * (CAVE_LOOKUP_MISS_HELPER_SIZE - len(lookup_miss_helper))
    )
    lookup_miss_default_blob = lookup_miss_helper_default + (
        b"\x90" * (CAVE_LOOKUP_MISS_HELPER_SIZE - len(lookup_miss_helper_default))
    )
    lookup_miss_probe_builtin_blob = lookup_miss_helper_probe_builtin + (
        b"\x90" * (CAVE_LOOKUP_MISS_HELPER_SIZE - len(lookup_miss_helper_probe_builtin))
    )
    lookup_miss_probe_runtime_blob = (
        lookup_miss_helper_probe_runtime
        + (b"\x90" * (CAVE_LOOKUP_MISS_HELPER_SIZE - len(lookup_miss_helper_probe_runtime)))
        if lookup_miss_helper_probe_runtime is not None
        else None
    )
    lookup_miss_off = _va_to_file_offset(input_bytes, CAVE_LOOKUP_MISS_HELPER_VA)
    current_lookup_miss = input_bytes[
        lookup_miss_off: lookup_miss_off + CAVE_LOOKUP_MISS_HELPER_SIZE
    ]
    lookup_miss_empty = current_lookup_miss in {
        b"\x00" * CAVE_LOOKUP_MISS_HELPER_SIZE,
        b"\x90" * CAVE_LOOKUP_MISS_HELPER_SIZE,
    }
    lookup_miss_legacy_call_through = bytes.fromhex("e84dd9e9ff85c07505b8ad516e00c3")
    if (
        (not force)
        and (not lookup_miss_empty)
        and (current_lookup_miss != lookup_miss_blob)
        and (current_lookup_miss != lookup_miss_default_blob)
        and (current_lookup_miss != lookup_miss_probe_builtin_blob)
        and (
            lookup_miss_probe_runtime_blob is None
            or current_lookup_miss != lookup_miss_probe_runtime_blob
        )
        and (current_lookup_miss != lookup_miss_legacy_call_through)
    ):
        raise RuntimeError(
            "Lookup miss helper cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        lookup_miss_off: lookup_miss_off + CAVE_LOOKUP_MISS_HELPER_SIZE
    ] = lookup_miss_blob
    rows.append(
        {
            "name": "write_search_lookup_miss_helper_cave",
            "site_va": f"0x{CAVE_LOOKUP_MISS_HELPER_VA:08X}",
            "site_file_offset": f"0x{lookup_miss_off:08X}",
            "site_before": current_lookup_miss.hex(),
            "site_after": lookup_miss_blob.hex(),
            "bytes_written": CAVE_LOOKUP_MISS_HELPER_SIZE,
        }
    )

    # Write isolated runtime probe helper cave (only for runtime_* probes).
    runtime_probe_helper = (
        _build_return_marker_ptr_ret_n(
            marker_va=string_addrs["unknown"],
            pop_bytes=int(runtime_probe["pop_bytes"]),
        )
        if runtime_probe is not None
        else None
    )
    runtime_probe_helper_blob = (
        runtime_probe_helper
        + (b"\xCC" * (CAVE_RUNTIME_PROBE_HELPER_SIZE - len(runtime_probe_helper)))
        if runtime_probe_helper is not None
        else None
    )
    runtime_probe_helper_off = _va_to_file_offset(input_bytes, CAVE_RUNTIME_PROBE_HELPER_VA)
    current_runtime_probe_helper = input_bytes[
        runtime_probe_helper_off: runtime_probe_helper_off + CAVE_RUNTIME_PROBE_HELPER_SIZE
    ]
    runtime_probe_helper_empty = current_runtime_probe_helper in {
        b"\x00" * CAVE_RUNTIME_PROBE_HELPER_SIZE,
        b"\x90" * CAVE_RUNTIME_PROBE_HELPER_SIZE,
        b"\xCC" * CAVE_RUNTIME_PROBE_HELPER_SIZE,
    }
    if runtime_probe_helper is not None:
        if len(runtime_probe_helper) > CAVE_RUNTIME_PROBE_HELPER_SIZE:
            raise RuntimeError(
                "Runtime probe helper overflow "
                f"({len(runtime_probe_helper)} > {CAVE_RUNTIME_PROBE_HELPER_SIZE})"
            )
        if (
            (not force)
            and (not runtime_probe_helper_empty)
            and (current_runtime_probe_helper != runtime_probe_helper_blob)
        ):
            raise RuntimeError(
                "Runtime probe helper cave bytes are not empty/known. "
                "Use --force only after manual verification."
            )
        patched[
            runtime_probe_helper_off: runtime_probe_helper_off + CAVE_RUNTIME_PROBE_HELPER_SIZE
        ] = runtime_probe_helper_blob
        rows.append(
            {
                "name": "write_runtime_probe_helper_cave",
                "site_va": f"0x{CAVE_RUNTIME_PROBE_HELPER_VA:08X}",
                "site_file_offset": f"0x{runtime_probe_helper_off:08X}",
                "site_before": current_runtime_probe_helper.hex(),
                "site_after": runtime_probe_helper_blob.hex(),
                "bytes_written": CAVE_RUNTIME_PROBE_HELPER_SIZE,
            }
        )

    # Write field-local hover draw wrapper cave (force source arg [esp+8] to Unknown club).
    hover_draw_wrapper = _build_force_unknown_stackarg_tailjmp_wrapper(
        cave_va=CAVE_HOVER_DRAW_WRAPPER_VA,
        target_va=0x0040D3E0,
        unknown_va=string_addrs["unknown"],
        arg_disp=0x08,
    )
    if len(hover_draw_wrapper) > CAVE_HOVER_DRAW_WRAPPER_SIZE:
        raise RuntimeError(
            f"Hover draw wrapper overflow ({len(hover_draw_wrapper)} > {CAVE_HOVER_DRAW_WRAPPER_SIZE})"
        )
    hover_draw_wrapper_blob = hover_draw_wrapper + (
        b"\xCC" * (CAVE_HOVER_DRAW_WRAPPER_SIZE - len(hover_draw_wrapper))
    )
    hover_draw_wrapper_legacy = _build_force_unknown_stackarg_tailjmp_wrapper(
        cave_va=CAVE_HOVER_DRAW_WRAPPER_VA,
        target_va=0x0040D3E0,
        unknown_va=string_addrs["unknown"],
        arg_disp=0x04,
    )
    hover_draw_wrapper_legacy_blob = hover_draw_wrapper_legacy + (
        b"\xCC" * (CAVE_HOVER_DRAW_WRAPPER_SIZE - len(hover_draw_wrapper_legacy))
    )
    hover_draw_wrapper_off = _va_to_file_offset(input_bytes, CAVE_HOVER_DRAW_WRAPPER_VA)
    current_hover_draw_wrapper = input_bytes[
        hover_draw_wrapper_off: hover_draw_wrapper_off + CAVE_HOVER_DRAW_WRAPPER_SIZE
    ]
    hover_draw_wrapper_empty = current_hover_draw_wrapper in {
        b"\x00" * CAVE_HOVER_DRAW_WRAPPER_SIZE,
        b"\x90" * CAVE_HOVER_DRAW_WRAPPER_SIZE,
        b"\xCC" * CAVE_HOVER_DRAW_WRAPPER_SIZE,
    }
    if (
        (not force)
        and (not hover_draw_wrapper_empty)
        and (current_hover_draw_wrapper != hover_draw_wrapper_blob)
        and (current_hover_draw_wrapper != hover_draw_wrapper_legacy_blob)
    ):
        raise RuntimeError(
            "Hover draw wrapper cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        hover_draw_wrapper_off: hover_draw_wrapper_off + CAVE_HOVER_DRAW_WRAPPER_SIZE
    ] = hover_draw_wrapper_blob
    rows.append(
        {
            "name": "write_hover_draw_wrapper_cave",
            "site_va": f"0x{CAVE_HOVER_DRAW_WRAPPER_VA:08X}",
            "site_file_offset": f"0x{hover_draw_wrapper_off:08X}",
            "site_before": current_hover_draw_wrapper.hex(),
            "site_after": hover_draw_wrapper_blob.hex(),
            "bytes_written": CAVE_HOVER_DRAW_WRAPPER_SIZE,
        }
    )

    # Write FUN_00499D00 null-token normalization helpers.
    token_null_norm_helper_default = _build_token_null_norm_helper(
        fallback_text_va=string_addrs["unknown"],
    )
    token_null_norm_helper = token_null_norm_helper_default
    if len(token_null_norm_helper) > CAVE_TOKEN_NULL_NORM_HELPER_SIZE:
        raise RuntimeError(
            f"Token null-normalizer overflow ({len(token_null_norm_helper)} > {CAVE_TOKEN_NULL_NORM_HELPER_SIZE})"
        )
    token_null_norm_blob = token_null_norm_helper + (
        b"\x90" * (CAVE_TOKEN_NULL_NORM_HELPER_SIZE - len(token_null_norm_helper))
    )
    token_null_norm_default_blob = token_null_norm_helper_default + (
        b"\x90" * (CAVE_TOKEN_NULL_NORM_HELPER_SIZE - len(token_null_norm_helper_default))
    )
    token_null_norm_off = _va_to_file_offset(input_bytes, CAVE_TOKEN_NULL_NORM_HELPER_VA)
    current_token_null_norm = input_bytes[
        token_null_norm_off: token_null_norm_off + CAVE_TOKEN_NULL_NORM_HELPER_SIZE
    ]
    token_null_norm_empty = current_token_null_norm in {
        b"\x00" * CAVE_TOKEN_NULL_NORM_HELPER_SIZE,
        b"\x90" * CAVE_TOKEN_NULL_NORM_HELPER_SIZE,
    }
    token_null_norm_legacy_blob = bytes.fromhex("85c07505b8ad516e0050c390909090")
    token_null_norm_probe_legacy = _build_return_marker_ptr_stdcall2(
        marker_va=string_addrs["unknown"],
    )
    token_null_norm_probe_legacy_blob = token_null_norm_probe_legacy + (
        b"\x90" * (CAVE_TOKEN_NULL_NORM_HELPER_SIZE - len(token_null_norm_probe_legacy))
    )
    if (
        (not force)
        and (not token_null_norm_empty)
        and (current_token_null_norm != token_null_norm_blob)
        and (current_token_null_norm != token_null_norm_default_blob)
        and (current_token_null_norm != token_null_norm_legacy_blob)
        and (current_token_null_norm != token_null_norm_probe_legacy_blob)
    ):
        raise RuntimeError(
            "Token null-normalizer cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        token_null_norm_off: token_null_norm_off + CAVE_TOKEN_NULL_NORM_HELPER_SIZE
    ] = token_null_norm_blob
    rows.append(
        {
            "name": "write_search_token_null_norm_helper_cave",
            "site_va": f"0x{CAVE_TOKEN_NULL_NORM_HELPER_VA:08X}",
            "site_file_offset": f"0x{token_null_norm_off:08X}",
            "site_before": current_token_null_norm.hex(),
            "site_after": token_null_norm_blob.hex(),
            "bytes_written": CAVE_TOKEN_NULL_NORM_HELPER_SIZE,
        }
    )

    token_null_push_helper = _build_token_null_push_helper(
        norm_helper_va=CAVE_TOKEN_NULL_NORM_HELPER_VA,
        cave_va=CAVE_TOKEN_NULL_PUSH_HELPER_VA,
    )
    if len(token_null_push_helper) > CAVE_TOKEN_NULL_PUSH_HELPER_SIZE:
        raise RuntimeError(
            f"Token null-push helper overflow ({len(token_null_push_helper)} > {CAVE_TOKEN_NULL_PUSH_HELPER_SIZE})"
        )
    token_null_push_blob = token_null_push_helper + (
        b"\x90" * (CAVE_TOKEN_NULL_PUSH_HELPER_SIZE - len(token_null_push_helper))
    )
    token_null_push_off = _va_to_file_offset(input_bytes, CAVE_TOKEN_NULL_PUSH_HELPER_VA)
    current_token_null_push = input_bytes[
        token_null_push_off: token_null_push_off + CAVE_TOKEN_NULL_PUSH_HELPER_SIZE
    ]
    token_null_push_empty = current_token_null_push in {
        b"\x00" * CAVE_TOKEN_NULL_PUSH_HELPER_SIZE,
        b"\x90" * CAVE_TOKEN_NULL_PUSH_HELPER_SIZE,
    }
    token_null_push_legacy_blob = bytes.fromhex("85c07505b8ad516e00c39090")
    token_null_push_broken_call_blob = bytes.fromhex("e86800000050c39090909090")
    if (
        (not force)
        and (not token_null_push_empty)
        and (current_token_null_push != token_null_push_blob)
        and (current_token_null_push != token_null_push_legacy_blob)
        and (current_token_null_push != token_null_push_broken_call_blob)
    ):
        raise RuntimeError(
            "Token null-push helper cave bytes are not empty/known. "
            "Use --force only after manual verification."
        )
    patched[
        token_null_push_off: token_null_push_off + CAVE_TOKEN_NULL_PUSH_HELPER_SIZE
    ] = token_null_push_blob
    rows.append(
        {
            "name": "write_search_token_null_push_helper_cave",
            "site_va": f"0x{CAVE_TOKEN_NULL_PUSH_HELPER_VA:08X}",
            "site_file_offset": f"0x{token_null_push_off:08X}",
            "site_before": current_token_null_push.hex(),
            "site_after": token_null_push_blob.hex(),
            "bytes_written": CAVE_TOKEN_NULL_PUSH_HELPER_SIZE,
        }
    )

    # Write shared hover source-pointer normalizer helper cave.
    hover_draw_helper = _build_source_ptr_fallback_helper(
        unknown_va=string_addrs["unknown"],
    )
    if len(hover_draw_helper) > CAVE_HOVER_DRAW_HELPER_SIZE:
        raise RuntimeError(
            f"Post-call fill helper overflow ({len(hover_draw_helper)} > {CAVE_HOVER_DRAW_HELPER_SIZE})"
        )
    hover_draw_blob = hover_draw_helper + (
        b"\x00" * (CAVE_HOVER_DRAW_HELPER_SIZE - len(hover_draw_helper))
    )
    hover_draw_off = _va_to_file_offset(input_bytes, CAVE_HOVER_DRAW_HELPER_VA)
    current_hover_draw = input_bytes[
        hover_draw_off: hover_draw_off + CAVE_HOVER_DRAW_HELPER_SIZE
    ]
    empty_template_legacy = _build_search_empty_template_fallback_helper(
        unknown_va=string_addrs["unknown"],
    )
    empty_template_legacy_blob = empty_template_legacy + (
        b"\x00" * (CAVE_HOVER_DRAW_HELPER_SIZE - len(empty_template_legacy))
    )
    hover_draw_legacy_blob = bytes.fromhex("e84dc3e6ff85c07505b8ad516e005056e89c0ae1ffc30000")
    hover_draw_legacy_blob_v2 = bytes.fromhex("e84dc3e6ff85c07505b8ad516e0081c63c900000c3000000")
    hover_draw_wrapper_prev = bytes.fromhex("8b4424045250e8a6d7e9ff8b442404e89e880e00c2080000")
    hover_draw_hard_fallback_legacy = bytes.fromhex("8b44240468ad516e0050ff1508616e00c208000000000000")
    hover_draw_stage2_threshold_legacy = bytes.fromhex("803820770868ad516e0050ff1508616e00c3000000000000")
    hover_draw_cmp0_legacy = bytes.fromhex("81c63c9000008038007505b8ad516e00c300000000000000")
    hover_draw_cmp41_legacy = bytes.fromhex("81c63c900000803841720580387a7605b8ad516e00c30000")
    hover_draw_cmp20_legacy = bytes.fromhex("81c63c90000085c074058038207705b8ad516e00c3000000")
    hover_draw_cmp2e_legacy = bytes.fromhex("81c63c90000085c0740580382e7705b8ad516e00c3000000")
    hover_draw_call_through_legacy = bytes.fromhex("e8dcdae9ff803800750c68ad516e0050ff1508616e00c300")
    hover_draw_prev_default_legacy = bytes.fromhex("85c07407803800750c68ad516e0050ff1508616e00c30000")
    hover_lookup_legacy_blob = bytes.fromhex(
        "e8dcdae9ffe848c3e6ff85c07505b8ad516e00c300000000"
    )
    _reject_known_bad_signature(
        current=current_hover_draw,
        known_bad=(
            hover_draw_wrapper_prev,
            hover_draw_hard_fallback_legacy,
            hover_lookup_legacy_blob,
        ),
        context="postcall fill helper cave",
        force_known_legacy=force_known_legacy,
    )
    source_ptr_norm_legacy_blob = bytes.fromhex("85c07407803800750cb8ad516e00c3000000000000000000")
    dest_fill_legacy_blob = bytes.fromhex("85c07410803841720980387a760768ad516e0050ff1508616e00c30000000000")
    dest_fill_prev_blob = bytes.fromhex("85c0740d80382e76037801c3e941eee6ffc3000000000000")
    dest_fill_lowptr_prev_blob = bytes.fromhex("85c0740f3d00000100720880382e76037801c3e93aeee6ff")
    hover_draw_is_known = current_hover_draw in {
        b"\x00" * CAVE_HOVER_DRAW_HELPER_SIZE,
        hover_draw_blob,
        source_ptr_norm_legacy_blob,
        dest_fill_legacy_blob,
        dest_fill_prev_blob,
        dest_fill_lowptr_prev_blob,
        empty_template_legacy_blob,
        hover_draw_legacy_blob,
        hover_draw_legacy_blob_v2,
        hover_draw_wrapper_prev,
        hover_draw_hard_fallback_legacy,
        hover_draw_stage2_threshold_legacy,
        hover_draw_cmp0_legacy,
        hover_draw_cmp41_legacy,
        hover_draw_cmp20_legacy,
        hover_draw_cmp2e_legacy,
        hover_draw_call_through_legacy,
        hover_draw_prev_default_legacy,
        hover_lookup_legacy_blob,
    }
    if (not force) and (not hover_draw_is_known):
        raise RuntimeError(
            "Post-call fill helper cave bytes are not recognized. "
            "Use --force only after manual verification."
        )
    patched[hover_draw_off: hover_draw_off + CAVE_HOVER_DRAW_HELPER_SIZE] = hover_draw_blob
    rows.append(
        {
            "name": "write_postcall_fill_helper_cave",
            "site_va": f"0x{CAVE_HOVER_DRAW_HELPER_VA:08X}",
            "site_file_offset": f"0x{hover_draw_off:08X}",
            "site_before": current_hover_draw.hex(),
            "site_after": hover_draw_blob.hex(),
            "bytes_written": CAVE_HOVER_DRAW_HELPER_SIZE,
        }
    )

    # Write null-guard cave stub.
    null_stub = _build_null_text_guard_stub(
        cave_va=CAVE_NULL_GUARD_VA,
        resume_va=0x0066F20A,
        fallback_text_va=string_addrs["empty"],
    )
    prev_null_stub_unknown = _build_null_text_guard_stub(
        cave_va=CAVE_NULL_GUARD_VA,
        resume_va=0x0066F20A,
        fallback_text_va=string_addrs["unknown"],
    )
    old_null_stub = _build_old_null_guard_stub(
        cave_va=CAVE_NULL_GUARD_VA,
        resume_va=0x0066F20A,
        null_target_va=0x0066F243,
    )

    null_off = _va_to_file_offset(input_bytes, CAVE_NULL_GUARD_VA)
    current_null = input_bytes[null_off: null_off + len(null_stub)]
    old_prefix_ok = current_null.startswith(old_null_stub) and all(
        b == 0 for b in current_null[len(old_null_stub):]
    )

    allowed_null = {b"\x00" * len(null_stub), null_stub, prev_null_stub_unknown}
    if (current_null not in allowed_null) and (not old_prefix_ok) and (not force):
        raise RuntimeError(
            "Null-guard cave bytes are not empty/known. "
            "Use --force only after manual verification."
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

    output_bytes = bytes(patched)

    target_out: Path
    if in_place:
        target_out = input_exe
    else:
        target_out = output_exe or DEFAULT_OUTPUT_EXE

    backup_path: Path | None = None
    if not dry_run:
        target_out.parent.mkdir(parents=True, exist_ok=True)
        if in_place and make_backup:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = target_out.with_name(f"{target_out.name}.bak_valderrama_upstream_{stamp}")
            shutil.copy2(target_out, backup_path)
        target_out.write_bytes(output_bytes)

    notes = [
        "MANAGPRE-only patch. No database edits.",
        f"Patch mode: {mode}.",
        "FUN_0066f1f0 keeps the proven null text-pointer guard (NULL -> empty string).",
        "FUN_00474870 pre-sprintf path now force-normalizes search-window team text by team_id.",
        "FUN_0049A410 found-path call at 0x0049A478 is restored to original bytes.",
        "FUN_0049A410 miss epilogue at 0x0049A486 now writes 'Unknown club' into destination buffer.",
        "FUN_00499D00 token branches are restored to original bytes (no global token hooks).",
        "Selected formatter callsites are restored to original import-thunk dispatch.",
        "FUN_0049A0E0 global call site at 0x0049A103 is restored to original target.",
        "FUN_0049A0E0 empty-template branch at 0x0049A111 is restored to original bytes.",
        "0x00468E52 is restored to original post-call gate bytes (no helper call).",
        "0x0043BD41 is restored to original FUN_0049A410 call target.",
        "0x0043BD46 is restored to original empty-gate bytes (crash-safe rollback of helper call).",
        "0x0041E74B..0x0041E750 now routes through staged local caves and substitutes 'Unknown club' only when hover text is empty.",
        "0x0043F24F now uses a source-empty lstrcpyA shim so bio/search copy paths fall back to 'Unknown club'.",
        "FUN_004960c0 formatter call at 0x00496358 is restored to original target.",
        "FUN_004960c0 draw call at 0x0049635D is restored to original bytes.",
        "Source-wrapper hooks at 0x004B8C3D/73 and 0x004B8F09/3F are restored to original calls.",
        "FUN_004b5c20 tail now rejects invalid candidate name pointers before fallback mapping.",
        "FUN_0064ce30 path now skips secondary virtual-call when chained object pointer is NULL.",
        "Legacy experimental upstream list trampolines are reverted to original bytes.",
    ]
    if mode == "instrument" and probe_id:
        notes.append(
            f"Instrumentation probe active: {probe_id}. Marker text={_probe_unknown_text(probe_id)!r}."
        )
        if runtime_probe is not None:
            notes.append(
                "Runtime owner probe active: exact callsite redirected to lookup-miss helper marker bridge."
            )

    return {
        "input_exe": str(input_exe),
        "output_exe": str(target_out),
        "backup_exe": str(backup_path) if backup_path else None,
        "dry_run": bool(dry_run),
        "mode": mode,
        "probe_id": probe_id,
        "runtime_probe": (
            {
                "site_va": f"0x{runtime_probe['site_va']:08X}",
                "expected_hex": bytes(runtime_probe["expected"]).hex(),
                "original_target_va": (
                    f"0x{int(runtime_probe['original_target_va']):08X}"
                    if runtime_probe.get("original_target_va") is not None
                    else None
                ),
                "pop_bytes": int(runtime_probe["pop_bytes"]),
            }
            if runtime_probe is not None
            else None
        ),
        "patch_count": len(rows),
        "patches": rows,
        "addresses": {
            "bundle_base": f"0x{CAVE_BUNDLE_BASE_VA:08X}",
            "bundle_size": CAVE_BUNDLE_SIZE,
            "search_text_helper": f"0x{search_text_helper_va:08X}",
            "formatter_arg3_guard_wrapper": f"0x{FORMATTTER_ARG3_GUARD_VA:08X}",
            "formatter_arg3_guard_call_thunk": f"0x{FORMATTTER_ARG3_CALL_THUNK_VA:08X}",
            "search_token_le_de_wrapper": f"0x{CAVE_LE_DE_WRAPPER_VA:08X}",
            "search_token_null_norm_helper": f"0x{CAVE_TOKEN_NULL_NORM_HELPER_VA:08X}",
            "search_token_null_push_helper": f"0x{CAVE_TOKEN_NULL_PUSH_HELPER_VA:08X}",
            "search_token_d1_ptr_stage1": f"0x{CAVE_D1_PTR_STAGE1_VA:08X}",
            "search_token_d1_ptr_stage2": f"0x{CAVE_D1_PTR_STAGE2_VA:08X}",
            "search_lookup_miss_helper": f"0x{CAVE_LOOKUP_MISS_HELPER_VA:08X}",
            "search_hover_post_lookup_helper": f"0x{CAVE_HOVER_DRAW_HELPER_VA:08X}",
            "search_hover_field_stage1": f"0x{CAVE_HOVER_FIELD_STAGE1_VA:08X}",
            "search_hover_field_stage2": f"0x{CAVE_HOVER_FIELD_STAGE2_VA:08X}",
            "search_hover_field_stage3": f"0x{CAVE_HOVER_FIELD_STAGE3_VA:08X}",
            "runtime_probe_helper": f"0x{CAVE_RUNTIME_PROBE_HELPER_VA:08X}",
            "hover_draw_wrapper": f"0x{CAVE_HOVER_DRAW_WRAPPER_VA:08X}",
            "lookup_helper": f"0x{lookup_helper_va:08X}",
            "null_guard": f"0x{CAVE_NULL_GUARD_VA:08X}",
            "secondary_chain_guard_site": f"0x{SECONDARY_CHAIN_GUARD_SITE_VA:08X}",
            "secondary_chain_guard_stage0": f"0x{SECONDARY_CHAIN_GUARD_STAGE0_VA:08X}",
            "secondary_chain_guard_stage1": f"0x{SECONDARY_CHAIN_GUARD_STAGE1_VA:08X}",
            "secondary_chain_guard_stage2": f"0x{SECONDARY_CHAIN_GUARD_STAGE2_VA:08X}",
            "empty": f"0x{string_addrs['empty']:08X}",
            "stars": f"0x{string_addrs['stars']:08X}",
            "free": f"0x{string_addrs['free']:08X}",
            "unknown": f"0x{string_addrs['unknown']:08X}",
        },
        "sha256": {
            "input": _sha256(input_bytes),
            "output": _sha256(output_bytes),
        },
        "notes": notes,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Patch MANAGPRE.EXE with Valderrama-safe null guard + source-club fallbacks"
    )
    parser.add_argument("--input-exe", default=str(DEFAULT_INPUT_EXE), help="Path to source MANAGPRE.EXE")
    parser.add_argument(
        "--output-exe",
        default=str(DEFAULT_OUTPUT_EXE),
        help="Output path (ignored with --in-place)",
    )
    parser.add_argument("--in-place", action="store_true", help="Patch input file in place")
    parser.add_argument("--dry-run", action="store_true", help="Validate and report only")
    parser.add_argument("--force", action="store_true", help="Ignore signature checks")
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Disable auto-backup when using --in-place",
    )
    parser.add_argument(
        "--mode",
        choices=PATCH_MODES,
        default="final",
        help="Patch behavior mode: stable baseline copy, instrument probe, or final patch.",
    )
    parser.add_argument(
        "--probe-id",
        help=(
            "Instrumentation probe target (required with --mode instrument). "
            f"Built-ins: {', '.join(PROBE_IDS)}. "
            "Runtime probes are allowed with ids starting runtime_."
        ),
    )
    parser.add_argument(
        "--runtime-probe-site-va",
        help="Runtime owner probe callsite virtual address (instrument mode, runtime_* probe id only).",
    )
    parser.add_argument(
        "--runtime-probe-expected-hex",
        help=(
            "Expected bytes at runtime probe callsite as hex (must be 5 bytes, CALL rel32 site). "
            "Example: e8d5120400"
        ),
    )
    parser.add_argument(
        "--runtime-probe-original-target-va",
        help="Optional original call target VA for idempotent alternates at runtime probe callsite.",
    )
    parser.add_argument(
        "--runtime-probe-pop-bytes",
        help="Runtime probe helper return pop size (0, 4, or 8). Default: 4.",
    )
    parser.add_argument(
        "--emit-ownership-manifest",
        action="store_true",
        help=(
            "Print JSON manifest for the 2-session runtime ownership pass and exit "
            "(no binary mutation)."
        ),
    )
    parser.add_argument(
        "--force-known-legacy",
        action="store_true",
        help="Allow migration from known-bad legacy signatures (unsafe; controlled use only).",
    )
    parser.add_argument("--json-output", help="Optional report output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_exe = Path(args.input_exe)
    output_exe = None if args.in_place else Path(args.output_exe)
    if args.emit_ownership_manifest:
        manifest = _build_ownership_manifest(
            script_path=Path(__file__).resolve(),
            input_exe=input_exe,
        )
        text = json.dumps(manifest, indent=2)
        if args.json_output:
            out = Path(args.json_output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text + "\n", encoding="utf-8")
        print(text)
        return 0

    runtime_probe_site_va = (
        _parse_va(str(args.runtime_probe_site_va), arg_name="--runtime-probe-site-va")
        if args.runtime_probe_site_va
        else None
    )
    runtime_probe_expected = (
        _parse_hex_bytes(str(args.runtime_probe_expected_hex), arg_name="--runtime-probe-expected-hex")
        if args.runtime_probe_expected_hex
        else None
    )
    runtime_probe_original_target_va = (
        _parse_va(str(args.runtime_probe_original_target_va), arg_name="--runtime-probe-original-target-va")
        if args.runtime_probe_original_target_va
        else None
    )
    runtime_probe_pop_bytes = (
        int(str(args.runtime_probe_pop_bytes), 0)
        if args.runtime_probe_pop_bytes is not None
        else None
    )

    report = apply_patch(
        input_exe=input_exe,
        output_exe=output_exe,
        in_place=bool(args.in_place),
        dry_run=bool(args.dry_run),
        force=bool(args.force),
        make_backup=not bool(args.no_backup),
        mode=str(args.mode),
        probe_id=str(args.probe_id) if args.probe_id else None,
        force_known_legacy=bool(args.force_known_legacy),
        runtime_probe_site_va=runtime_probe_site_va,
        runtime_probe_expected=runtime_probe_expected,
        runtime_probe_original_target_va=runtime_probe_original_target_va,
        runtime_probe_pop_bytes=runtime_probe_pop_bytes,
    )
    text = json.dumps(report, indent=2)
    if args.json_output:
        out = Path(args.json_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
