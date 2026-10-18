"""Preserve valid modern birth dates instead of PM99's random-age fallback."""
from __future__ import annotations

import hashlib
import struct

GUARD_VA = 0x004AFEDF
BEFORE = bytes.fromhex('81 fd 6c 07 00 00 76 08 81 fd d0 07 00 00 72 1f')
AFTER = bytes.fromhex('81 fd 6c 07 00 00 76 08 81 fd 35 08 00 00 72 1f')
# 1900 < birth year < 2101, replacing 1900 < birth year < 2000.


def offset_for_va(source: bytes, va: int) -> int:
    if source[:2] != b'MZ':
        raise ValueError('not a PE executable')
    pe = struct.unpack_from('<I', source, 0x3c)[0]
    if source[pe:pe+4] != b'PE\0\0':
        raise ValueError('invalid PE signature')
    count = struct.unpack_from('<H', source, pe+6)[0]
    optional = struct.unpack_from('<H', source, pe+20)[0]
    image_base = struct.unpack_from('<I', source, pe+24+28)[0]
    rva = va - image_base
    for i in range(count):
        section = pe+24+optional+i*40
        _, address, size, raw = struct.unpack_from('<IIII', source, section+8)
        if address <= rva < address+size:
            offset = raw+rva-address
            if offset+16 > len(source):
                raise ValueError('birth-year guard outside file')
            return offset
    raise ValueError('birth-year guard VA is not mapped')


def patch_native_birth_year_guard(source: bytes) -> tuple[bytes, dict]:
    """Change only the proven upper-bound immediate; no calendar rebase."""
    offset = offset_for_va(source, GUARD_VA)
    observed = source[offset:offset+len(BEFORE)]
    if observed not in (BEFORE, AFTER):
        raise ValueError('unsupported player birth-year guard instructions')
    result = bytearray(source)
    result[offset:offset+len(AFTER)] = AFTER
    patched = bytes(result)
    changed = [i for i, (a, b) in enumerate(zip(source, patched)) if a != b]
    if len(patched) != len(source) or not set(changed) <= {offset+10, offset+11}:
        raise ValueError('birth-year patch changed bytes outside immediate')
    return patched, {'schema_version': 'pm99-native-birth-year-guard-v1',
        'instruction_va': f'0x{GUARD_VA:08X}', 'file_offset': offset,
        'before_sha256': hashlib.sha256(source).hexdigest(), 'after_sha256': hashlib.sha256(patched).hexdigest(),
        'changed_offsets': changed, 'already_applied': observed == AFTER,
        'before_upper_exclusive': 2000 if observed == BEFORE else 2101, 'after_upper_exclusive': 2101,
        'scope': 'Retain valid player DOB; missing/invalid dates still use the original fallback',
        'calendar_rebased': False}
