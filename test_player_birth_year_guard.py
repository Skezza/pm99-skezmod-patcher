import struct
import pytest
from player_birth_year_guard import BEFORE, AFTER, patch_native_birth_year_guard


def fixture():
    blob = bytearray(512)
    blob[:2] = b'MZ'
    struct.pack_into('<I', blob, 0x3c, 0x80)
    blob[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', blob, 0x86, 1)
    struct.pack_into('<H', blob, 0x94, 0xe0)
    struct.pack_into('<I', blob, 0x98+28, 0x400000)
    section = 0x98+0xe0
    struct.pack_into('<IIII', blob, section+8, 16, 0xafedf, 16, 496)
    blob[496:512] = BEFORE
    return bytes(blob)


def test_only_birth_year_upper_bound_changes_and_replay_is_identical():
    before = fixture()
    after, receipt = patch_native_birth_year_guard(before)
    assert before[496:] == BEFORE
    assert after[496:] == AFTER
    assert receipt['changed_offsets'] == [506, 507]
    assert patch_native_birth_year_guard(after)[0] == after
    assert patch_native_birth_year_guard(after)[1]['already_applied'] is True


def test_unknown_instructions_are_never_patched():
    source = bytearray(fixture())
    source[503] = 0
    with pytest.raises(ValueError, match='unsupported'):
        patch_native_birth_year_guard(bytes(source))
