"""Unit tests for vtable struct header generation."""
from __future__ import annotations

from re_agent.utils.vtable import generate_vtable_header


def test_generate_vtable_header() -> None:
    vtable_entries = [
        {"name": "Update", "return_type": "void", "args": "Player* self", "offset": 0x0},
        {"name": "GetHealth", "return_type": "float", "args": "Player* self", "offset": 0x8},
    ]
    field_offsets = [
        {"name": "health", "type": "float", "offset": 0x18},
        {"name": "ammo", "type": "int32_t", "offset": 0x1C},
    ]

    header = generate_vtable_header("Player", vtable_entries, field_offsets)
    assert "not a verified C++ object layout or ABI" in header
    assert "struct PlayerVTableOffsets {" in header
    assert "k_Update = 0x0" in header
    assert "k_GetHealth = 0x8" in header
    assert "struct PlayerFieldOffsets {" in header
    assert "k_health = 0x18" in header
    assert "k_ammo = 0x1C" in header
