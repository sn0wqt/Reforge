"""Tests for exact Mach-O file-offset to unslid-VM mapping."""
from __future__ import annotations

import struct

from re_agent.core.macho import (
    macho_vm_address_for_file_offset,
    parse_macho_segments,
)


def _thin_macho() -> bytes:
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        1,
        72,
        0,
        0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        72,
        b"__TEXT\0" + b"\0" * 9,
        0x100000000,
        0x400,
        0,
        0x400,
        7,
        5,
        0,
        0,
    )
    return (header + segment).ljust(0x400, b"\0")


def test_maps_thin_macho_segment_offset() -> None:
    data = _thin_macho()

    segments = parse_macho_segments(data)

    assert len(segments) == 1
    assert segments[0].name == "__TEXT"
    assert macho_vm_address_for_file_offset(data, 0x180) == 0x100000180
    assert macho_vm_address_for_file_offset(data, 0x500) is None


def test_maps_absolute_offset_inside_fat_slice() -> None:
    thin = _thin_macho()
    slice_offset = 0x100
    fat_header = struct.pack(">II", 0xCAFEBABE, 1)
    fat_arch = struct.pack(
        ">IIIII",
        0x0100000C,
        0,
        slice_offset,
        len(thin),
        2,
    )
    data = (fat_header + fat_arch).ljust(slice_offset, b"\0") + thin

    assert (
        macho_vm_address_for_file_offset(data, slice_offset + 0x180)
        == 0x100000180
    )


def test_rejects_truncated_or_invalid_macho() -> None:
    assert parse_macho_segments(b"\xcf\xfa\xed\xfe") == ()
    assert macho_vm_address_for_file_offset(b"not-macho", 0) is None
