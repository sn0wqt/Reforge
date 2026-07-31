"""Tests for bounded DEX method and prototype recovery."""

from __future__ import annotations

import struct

from re_agent.core.dex_parser import parse_dex_file


def _minimal_dex_with_overload() -> bytes:
    """Build the smallest table-only fixture needed by the local parser."""
    strings = [
        b"Lcom/game/Wallet;",
        b"I",
        b"J",
        b"getCoins",
        b"IIJ",
    ]
    string_ids_off = 112
    type_ids_off = string_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + 3 * 4
    method_ids_off = proto_ids_off + 12
    parameters_off = method_ids_off + 8
    class_defs_off = parameters_off + 8
    class_data_off = class_defs_off + 32
    data = bytearray(class_data_off)
    # static fields=0, instance fields=0, direct methods=1, virtual=0;
    # method_idx_diff=0, public|static access, non-zero code offset.
    data.extend(b"\x00\x00\x01\x00\x00\x09\x01")

    string_offsets: list[int] = []
    for value in strings:
        string_offsets.append(len(data))
        data.extend(bytes([len(value)]))
        data.extend(value)
        data.append(0)

    data[0:8] = b"dex\n035\x00"
    struct.pack_into("<III", data, 32, len(data), 112, 0x12345678)
    struct.pack_into("<II", data, 56, len(strings), string_ids_off)
    struct.pack_into("<II", data, 64, 3, type_ids_off)
    struct.pack_into("<II", data, 72, 1, proto_ids_off)
    struct.pack_into("<II", data, 80, 0, 0)
    struct.pack_into("<II", data, 88, 1, method_ids_off)
    struct.pack_into("<II", data, 96, 1, class_defs_off)

    for index, string_offset in enumerate(string_offsets):
        struct.pack_into("<I", data, string_ids_off + index * 4, string_offset)
    for index, descriptor_string_index in enumerate((0, 1, 2)):
        struct.pack_into(
            "<I",
            data,
            type_ids_off + index * 4,
            descriptor_string_index,
        )

    # return int, parameters int and long
    struct.pack_into("<III", data, proto_ids_off, 4, 1, parameters_off)
    struct.pack_into("<HHI", data, method_ids_off, 0, 0, 3)
    struct.pack_into("<IHH", data, parameters_off, 2, 1, 2)
    struct.pack_into(
        "<IIIIIIII",
        data,
        class_defs_off,
        0,
        1,
        0xFFFFFFFF,
        0,
        0xFFFFFFFF,
        0,
        class_data_off,
        0,
    )
    return bytes(data)


def test_parse_dex_recovers_exact_method_prototype() -> None:
    methods = parse_dex_file(_minimal_dex_with_overload())

    assert methods == [
        {
            "class_name": "com.game.Wallet",
            "method_name": "getCoins",
            "class_descriptor": "Lcom/game/Wallet;",
            "raw_descriptor": "(IJ)I",
            "descriptor": "(IJ)I",
            "parameter_types": ("int", "long"),
            "return_type": "int",
            "is_declared": True,
            "is_executable": True,
            "is_static": True,
            "is_native": False,
            "is_abstract": False,
            "is_constructor": False,
            "access_flags": 9,
            "code_off": 1,
        }
    ]
