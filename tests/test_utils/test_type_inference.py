"""Unit tests for vector and protocol type inference."""
from __future__ import annotations

from re_agent.utils.type_inference import generate_protocol_struct, infer_vector_types


def test_infer_vector3() -> None:
    fields = [
        {"name": "x", "type": "float", "offset": 0x0},
        {"name": "y", "type": "float", "offset": 0x4},
        {"name": "z", "type": "float", "offset": 0x8},
        {"name": "health", "type": "float", "offset": 0xC},
    ]
    inferred = infer_vector_types(fields)
    assert len(inferred) == 2
    assert inferred[0]["type"] == "Vector3"
    assert inferred[0]["offset"] == 0x0
    assert inferred[1]["name"] == "health"


def test_infer_quaternion() -> None:
    fields = [
        {"name": "qx", "type": "float", "offset": 0x10},
        {"name": "qy", "type": "float", "offset": 0x14},
        {"name": "qz", "type": "float", "offset": 0x18},
        {"name": "qw", "type": "float", "offset": 0x1C},
    ]
    inferred = infer_vector_types(fields)
    assert len(inferred) == 1
    assert inferred[0]["type"] == "Quaternion"
    assert inferred[0]["offset"] == 0x10


def test_generate_protocol_struct() -> None:
    fields = [
        {"name": "packet_id", "type": "uint16_t", "offset": 0x0},
        {"name": "pos_x", "type": "float", "offset": 0x2},
        {"name": "pos_y", "type": "float", "offset": 0x6},
        {"name": "pos_z", "type": "float", "offset": 0xA},
    ]
    header = generate_protocol_struct("PositionPacket", fields)
    assert "#pragma pack(push, 1)" in header
    assert "struct PositionPacket {" in header
    assert "ReAgentVector3 pos_x; // verified offset: 0x2" in header
    assert "static_assert(offsetof(PositionPacket, pos_x) == 0x2);" in header


def test_does_not_infer_vector_from_arbitrary_adjacent_floats() -> None:
    fields = [
        {"name": "power", "type": "float", "offset": 0x0},
        {"name": "weight", "type": "float", "offset": 0x4},
        {"name": "cooldown", "type": "float", "offset": 0x8},
        {"name": "window", "type": "float", "offset": 0xC},
    ]

    inferred = infer_vector_types(fields)

    assert [field["name"] for field in inferred] == [
        "power",
        "weight",
        "cooldown",
        "window",
    ]
