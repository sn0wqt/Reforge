"""Unit tests for byte signature generation and pattern scanning."""
from __future__ import annotations

import pytest

from re_agent.parity.sigscan import generate_signature, match_signature, parse_signature


def test_parse_signature() -> None:
    pattern = parse_signature("55 48 89 ?? E5")
    assert pattern == [0x55, 0x48, 0x89, None, 0xE5]


@pytest.mark.parametrize("signature", ["?A", "GG", "100"])
def test_parse_signature_rejects_invalid_tokens(signature: str) -> None:
    with pytest.raises(ValueError, match="Invalid signature token"):
        parse_signature(signature)


def test_match_signature_exact() -> None:
    data = bytes([0x90, 0x55, 0x48, 0x89, 0xE5, 0xC3])
    matches = match_signature(data, "55 48 89 E5")
    assert matches == [1]


def test_match_signature_wildcard() -> None:
    data = bytes([0x55, 0x48, 0x89, 0xAA, 0xE5, 0x90, 0x55, 0x48, 0x89, 0xBB, 0xE5])
    matches = match_signature(data, "55 48 89 ?? E5")
    assert matches == [0, 6]


def test_match_signature_no_match() -> None:
    data = bytes([0x00, 0x01, 0x02, 0x03])
    matches = match_signature(data, "AA BB CC")
    assert matches == []


def test_generate_signature() -> None:
    instructions = [
        {"bytes": "55 48 89 e5", "is_relocated": False},
        {"bytes": "e9 12 34 56 78", "is_relocated": True},
    ]
    sig = generate_signature(instructions, mask_relocations=True)
    assert sig == "55 48 89 E5 ?? ?? ?? ?? ??"
