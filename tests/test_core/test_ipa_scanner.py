"""Unit tests for IPA & Swift String Scanner core modules."""
from __future__ import annotations

import plistlib
from pathlib import Path

from re_agent.core.ipa_scanner import IPAScanner
from re_agent.core.swift_decoder import decode_swift_small_string, extract_swift_strings_from_bytes


def test_decode_swift_small_string() -> None:
    # Pack ASCII "Hello" into a 64-bit int
    packed = ord("H") | (ord("e") << 8) | (ord("l") << 16) | (ord("l") << 24) | (ord("o") << 32)
    decoded = decode_swift_small_string(packed)
    assert decoded == "Hello"


def test_extract_swift_strings_from_bytes() -> None:
    raw_data = b"Some random garbage bytes\x00\x00PlayerPrefs\x00\x00More garbage"
    results = extract_swift_strings_from_bytes(raw_data, base_address=0x100000000)
    strings = [r["string"] for r in results]
    assert "PlayerPrefs" in strings


def test_ipa_scanner_plist_and_binary(tmp_path: Path) -> None:
    ipa_dir = tmp_path / "Payload" / "TestApp.app"
    ipa_dir.mkdir(parents=True)

    # Create dummy Info.plist
    plist_path = ipa_dir / "Info.plist"
    with open(plist_path, "wb") as f:
        plistlib.dump({"CFBundleDisplayName": "SubwayGame"}, f)

    # Create dummy binary
    bin_path = ipa_dir / "TestApp"
    bin_path.write_bytes(b"\xfe\xed\xfa\xcf" + b"A" * 16 + b"WalletModel\x00")

    scanner = IPAScanner(tmp_path)
    results = scanner.scan("SubwayGame")
    assert len(results) >= 1
    assert "SubwayGame" in results[0]["snippet"]

    bin_results = scanner.scan("WalletModel")
    assert len(bin_results) >= 1
    assert "WalletModel" in bin_results[0]["match"]
