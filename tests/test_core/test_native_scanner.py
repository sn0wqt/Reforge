"""Tests for bounded review-only native evidence discovery."""
from __future__ import annotations

import zipfile
from pathlib import Path

from re_agent.core.native_scanner import scan_native_evidence


def test_scans_direct_native_symbols_as_review_only(tmp_path: Path) -> None:
    binary = tmp_path / "game.exe"
    binary.write_bytes(
        b"\x00noise\x00PlayerWallet::GetCoins\x00unrelated\x00"
    )

    targets = scan_native_evidence(binary, ["coins", "wallet"])

    assert len(targets) == 1
    assert targets[0].confidence == 35
    assert targets[0].signature_verified is False
    assert targets[0].address_verified is False
    assert targets[0].implementation_ready is False
    assert "No code xref" in targets[0].reason


def test_scans_native_archive_members_only(tmp_path: Path) -> None:
    package = tmp_path / "app.ipa"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr(
            "Payload/Game.app/Game",
            b"\x00_$s4Game12DiamondStoreC\x00",
        )
        archive.writestr(
            "Payload/Game.app/config.json",
            b'{"diamonds": "not native evidence"}',
        )

    targets = scan_native_evidence(package, ["diamond"])

    assert len(targets) == 1
    assert targets[0].class_name == "Game"


def test_native_scan_respects_empty_terms_and_missing_paths(tmp_path: Path) -> None:
    binary = tmp_path / "game.so"
    binary.write_bytes(b"WalletCoins")

    assert scan_native_evidence(binary, []) == ()
    assert scan_native_evidence(tmp_path / "missing.so", ["coins"]) == ()
