"""Unit tests for Apple Info.plist and IPA scanner."""

from __future__ import annotations

import io
import plistlib
import zipfile
from pathlib import Path

from reforge.core.scanners.plist_scanner import PlistScanner


def _build_synthetic_plist(
    bundle_id: str = "com.reforge.app",
    bundle_name: str = "ReforgeApp",
    version: str = "1.2.3",
    executable: str = "ReforgeApp",
    min_os: str = "15.0",
    url_schemes: list[str] | None = None,
    permissions: dict[str, str] | None = None,
    binary_format: bool = False,
) -> bytes:
    payload: dict[str, object] = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleName": bundle_name,
        "CFBundleDisplayName": bundle_name,
        "CFBundleVersion": version,
        "CFBundleShortVersionString": version,
        "CFBundleExecutable": executable,
        "MinimumOSVersion": min_os,
    }
    if url_schemes:
        payload["CFBundleURLTypes"] = [{"CFBundleURLSchemes": url_schemes}]
    if permissions:
        for k, v in permissions.items():
            payload[f"NS{k}UsageDescription"] = v

    fmt = plistlib.FMT_BINARY if binary_format else plistlib.FMT_XML
    return plistlib.dumps(payload, fmt=fmt)


def _build_synthetic_ipa(
    plist_bytes: bytes,
    entitlements: dict[str, object] | None = None,
    team_name: str = "Reforge Team",
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/ReforgeApp.app/Info.plist", plist_bytes)
        if entitlements:
            prov_dict: dict[str, object] = {
                "Entitlements": entitlements,
                "TeamName": team_name,
            }
            prov_xml = plistlib.dumps(prov_dict, fmt=plistlib.FMT_XML)
            # Wrap into mock CMS envelope
            cms_envelope = b"MOCK_PKCS7_PREFIX" + prov_xml + b"MOCK_PKCS7_SUFFIX"
            zf.writestr("Payload/ReforgeApp.app/embedded.mobileprovision", cms_envelope)
    return buf.getvalue()


def test_scan_xml_plist() -> None:
    data = _build_synthetic_plist(
        bundle_id="com.example.testapp",
        bundle_name="TestApp",
        version="2.0.1",
        url_schemes=["testapp", "oauth-callback"],
        permissions={"Camera": "Scan barcodes", "PhotoLibrary": "Select avatars"},
        binary_format=False,
    )
    info = PlistScanner.scan_plist_bytes(data)
    assert info is not None
    assert info.bundle_id == "com.example.testapp"
    assert info.bundle_name == "TestApp"
    assert info.version == "2.0.1"
    assert "testapp" in info.url_schemes
    assert "Camera" in info.permissions
    assert info.permissions["Camera"] == "Scan barcodes"
    assert any("com.example.testapp" in n for n in info.notes)


def test_scan_binary_plist() -> None:
    data = _build_synthetic_plist(
        bundle_id="com.example.binaryplist",
        bundle_name="BinaryApp",
        binary_format=True,
    )
    info = PlistScanner.scan_plist_bytes(data)
    assert info is not None
    assert info.bundle_id == "com.example.binaryplist"
    assert info.bundle_name == "BinaryApp"


def test_scan_ipa_file(tmp_path: Path) -> None:
    plist_bytes = _build_synthetic_plist(
        bundle_id="com.reforge.signedipa",
        bundle_name="SignedIPA",
        version="3.0.0",
    )
    ipa_bytes = _build_synthetic_ipa(
        plist_bytes,
        entitlements={
            "application-identifier": "TEAM123.com.reforge.signedipa",
            "get-task-allow": True,
            "keychain-access-groups": ["TEAM123.keychain"],
        },
        team_name="Apple Developer Reforge",
    )
    ipa_file = tmp_path / "app.ipa"
    ipa_file.write_bytes(ipa_bytes)

    info = PlistScanner.scan_ipa_file(ipa_file)
    assert info is not None
    assert info.bundle_id == "com.reforge.signedipa"
    assert info.is_debuggable is True
    assert info.team_name == "Apple Developer Reforge"
    assert any("Debuggable: YES" in n for n in info.notes)
    assert any("TEAM123.com.reforge.signedipa" in n for n in info.notes)

    # Missing or corrupt
    assert PlistScanner.scan_ipa_file(tmp_path / "missing.ipa") is None
    bad_ipa = tmp_path / "corrupt.ipa"
    bad_ipa.write_bytes(b"not a zip")
    assert PlistScanner.scan_ipa_file(bad_ipa) is None
