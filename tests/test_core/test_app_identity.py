"""Application identity and default output-directory tests."""

from __future__ import annotations

import plistlib
import struct
import zipfile
from pathlib import Path

from re_agent.core.app_identity import (
    default_pipeline_output_dir,
    detect_application_name,
)


def _utf8_string_pool(strings: list[str]) -> bytes:
    encoded: list[bytes] = []
    offsets: list[int] = []
    cursor = 0
    for value in strings:
        raw = value.encode("utf-8")
        assert len(value) < 128 and len(raw) < 128
        offsets.append(cursor)
        item = bytes((len(value), len(raw))) + raw + b"\x00"
        encoded.append(item)
        cursor += len(item)
    payload = b"".join(encoded)
    payload += b"\x00" * ((-len(payload)) % 4)
    strings_start = 28 + (len(strings) * 4)
    size = strings_start + len(payload)
    return (
        struct.pack(
            "<HHIIIIII",
            0x0001,
            28,
            size,
            len(strings),
            0,
            0x100,
            strings_start,
            0,
        )
        + b"".join(struct.pack("<I", offset) for offset in offsets)
        + payload
    )


def _start_element(name_index: int, attributes: list[tuple[int, int]]) -> bytes:
    attribute_data = b"".join(
        struct.pack(
            "<IIIHBBI",
            0xFFFFFFFF,
            attribute_name,
            value,
            8,
            0,
            0x03,
            value,
        )
        for attribute_name, value in attributes
    )
    size = 36 + len(attribute_data)
    return (
        struct.pack("<HHIII", 0x0102, 16, size, 1, 0xFFFFFFFF)
        + struct.pack(
            "<IIHHHHHH",
            0xFFFFFFFF,
            name_index,
            20,
            20,
            len(attributes),
            0,
            0,
            0,
        )
        + attribute_data
    )


def _binary_manifest() -> bytes:
    strings = [
        "manifest",
        "package",
        "com.example.runner",
        "application",
        "label",
        "Diamond Quest",
    ]
    body = _utf8_string_pool(strings) + _start_element(0, [(1, 2)]) + _start_element(3, [(4, 5)])
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def test_detect_android_application_name_from_text_manifest(tmp_path: Path) -> None:
    apk = tmp_path / "base.apk"
    manifest = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.diamondquest">
  <application android:label="Diamond Quest" />
</manifest>
"""
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)

    assert detect_application_name(apk) == "Diamond_Quest"


def test_detect_android_application_name_from_binary_manifest(tmp_path: Path) -> None:
    apk = tmp_path / "base.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", _binary_manifest())

    assert detect_application_name(apk) == "Diamond_Quest"


def test_detect_android_application_name_falls_back_to_package(tmp_path: Path) -> None:
    apk = tmp_path / "base.apk"
    manifest = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                          package="com.example.runner">
  <application android:label="@string/app_name" />
</manifest>"""
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)

    assert detect_application_name(apk) == "runner"


def test_detect_ios_application_name_from_info_plist(tmp_path: Path) -> None:
    ipa = tmp_path / "base.ipa"
    info = plistlib.dumps(
        {
            "CFBundleDisplayName": "Space Runner",
            "CFBundleIdentifier": "com.example.runner",
        }
    )
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/Runner.app/Info.plist", info)

    assert detect_application_name(ipa) == "Space_Runner"


def test_default_output_directory_uses_desktop_and_detected_name(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "GameAssembly.dll"
    binary.write_bytes(b"MZ")
    desktop = tmp_path / "Desktop"

    assert default_pipeline_output_dir(binary, desktop_root=desktop) == (desktop / "GameAssembly_output")
