"""Tests for explicit, fail-closed Android Frida Gadget embedding."""

from __future__ import annotations

import hashlib
import json
import lzma
import struct
import zipfile
from pathlib import Path
from xml.etree import ElementTree

import pytest

from re_agent.packaging.frida_gadget import (
    ANDROID_NS,
    GADGET_CONFIG_NAME,
    GADGET_LIBRARY_NAME,
    GADGET_LOADER_CLASS,
    GADGET_LOADER_DESCRIPTOR,
    GadgetPackagingError,
    embed_frida_gadget,
    verify_gadget_archive,
    write_gadget_deployment_notes,
)


def _write_elf(path: Path, machine: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<H", header, 16, 3)
    struct.pack_into("<H", header, 18, machine)
    payload = bytes(header) + b"GADGET-PAYLOAD"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return payload


def _decoded_apk(tmp_path: Path, *, abis: tuple[str, ...] = ("arm64-v8a",)) -> Path:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.game"><application android:extractNativeLibs="false" />'
        "</manifest>",
        encoding="utf-8",
    )
    for abi in abis:
        (decoded / "lib" / abi).mkdir(parents=True)
    return decoded


def _archive_decoded(decoded: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w") as archive:
        for path in sorted(decoded.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(decoded).as_posix())
        archive.writestr("classes.dex", b"dex\n035\x00" + GADGET_LOADER_DESCRIPTOR)


def test_embed_gadget_patches_manifest_loader_config_and_hashes(tmp_path: Path) -> None:
    decoded = _decoded_apk(tmp_path)
    gadget = tmp_path / "frida-gadget.so"
    payload = _write_elf(gadget, 183)
    source_hash = hashlib.sha256(payload).hexdigest()

    result = embed_frida_gadget(
        decoded,
        gadget,
        expected_sha256=source_hash,
        on_load="wait",
        port=28042,
        declared_version="17.15.2",
    )

    assert result.abis == ("arm64-v8a",)
    assert result.package_name == "com.example.game"
    assert result.extract_native_libs_changed is True
    assert (decoded / "lib" / "arm64-v8a" / GADGET_LIBRARY_NAME).read_bytes() == payload
    config = json.loads((decoded / "lib" / "arm64-v8a" / GADGET_CONFIG_NAME).read_text())
    assert config["interaction"]["on_load"] == "wait"
    assert config["interaction"]["port"] == 28042
    assert "loadLibrary" in (decoded / "smali" / "re" / "agent" / "GadgetInitProvider.smali").read_text()

    manifest = ElementTree.parse(decoded / "AndroidManifest.xml").getroot()
    application = manifest.find("application")
    assert application is not None
    assert application.get(f"{{{ANDROID_NS}}}extractNativeLibs") == "true"
    provider = application.find("provider")
    assert provider is not None
    assert provider.get(f"{{{ANDROID_NS}}}name") == GADGET_LOADER_CLASS
    assert provider.get(f"{{{ANDROID_NS}}}exported") == "false"

    rebuilt = tmp_path / "rebuilt.apk"
    _archive_decoded(decoded, rebuilt)
    verify_gadget_archive(rebuilt, result)


def test_embed_gadget_accepts_xz_payload(tmp_path: Path) -> None:
    decoded = _decoded_apk(tmp_path)
    raw = tmp_path / "raw.so"
    payload = _write_elf(raw, 183)
    compressed = tmp_path / "frida-gadget-arm64.so.xz"
    compressed.write_bytes(lzma.compress(payload))

    result = embed_frida_gadget(decoded, compressed)

    assert result.abis == ("arm64-v8a",)
    assert (decoded / "lib" / "arm64-v8a" / GADGET_LIBRARY_NAME).read_bytes() == payload


def test_multi_abi_apk_requires_complete_gadget_set(tmp_path: Path) -> None:
    decoded = _decoded_apk(tmp_path, abis=("arm64-v8a", "x86_64"))
    gadget = tmp_path / "frida-gadget.so"
    _write_elf(gadget, 183)

    with pytest.raises(GadgetPackagingError, match="does not cover every APK ABI"):
        embed_frida_gadget(decoded, gadget)


def test_gadget_directory_matches_each_abi(tmp_path: Path) -> None:
    decoded = _decoded_apk(tmp_path, abis=("arm64-v8a", "x86_64"))
    gadget_dir = tmp_path / "gadgets"
    _write_elf(gadget_dir / "arm64-v8a" / "frida-gadget.so", 183)
    _write_elf(gadget_dir / "x86_64" / "frida-gadget.so", 62)

    result = embed_frida_gadget(decoded, gadget_dir)

    assert result.abis == ("arm64-v8a", "x86_64")


def test_gadget_checksum_and_split_apk_fail_closed(tmp_path: Path) -> None:
    decoded = _decoded_apk(tmp_path)
    gadget = tmp_path / "frida-gadget.so"
    _write_elf(gadget, 183)

    with pytest.raises(GadgetPackagingError, match="SHA-256 mismatch"):
        embed_frida_gadget(decoded, gadget, expected_sha256="0" * 64)

    (decoded / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.game" split="config.arm64_v8a"><application /></manifest>',
        encoding="utf-8",
    )
    with pytest.raises(GadgetPackagingError, match="split APK"):
        embed_frida_gadget(decoded, gadget)


def test_split_required_application_fails_closed(tmp_path: Path) -> None:
    decoded = _decoded_apk(tmp_path)
    gadget = tmp_path / "frida-gadget.so"
    _write_elf(gadget, 183)
    (decoded / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.game"><application android:isSplitRequired="true" />'
        "</manifest>",
        encoding="utf-8",
    )

    with pytest.raises(GadgetPackagingError, match="split-required APK"):
        embed_frida_gadget(decoded, gadget)


def test_archive_verification_detects_missing_loader(tmp_path: Path) -> None:
    decoded = _decoded_apk(tmp_path)
    gadget = tmp_path / "frida-gadget.so"
    _write_elf(gadget, 183)
    result = embed_frida_gadget(decoded, gadget)
    rebuilt = tmp_path / "rebuilt.apk"
    with zipfile.ZipFile(rebuilt, "w") as archive:
        for member, _expected_hash in result.expected_member_hashes:
            archive.write(decoded / Path(member), member)
        archive.writestr("classes.dex", b"dex\n035\x00")

    with pytest.raises(GadgetPackagingError, match="loader class"):
        verify_gadget_archive(rebuilt, result)


def test_deployment_notes_are_truthful(tmp_path: Path) -> None:
    decoded = _decoded_apk(tmp_path)
    gadget = tmp_path / "frida-gadget.so"
    _write_elf(gadget, 183)
    result = embed_frida_gadget(decoded, gadget, port=28042)

    notes = write_gadget_deployment_notes(tmp_path, result).read_text()

    assert "forward tcp:28042 tcp:28042" in notes
    assert "new signing certificate" in notes
    assert "Play Integrity" in notes
