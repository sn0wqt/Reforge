"""Unit tests for static binary and runtime scanners."""

from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path

from reforge.core.engine_detector import detect_architecture_from_path
from reforge.core.scanners.dotnet_scanner import DotNetScanner
from reforge.core.scanners.electron_scanner import ElectronScanner
from reforge.core.scanners.flutter_scanner import FlutterScanner
from reforge.core.scanners.go_scanner import (
    GO_BUILDINFO_MAGIC,
    GO_MODULE_HEADER_MAGIC,
    GO_MODULE_TAIL_MAGIC,
    GoScanner,
)
from reforge.core.scanners.rust_scanner import RustScanner


def test_go_scanner_probe_inline(tmp_path: Path) -> None:
    # Build synthetic Go 1.18+ buildinfo payload
    # 14 bytes magic + 1 byte ptrSize (8) + 1 byte flags (2 = inline) + 16 bytes reserved = 32 bytes
    header = bytearray(GO_BUILDINFO_MAGIC + b"\x08\x02" + (b"\x00" * 16))
    assert len(header) == 32

    # Version: "go1.22.4"
    ver_str = b"go1.22.4"
    ver_len = len(ver_str)
    # Module text: path\tgithub.com/example/tool\nmod\tgithub.com/example/tool\t(devel)\t\n
    mod_text = (
        b"path\tgithub.com/example/tool\n"
        b"mod\tgithub.com/example/tool\t(devel)\t\n"
        b"dep\tgolang.org/x/sync\tv0.7.0\thash123\n"
        b"build\tGOARCH=amd64\n"
        b"build\tGOOS=linux\n"
        b"build\tvcs.revision=abcd1234ef\n"
    )
    mod_payload = GO_MODULE_HEADER_MAGIC + mod_text + b"\n" + GO_MODULE_TAIL_MAGIC
    mod_len = len(mod_payload)

    # Encode varints
    payload = bytearray()
    payload.append(ver_len)
    payload.extend(ver_str)
    # mod_len ULEB128
    m = mod_len
    while True:
        b = m & 0x7F
        m >>= 7
        if m != 0:
            payload.append(b | 0x80)
        else:
            payload.append(b)
            break
    payload.extend(mod_payload)

    # Combine with 16-byte alignment padding (64 bytes prefix preserves alignment)
    binary_data = b"\x7fELF" + (b"\x90" * 60) + header + payload + (b"\x90" * 32)
    info = GoScanner.probe_bytes(binary_data)
    assert info is not None
    assert info.version == "go1.22.4"
    assert info.main_module == "github.com/example/tool"
    assert info.architecture == "amd64"
    assert info.os == "linux"
    assert info.vcs_revision == "abcd1234ef"
    assert len(info.dependencies) == 1
    assert info.dependencies[0][0] == "golang.org/x/sync"

    test_file = tmp_path / "app.elf"
    test_file.write_bytes(binary_data)
    detection = detect_architecture_from_path(test_file)
    assert detection.pathway == "native-go"
    assert detection.engine_type == "go"
    assert "github.com/example/tool" in " ".join(detection.detection_notes)


def test_rust_scanner_probe(tmp_path: Path) -> None:
    # Build synthetic cargo-auditable document
    audit_doc = {
        "format": 1,
        "packages": [
            {
                "name": "my-tool",
                "version": "0.4.0",
                "root": True,
                "kind": "runtime",
            },
            {
                "name": "serde",
                "version": "1.0.197",
                "root": False,
                "kind": "runtime",
                "source": "registry+https://crates.io",
            },
        ],
    }
    raw_json = json.dumps(audit_doc).encode("utf-8")
    compressed = zlib.compress(raw_json)

    # Section tag + compressed zlib payload
    section_data = b".dep-v0\x00\x00\x00\x00" + compressed
    rustc_marker = b"/rustc/07dca489ac12be337357e9c8329e19216f5ed6f7/library/std/src/lib.rs"

    binary_data = b"\x7fELF" + (b"\x00" * 128) + section_data + (b"\x00" * 64) + rustc_marker
    info = RustScanner.probe_bytes(binary_data)
    assert info is not None
    assert len(info.crates) == 2
    assert info.root_package == "my-tool 0.4.0"
    assert info.rustc_commit == "07dca489ac12be337357e9c8329e19216f5ed6f7"

    test_file = tmp_path / "tool.elf"
    test_file.write_bytes(binary_data)
    detection = detect_architecture_from_path(test_file)
    assert detection.pathway == "native-rust"
    assert detection.engine_type == "rust"
    assert "rust crates: 2" in " ".join(detection.detection_notes)


def test_dotnet_scanner_probe(tmp_path: Path) -> None:
    # Construct minimal valid PE header with CLI Directory #14
    data = bytearray(2048)
    data[0:2] = b"MZ"
    # e_lfanew at 0x3C -> 0x80
    struct.pack_into("<I", data, 0x3C, 0x80)

    # PE signature at 0x80
    e_lfanew = 0x80
    data[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    # Number of sections: 1
    struct.pack_into("<H", data, e_lfanew + 6, 1)
    # Size of optional header: 224
    struct.pack_into("<H", data, e_lfanew + 20, 224)
    # Optional header magic: 0x10B (PE32)
    struct.pack_into("<H", data, e_lfanew + 24, 0x10B)

    # Data Directory 14 (CLI / COM descriptor) at e_lfanew + 24 + 96 + (14 * 8) = e_lfanew + 232
    cli_dir_offset = e_lfanew + 232
    cli_rva = 0x2000
    cli_size = 72
    struct.pack_into("<II", data, cli_dir_offset, cli_rva, cli_size)

    # Section table at e_lfanew + 24 + 224 = 0x80 + 248 = 0x178
    sect_offset = e_lfanew + 248
    # Section header: name ".text", virt_size=0x1000, virt_addr=0x2000, raw_size=0x1000, raw_offset=0x400
    data[sect_offset : sect_offset + 5] = b".text"
    struct.pack_into("<IIII", data, sect_offset + 8, 0x1000, 0x2000, 0x1000, 0x400)

    # CLI Header at file offset 0x400
    # cb=72, major=2, minor=5, meta_rva=0x2100, meta_size=256, flags=1 (ILONLY)
    struct.pack_into("<IHHIII", data, 0x400, 72, 2, 5, 0x2100, 256, 1)

    # Metadata Root (BSJB) at RVA 0x2100 -> file offset 0x500
    meta_offset = 0x500
    data[meta_offset : meta_offset + 4] = b"BSJB"
    version_str = b"v4.0.30319\x00"
    struct.pack_into("<I", data, meta_offset + 12, len(version_str))
    data[meta_offset + 16 : meta_offset + 16 + len(version_str)] = version_str

    # Embed #Strings stream header and assembly tokens
    strings_stream_offset = meta_offset + 40
    data[strings_stream_offset : strings_stream_offset + 12] = b"#Strings\x00\x00\x00\x00"
    struct.pack_into("<II", data, strings_stream_offset - 8, 0x80, 0x100)
    # Strings stream payload at meta_offset + 0x80 = 0x580
    data[0x580:0x5B0] = b"\x00mscorlib\x00System\x00UnityEngine.CoreModule\x00"

    info = DotNetScanner.probe_bytes(bytes(data))
    assert info is not None
    assert info.clr_version == "v4.0.30319"
    assert info.is_il_only is True
    assert info.is_unity is True

    test_pe = tmp_path / "game.exe"
    test_pe.write_bytes(data)
    detection = detect_architecture_from_path(test_pe)
    assert detection.pathway == "unity-il2cpp-windows"
    assert detection.engine_type == "unity-dotnet"


def test_flutter_scanner_probe(tmp_path: Path) -> None:
    # 1. libapp.so payload with Dart snapshot magic and 32-hex hash
    snapshot_hash = b"a1b2c3d4e5f60718293a4b5c6d7e8f90"
    libapp_data = (
        b"\x7fELF"
        + (b"\x00" * 32)
        + b"\xf5\xf5\xdc\xdc"  # Magic
        + (b"\x00" * 16)  # Header padding to reach offset + 20
        + snapshot_hash
        + b"\x00\x00package:shared_preferences/sp.dart\x00package:dio/dio.dart\x00"
    )
    info = FlutterScanner.probe_bytes(libapp_data)
    assert info is not None
    assert info.snapshot_hash == "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    assert "shared_preferences" in info.packages
    assert "dio" in info.packages

    libapp_file = tmp_path / "libapp.so"
    libapp_file.write_bytes(libapp_data)
    detection = detect_architecture_from_path(libapp_file)
    assert detection.engine_type == "flutter"
    assert any("dart snapshot:" in note for note in detection.detection_notes)


def test_electron_scanner_probe(tmp_path: Path) -> None:
    # Sentinel + 1-byte version (1) + fuse1 (0: runAsNode disabled) + fuse2 (1) + fuse3 (1: onlyLoadFromAsar)
    fuse_payload = b"dL7h2TvoWupn74WftndoSmAE33vdZup8\x010110000"
    binary_data = b"MZ" + (b"\x90" * 128) + fuse_payload + (b"\x90" * 64)

    info = ElectronScanner.probe_bytes(binary_data)
    assert info is not None
    assert info.is_electron is True
    assert info.run_as_node_disabled is True
    assert info.only_load_from_asar is True
    assert info.cookie_encryption_enabled is True

    test_file = tmp_path / "desktop.exe"
    test_file.write_bytes(binary_data)
    detection = detect_architecture_from_path(test_file)
    assert detection.engine_type == "electron"
    assert any("runAsNode disabled" in note for note in detection.detection_notes)
