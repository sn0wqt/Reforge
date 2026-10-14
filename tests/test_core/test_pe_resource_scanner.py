"""Unit tests for PE resource (.rsrc) scanner."""

from __future__ import annotations

import struct
from pathlib import Path

from reforge.core.scanners.pe_resource_scanner import PeResourceScanner


def _build_synthetic_pe_with_resources(
    product_name: str = "ReforgeSuite",
    company_name: str = "OpenSourceReforge",
    file_version: str = "1.0.0.0",
    manifest_xml: str | None = (
        '<assembly><requestedExecutionLevel level="requireAdministrator" uiAccess="false"/></assembly>'
    ),
) -> bytes:
    # Construct .rsrc payload at file offset 0x200 (RVA 0x2000)
    # Root Resource Directory (offset 0 relative to rsrc root)
    # 2 entries: Type 16 (Version), Type 24 (Manifest)
    # Subdirectories for each type at relative offsets:
    # Type 16 -> Subdir1 at offset 0x40 -> Subdir2 at offset 0x60 -> Leaf1 at offset 0x80
    # Type 24 -> Subdir3 at offset 0xA0 -> Subdir4 at offset 0xC0 -> Leaf2 at offset 0xE0

    rsrc_data = bytearray(0x800)

    # 1. Root directory (Type level)
    # characteristics(4), timestamp(4), major(2), minor(2), named_entries(2), id_entries(2)
    struct.pack_into("<IIHHHH", rsrc_data, 0, 0, 0, 0, 0, 0, 2)
    # Entry 1: ID 16 (Version) -> Subdir1 at 0x40 (high bit set: 0x80000040)
    struct.pack_into("<II", rsrc_data, 16, 16, 0x80000040)
    # Entry 2: ID 24 (Manifest) -> Subdir3 at 0xA0 (high bit set: 0x800000A0)
    struct.pack_into("<II", rsrc_data, 24, 24, 0x800000A0)

    # 2. Subdir1 (Name level for Version: ID 1)
    struct.pack_into("<IIHHHH", rsrc_data, 0x40, 0, 0, 0, 0, 0, 1)
    # Entry: ID 1 -> Subdir2 at 0x60
    struct.pack_into("<II", rsrc_data, 0x50, 1, 0x80000060)

    # 3. Subdir2 (Language level for Version: Lang 1033)
    struct.pack_into("<IIHHHH", rsrc_data, 0x60, 0, 0, 0, 0, 0, 1)
    # Entry: Lang 1033 -> Leaf1 at 0x80
    struct.pack_into("<II", rsrc_data, 0x70, 1033, 0x80)

    # 4. Leaf1 (Data entry for Version)
    # RVA (0x2000 + 0x100 = 0x2100), size (0x200), codepage (0), reserved (0)
    struct.pack_into("<IIII", rsrc_data, 0x80, 0x2100, 0x200, 0, 0)

    # 5. Subdir3 (Name level for Manifest: ID 1)
    struct.pack_into("<IIHHHH", rsrc_data, 0xA0, 0, 0, 0, 0, 0, 1)
    # Entry: ID 1 -> Subdir4 at 0xC0
    struct.pack_into("<II", rsrc_data, 0xB0, 1, 0x800000C0)

    # 6. Subdir4 (Language level for Manifest: Lang 1033)
    struct.pack_into("<IIHHHH", rsrc_data, 0xC0, 0, 0, 0, 0, 0, 1)
    # Entry: Lang 1033 -> Leaf2 at 0xE0
    struct.pack_into("<II", rsrc_data, 0xD0, 1033, 0xE0)

    # 7. Leaf2 (Data entry for Manifest)
    # RVA (0x2000 + 0x300 = 0x2300), size, codepage, reserved
    manifest_bytes = manifest_xml.encode("utf-8") if manifest_xml else b""
    struct.pack_into("<IIII", rsrc_data, 0xE0, 0x2300, len(manifest_bytes), 0, 0)

    # 8. Version payload at offset 0x100
    version_payload = bytearray(b"VS_VERSION_INFO\x00\x00")
    for key, val in [("ProductName", product_name), ("CompanyName", company_name), ("FileVersion", file_version)]:
        version_payload.extend(key.encode("utf-16le") + b"\x00\x00")
        while len(version_payload) % 4 != 0:
            version_payload.append(0)
        version_payload.extend(val.encode("utf-16le") + b"\x00\x00\x00\x00")
    rsrc_data[0x100 : 0x100 + len(version_payload)] = version_payload

    # 9. Manifest payload at offset 0x300
    rsrc_data[0x300 : 0x300 + len(manifest_bytes)] = manifest_bytes

    # Now wrap into full PE structure
    pe = bytearray(0x200 + len(rsrc_data))
    # DOS Header
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)  # e_lfanew = 0x80

    # PE Signature
    pe[0x80:0x84] = b"PE\x00\x00"
    # COFF Header: Machine x86 (0x14c), 1 section, opt size = 224
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x102)

    # Optional Header (PE32)
    opt_offset = 0x98
    struct.pack_into("<H", pe, opt_offset, 0x10B)  # Magic = PE32
    # Resource Data Directory (Index 2): offset opt_offset + 96 + 2 * 8 = opt_offset + 112
    # RVA = 0x2000, Size = len(rsrc_data)
    struct.pack_into("<II", pe, opt_offset + 112, 0x2000, len(rsrc_data))

    # Section Table at opt_offset + 224 = 0x178
    sec_offset = opt_offset + 224
    pe[sec_offset : sec_offset + 8] = b".rsrc\x00\x00\x00"
    # vsize = len(rsrc_data), vaddr = 0x2000, raw_size = len(rsrc_data), raw_ptr = 0x200
    struct.pack_into("<IIII", pe, sec_offset + 8, len(rsrc_data), 0x2000, len(rsrc_data), 0x200)

    # Place .rsrc data at file offset 0x200
    pe[0x200 : 0x200 + len(rsrc_data)] = rsrc_data
    return bytes(pe)


def test_scan_pe_resources() -> None:
    pe_bytes = _build_synthetic_pe_with_resources(
        product_name="ReforgeTestApp",
        company_name="ReforgeCorp",
        file_version="2.5.1.0",
        manifest_xml='<assembly><requestedExecutionLevel level="requireAdministrator" uiAccess="false"/></assembly>',
    )
    info = PeResourceScanner.scan_bytes(pe_bytes)
    assert info is not None
    assert info.product_name == "ReforgeTestApp"
    assert info.company_name == "ReforgeCorp"
    assert info.file_version == "2.5.1.0"
    assert info.requested_execution_level == "requireAdministrator"
    assert info.ui_access is False
    assert "version" in info.resource_counts
    assert "manifest" in info.resource_counts
    assert any("ReforgeTestApp" in n for n in info.notes)


def test_scan_pe_file(tmp_path: Path) -> None:
    pe_file = tmp_path / "app.exe"
    pe_file.write_bytes(_build_synthetic_pe_with_resources(product_name="OnDiskApp"))

    info = PeResourceScanner.scan_file(pe_file)
    assert info is not None
    assert info.product_name == "OnDiskApp"

    # Non-existent or invalid PE
    assert PeResourceScanner.scan_file(tmp_path / "missing.exe") is None
    bad_pe = tmp_path / "corrupt.exe"
    bad_pe.write_bytes(b"not a valid PE")
    assert PeResourceScanner.scan_file(bad_pe) is None
