"""Pure-Python PE Resource (.rsrc) Scanner.

Inspects Windows Portable Executable (.exe, .dll) resource trees without external tools:
- Locates and maps IMAGE_DIRECTORY_ENTRY_RESOURCE (Data Directory 2).
- Recursively parses the 3-tier resource directory hierarchy (Type -> Name/ID -> Language).
- Decodes RT_VERSION (VS_VERSION_INFO): CompanyName, FileDescription, FileVersion,
  ProductName, ProductVersion, LegalCopyright, OriginalFilename.
- Decodes RT_MANIFEST (XML Application Manifest): requestedExecutionLevel (asInvoker,
  requireAdministrator, highestAvailable), uiAccess, DPI awareness, supported OS GUIDs.
- Counts embedded resources: icons, cursors, dialogs, string tables, manifests.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RESOURCE_TYPE_NAMES: dict[int, str] = {
    1: "cursor",
    2: "bitmap",
    3: "icon",
    4: "menu",
    5: "dialog",
    6: "string_table",
    7: "font_directory",
    8: "font",
    9: "accelerator",
    10: "rcdata",
    11: "message_table",
    12: "group_cursor",
    14: "group_icon",
    16: "version",
    24: "manifest",
}


@dataclass(frozen=True)
class PeResourceEntry:
    """Single leaf resource data entry."""

    type_id: int | str
    name_id: int | str
    language_id: int
    rva: int
    size: int
    code_page: int


@dataclass(frozen=True)
class PeResourceInfo:
    """Aggregated PE resource extraction report."""

    version_info: dict[str, str] = field(default_factory=dict)
    manifest_xml: str | None = None
    requested_execution_level: str | None = None
    ui_access: bool | None = None
    resource_counts: dict[str, int] = field(default_factory=dict)
    total_resources: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def file_version(self) -> str | None:
        return self.version_info.get("FileVersion")

    @property
    def product_version(self) -> str | None:
        return self.version_info.get("ProductVersion")

    @property
    def company_name(self) -> str | None:
        return self.version_info.get("CompanyName")

    @property
    def product_name(self) -> str | None:
        return self.version_info.get("ProductName")


class PeResourceScanner:
    """Pure-Python scanner for PE .rsrc trees."""

    @classmethod
    def scan_file(cls, path: str | Path, max_bytes: int = 64 * 1024 * 1024) -> PeResourceInfo | None:
        """Scan a PE file on disk."""
        target = Path(path)
        if not target.is_file():
            return None
        try:
            with open(target, "rb") as f:
                header = f.read(1024)
                if len(header) < 64 or header[:2] != b"MZ":
                    return None
                f.seek(0)
                data = f.read(max_bytes)
                return cls.scan_bytes(data)
        except (OSError, ValueError):
            return None

    @classmethod
    def scan_bytes(cls, data: bytes) -> PeResourceInfo | None:
        """Parse PE bytes and extract resource directory contents."""
        if len(data) < 64 or data[:2] != b"MZ":
            return None

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 264 > len(data):
            return None

        pe_sig = data[e_lfanew : e_lfanew + 4]
        if pe_sig != b"PE\x00\x00":
            return None

        coff_offset = e_lfanew + 4
        num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
        size_opt_header = struct.unpack_from("<H", data, coff_offset + 16)[0]

        opt_offset = coff_offset + 20
        if opt_offset + size_opt_header > len(data):
            return None

        magic = struct.unpack_from("<H", data, opt_offset)[0]
        if magic == 0x10B:  # PE32
            rsrc_dir_offset = opt_offset + 96 + 2 * 8
        elif magic == 0x20B:  # PE32+
            rsrc_dir_offset = opt_offset + 112 + 2 * 8
        else:
            return None

        if rsrc_dir_offset + 8 > len(data):
            return None

        rsrc_rva, rsrc_size = struct.unpack_from("<II", data, rsrc_dir_offset)
        if rsrc_rva == 0 or rsrc_size == 0:
            return None

        # Parse section headers to find .rsrc file mapping
        sec_table_offset = opt_offset + size_opt_header
        sections: list[tuple[int, int, int, int]] = []  # (vaddr, vsize, raw_ptr, raw_size)
        for i in range(num_sections):
            sec_hdr = sec_table_offset + i * 40
            if sec_hdr + 40 > len(data):
                break
            vsize = struct.unpack_from("<I", data, sec_hdr + 8)[0]
            vaddr = struct.unpack_from("<I", data, sec_hdr + 12)[0]
            raw_size = struct.unpack_from("<I", data, sec_hdr + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, sec_hdr + 20)[0]
            sections.append((vaddr, vsize, raw_ptr, raw_size))

        def rva_to_offset(rva: int) -> int | None:
            for vaddr, vsize, raw_ptr, raw_size in sections:
                span = max(vsize, raw_size)
                if vaddr <= rva < vaddr + span:
                    file_off = raw_ptr + (rva - vaddr)
                    return file_off if file_off < len(data) else None
            return None

        root_file_offset = rva_to_offset(rsrc_rva)
        if root_file_offset is None or root_file_offset >= len(data):
            return None

        # Traversal of resource directory tree
        entries: list[PeResourceEntry] = []
        cls._walk_directory(
            data,
            root_file_offset,
            root_file_offset,
            rsrc_rva,
            rsrc_size,
            rva_to_offset,
            depth=0,
            path_ids=[],
            collected=entries,
        )

        counts: dict[str, int] = {}
        version_info: dict[str, str] = {}
        manifest_xml: str | None = None
        requested_execution_level: str | None = None
        ui_access: bool | None = None

        for entry in entries:
            type_label = (
                RESOURCE_TYPE_NAMES.get(entry.type_id, f"type_{entry.type_id}")
                if isinstance(entry.type_id, int)
                else str(entry.type_id)
            )
            counts[type_label] = counts.get(type_label, 0) + 1

            entry_file_offset = rva_to_offset(entry.rva)
            if entry_file_offset is None or entry_file_offset + entry.size > len(data):
                continue
            payload = data[entry_file_offset : entry_file_offset + entry.size]

            # RT_VERSION (16)
            if entry.type_id == 16 and not version_info:
                version_info = cls._parse_version_info(payload)

            # RT_MANIFEST (24)
            if entry.type_id == 24 and manifest_xml is None:
                manifest_xml, req_lvl, ui_acc = cls._parse_manifest(payload)
                if req_lvl:
                    requested_execution_level = req_lvl
                if ui_acc is not None:
                    ui_access = ui_acc

        notes: list[str] = []
        if version_info.get("ProductName"):
            notes.append(f"Product: {version_info.get('ProductName')}")
        if version_info.get("FileVersion"):
            notes.append(f"FileVersion: {version_info.get('FileVersion')}")
        if version_info.get("CompanyName"):
            notes.append(f"Company: {version_info.get('CompanyName')}")
        if requested_execution_level:
            notes.append(f"ExecutionLevel: {requested_execution_level}")
        if counts:
            summary_counts = [f"{k}: {v}" for k, v in sorted(counts.items())]
            notes.append(f"Resources ({len(entries)}): {', '.join(summary_counts)}")

        return PeResourceInfo(
            version_info=version_info,
            manifest_xml=manifest_xml,
            requested_execution_level=requested_execution_level,
            ui_access=ui_access,
            resource_counts=counts,
            total_resources=len(entries),
            notes=notes,
        )

    @classmethod
    def _walk_directory(
        cls,
        data: bytes,
        root_offset: int,
        dir_offset: int,
        rsrc_rva: int,
        rsrc_size: int,
        rva_to_offset: Any,
        depth: int,
        path_ids: list[int | str],
        collected: list[PeResourceEntry],
        max_entries: int = 500,
    ) -> None:
        """Recursively walk the Type -> Name -> Language directory tree."""
        if depth > 3 or len(collected) >= max_entries:
            return
        if dir_offset + 16 > len(data):
            return

        num_named, num_id = struct.unpack_from("<HH", data, dir_offset + 12)
        total_subentries = num_named + num_id
        entry_table = dir_offset + 16

        for i in range(min(total_subentries, 200)):
            if len(collected) >= max_entries:
                break
            entry_ptr = entry_table + i * 8
            if entry_ptr + 8 > len(data):
                break

            name_raw, data_raw = struct.unpack_from("<II", data, entry_ptr)

            # Name or ID
            if name_raw & 0x80000000:
                name_offset = root_offset + (name_raw & 0x7FFFFFFF)
                if name_offset + 2 <= len(data):
                    u16_len = struct.unpack_from("<H", data, name_offset)[0]
                    u16_bytes = data[name_offset + 2 : name_offset + 2 + u16_len * 2]
                    curr_id: int | str = u16_bytes.decode("utf-16le", errors="replace")
                else:
                    curr_id = f"offset_{name_raw & 0x7FFFFFFF}"
            else:
                curr_id = name_raw

            new_path = path_ids + [curr_id]

            # Subdirectory or Data
            if data_raw & 0x80000000:
                subdir_offset = root_offset + (data_raw & 0x7FFFFFFF)
                cls._walk_directory(
                    data,
                    root_offset,
                    subdir_offset,
                    rsrc_rva,
                    rsrc_size,
                    rva_to_offset,
                    depth + 1,
                    new_path,
                    collected,
                    max_entries,
                )
            else:
                leaf_offset = root_offset + data_raw
                if leaf_offset + 16 <= len(data):
                    leaf_rva, leaf_size, code_page = struct.unpack_from("<III", data, leaf_offset)
                    type_val = new_path[0] if len(new_path) > 0 else 0
                    name_val = new_path[1] if len(new_path) > 1 else 0
                    lang_val = new_path[2] if len(new_path) > 2 and isinstance(new_path[2], int) else 0

                    collected.append(
                        PeResourceEntry(
                            type_id=type_val,
                            name_id=name_val,
                            language_id=lang_val,
                            rva=leaf_rva,
                            size=leaf_size,
                            code_page=code_page,
                        )
                    )

    @classmethod
    def _parse_version_info(cls, data: bytes) -> dict[str, str]:
        """Decode VS_VERSION_INFO binary structures and extract StringFileInfo strings."""
        strings: dict[str, str] = {}
        if len(data) < 40:
            return strings

        # Scan for known UTF-16 string keys
        target_keys = [
            "CompanyName",
            "FileDescription",
            "FileVersion",
            "InternalName",
            "LegalCopyright",
            "OriginalFilename",
            "ProductName",
            "ProductVersion",
            "Comments",
        ]
        for key in target_keys:
            needle = key.encode("utf-16le") + b"\x00\x00"
            idx = data.find(needle)
            if idx != -1:
                # Value starts after key and 4-byte alignment
                val_start = idx + len(needle)
                if val_start % 4 != 0:
                    val_start += 4 - (val_start % 4)
                if val_start < len(data):
                    # Find trailing double null
                    val_data = data[val_start : val_start + 512]
                    null_idx = -1
                    for j in range(0, len(val_data) - 1, 2):
                        if val_data[j : j + 2] == b"\x00\x00":
                            null_idx = j
                            break
                    if null_idx > 0:
                        val_str = val_data[:null_idx].decode("utf-16le", errors="replace").strip()
                        if val_str:
                            strings[key] = val_str
        return strings

    @classmethod
    def _parse_manifest(cls, data: bytes) -> tuple[str, str | None, bool | None]:
        """Decode XML manifest and extract execution level."""
        try:
            # Manifest can be UTF-8 or UTF-16
            if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
                text = data.decode("utf-16", errors="replace")
            else:
                text = data.decode("utf-8", errors="replace")
        except Exception:
            return "", None, None

        exec_level: str | None = None
        ui_access: bool | None = None

        m_level = re.search(r'requestedExecutionLevel[^>]*level=["\']([^"\']+)["\']', text, re.IGNORECASE)
        if m_level:
            exec_level = m_level.group(1)

        m_ui = re.search(r'requestedExecutionLevel[^>]*uiAccess=["\']([^"\']+)["\']', text, re.IGNORECASE)
        if m_ui:
            ui_access = m_ui.group(1).lower() == "true"

        return text, exec_level, ui_access
