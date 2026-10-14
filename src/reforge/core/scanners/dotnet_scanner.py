"""Static .NET PE assembly and ECMA-335 CLI metadata parser."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

BSJB_MAGIC = b"BSJB"


@dataclass(frozen=True)
class DotNetInfo:
    """Parsed .NET PE assembly and CLI metadata."""

    clr_version: str
    is_il_only: bool
    is_32bit_required: bool
    is_ready_to_run: bool
    assembly_refs: tuple[str, ...]
    is_unity: bool = False

    @property
    def notes(self) -> tuple[str, ...]:
        entries: list[str] = [f"clr version: {self.clr_version}"]
        if self.is_il_only:
            entries.append("type: pure IL")
        if self.is_ready_to_run:
            entries.append("format: ReadyToRun (RTR)")
        if self.is_unity:
            entries.append("engine: Unity Mono/.NET")
        if self.assembly_refs:
            entries.append(f"assemblies: {', '.join(self.assembly_refs[:5])}")
        return tuple(entries)


class DotNetScanner:
    """Zero-dependency static parser for .NET PE assemblies and ECMA-335 metadata."""

    @classmethod
    def probe_bytes(cls, data: bytes) -> DotNetInfo | None:
        """Scan raw binary bytes for .NET PE CLI headers and ECMA-335 metadata."""
        if len(data) < 512 or not data.startswith(b"MZ"):
            return None

        # 1. Read e_lfanew
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 264 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None

        # 2. Check PE magic (PE32 vs PE32+)
        opt_magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
        if opt_magic == 0x10B:  # PE32
            cli_dir_offset = e_lfanew + 24 + 96 + (14 * 8)
        elif opt_magic == 0x20B:  # PE32+
            cli_dir_offset = e_lfanew + 24 + 112 + (14 * 8)
        else:
            return None

        if cli_dir_offset + 8 > len(data):
            return None

        cli_rva, cli_size = struct.unpack_from("<II", data, cli_dir_offset)
        if cli_rva == 0 or cli_size < 72:
            return None  # Native PE without CLI descriptor

        # 3. Read section headers to map RVA to file offset
        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sect_start = e_lfanew + 24 + opt_hdr_size

        cli_offset = cls._rva_to_offset(data, sect_start, num_sections, cli_rva)
        if cli_offset is None or cli_offset + 72 > len(data):
            return None

        # 4. Parse IMAGE_COR20_HEADER
        cb, major_rt, minor_rt, meta_rva, meta_size, flags = struct.unpack_from(
            "<IHHII I", data, cli_offset
        )
        if meta_rva == 0 or meta_size < 16:
            return None

        is_il_only = bool(flags & 0x0001)
        is_32bit = bool(flags & 0x0002)

        # Check for ReadyToRun signature
        rtr_offset = cli_offset + 64
        is_rtr = False
        if rtr_offset + 8 <= len(data):
            rtr_rva, _ = struct.unpack_from("<II", data, rtr_offset)
            if rtr_rva != 0:
                is_rtr = True

        # 5. Parse ECMA-335 Metadata Root (BSJB)
        meta_offset = cls._rva_to_offset(data, sect_start, num_sections, meta_rva)
        if meta_offset is None or meta_offset + 16 > len(data):
            return DotNetInfo(
                clr_version=f"{major_rt}.{minor_rt}",
                is_il_only=is_il_only,
                is_32bit_required=is_32bit,
                is_ready_to_run=is_rtr,
                assembly_refs=(),
            )

        if data[meta_offset : meta_offset + 4] != BSJB_MAGIC:
            return None

        version_len = struct.unpack_from("<I", data, meta_offset + 12)[0]
        version_str_offset = meta_offset + 16
        if version_str_offset + version_len > len(data):
            clr_ver = f"{major_rt}.{minor_rt}"
        else:
            raw_ver = data[version_str_offset : version_str_offset + version_len]
            clr_ver = raw_ver.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

        # 6. Extract assembly references by scanning metadata streams
        assembly_refs = cls._extract_strings(data, meta_offset)
        is_unity = any(
            "unity" in ref.lower() or "engine" in ref.lower()
            for ref in assembly_refs
        )

        return DotNetInfo(
            clr_version=clr_ver or f"{major_rt}.{minor_rt}",
            is_il_only=is_il_only,
            is_32bit_required=is_32bit,
            is_ready_to_run=is_rtr,
            assembly_refs=tuple(assembly_refs),
            is_unity=is_unity,
        )

    @classmethod
    def probe_file(cls, path: str | Path, max_bytes: int = 64 * 1024 * 1024) -> DotNetInfo | None:
        """Probe an executable file for .NET PE CLI metadata."""
        p = Path(path)
        if not p.is_file():
            return None
        try:
            with p.open("rb") as f:
                data = f.read(max_bytes)
            return cls.probe_bytes(data)
        except OSError:
            return None

    @staticmethod
    def _rva_to_offset(data: bytes, sect_start: int, num_sections: int, rva: int) -> int | None:
        """Convert a PE Relative Virtual Address (RVA) to physical file offset."""
        for i in range(num_sections):
            hdr = sect_start + (i * 40)
            if hdr + 40 > len(data):
                break
            virt_size = struct.unpack_from("<I", data, hdr + 8)[0]
            virt_addr = struct.unpack_from("<I", data, hdr + 12)[0]
            raw_size = struct.unpack_from("<I", data, hdr + 16)[0]
            raw_offset = struct.unpack_from("<I", data, hdr + 20)[0]

            span = max(virt_size, raw_size)
            if virt_addr <= rva < virt_addr + span:
                return int(raw_offset + (rva - virt_addr))
        return None

    @staticmethod
    def _extract_strings(data: bytes, meta_offset: int) -> list[str]:
        """Scan #Strings stream in metadata root for referenced assembly names."""
        # Search for #Strings stream header within 512 bytes of meta_offset
        strings_tag = b"#Strings\x00"
        pos = data.find(strings_tag, meta_offset, min(len(data), meta_offset + 512))
        if pos == -1:
            return []

        # Read stream offset relative to meta_offset
        stream_rel_offset = struct.unpack_from("<I", data, pos - 8)[0]
        stream_size = struct.unpack_from("<I", data, pos - 4)[0]

        start = meta_offset + stream_rel_offset
        end = min(len(data), start + min(stream_size, 64 * 1024))
        if start >= end:
            return []

        raw_strings = data[start:end]
        extracted: list[str] = []
        for token in raw_strings.split(b"\x00"):
            if 3 <= len(token) <= 64:
                try:
                    s = token.decode("utf-8")
                    if any(
                        s.startswith(p)
                        for p in ("mscorlib", "System", "Unity", "Newtonsoft", "Microsoft")
                    ) and s not in extracted:
                        extracted.append(s)
                except UnicodeDecodeError:
                    continue
            if len(extracted) >= 12:
                break
        return extracted
