"""Static Go binary build information and module parser."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
GO_MODULE_HEADER_MAGIC = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
GO_MODULE_TAIL_MAGIC = bytes.fromhex("f932433186182072008242104116d8f2")


@dataclass(frozen=True)
class GoBuildInfo:
    """Parsed Go build information and module metadata."""

    version: str
    main_module: str | None = None
    dependencies: tuple[tuple[str, str, str], ...] = ()
    build_settings: dict[str, str] = field(default_factory=dict)
    architecture: str | None = None
    os: str | None = None
    vcs_revision: str | None = None

    @property
    def notes(self) -> tuple[str, ...]:
        entries: list[str] = [f"go version: {self.version}"]
        if self.main_module:
            entries.append(f"module: {self.main_module}")
        if self.vcs_revision:
            entries.append(f"vcs: {self.vcs_revision}")
        if self.dependencies:
            entries.append(f"dependencies: {len(self.dependencies)} packages")
        return tuple(entries)


class GoScanner:
    """Zero-dependency static parser for Go binary build information."""

    @staticmethod
    def decode_uleb128(data: bytes, offset: int) -> tuple[int, int]:
        """Decode a ULEB128 varint returning (value, new_offset)."""
        result = 0
        shift = 0
        curr = offset
        while curr < len(data):
            byte = data[curr]
            curr += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
            if shift >= 64:
                break
        return result, curr

    @classmethod
    def probe_bytes(cls, data: bytes) -> GoBuildInfo | None:
        """Scan raw binary bytes for Go build information."""
        idx = 0
        limit = len(data) - 32
        while idx < limit:
            pos = data.find(GO_BUILDINFO_MAGIC, idx)
            if pos == -1:
                break
            # Go buildinfo is 16-byte aligned in virtual memory or binary file
            if (pos % 16) == 0 and pos + 32 <= len(data):
                info = cls._parse_header(data, pos)
                if info is not None:
                    return info
            idx = pos + 1
        return None

    @classmethod
    def probe_file(cls, path: str | Path, max_bytes: int = 64 * 1024 * 1024) -> GoBuildInfo | None:
        """Probe an executable file for Go build information."""
        p = Path(path)
        if not p.is_file():
            return None
        try:
            with p.open("rb") as f:
                data = f.read(max_bytes)
            return cls.probe_bytes(data)
        except OSError:
            return None

    @classmethod
    def _parse_header(cls, data: bytes, offset: int) -> GoBuildInfo | None:
        """Parse Go buildinfo header starting at offset."""
        ptr_size = data[offset + 14]
        if ptr_size not in (4, 8):
            return None
        flags = data[offset + 15]
        # Bit 1 = 1 means inline varint strings (Go 1.18+)
        is_inline = bool(flags & 2)

        if not is_inline:
            # Legacy Go <= 1.17 pointer-based format fallback
            # Scan nearby text for go version pattern
            version = cls._scan_legacy_version(data, offset)
            return GoBuildInfo(version=version or "Go (pre-1.18)")

        # Inline format (Go >= 1.18)
        curr = offset + 32
        if curr >= len(data):
            return None

        # 1. Version string
        version_len, curr = cls.decode_uleb128(data, curr)
        if version_len <= 0 or curr + version_len > len(data):
            return None
        version = data[curr : curr + version_len].decode("utf-8", errors="replace")
        curr += version_len

        # 2. Module string
        if curr >= len(data):
            return GoBuildInfo(version=version)

        mod_len, curr = cls.decode_uleb128(data, curr)
        if mod_len <= 0 or curr + mod_len > len(data):
            return GoBuildInfo(version=version)

        raw_mod = data[curr : curr + mod_len]
        return cls._parse_module_text(version, raw_mod)

    @classmethod
    def _scan_legacy_version(cls, data: bytes, offset: int) -> str | None:
        """Search adjacent segment bytes for go1.x version strings."""
        start = max(0, offset - 4096)
        end = min(len(data), offset + 4096)
        slice_data = data[start:end]
        import re

        m = re.search(rb"go1\.[0-9]+(\.[0-9]+)?", slice_data)
        if m:
            return m.group(0).decode("utf-8", errors="ignore")
        return None

    @classmethod
    def _parse_module_text(cls, version: str, raw: bytes) -> GoBuildInfo:
        """Parse tab-separated Go 1.18+ module text."""
        # Strip 16-byte framing markers if present
        if raw.startswith(GO_MODULE_HEADER_MAGIC) and len(raw) >= 32:
            raw = raw[16:]
        if raw.endswith(GO_MODULE_TAIL_MAGIC) and len(raw) >= 16:
            raw = raw[:-16]

        text = raw.decode("utf-8", errors="replace").strip()
        main_module: str | None = None
        deps: list[tuple[str, str, str]] = []
        settings: dict[str, str] = {}
        arch: str | None = None
        go_os: str | None = None
        vcs_rev: str | None = None

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if not parts:
                continue
            tag = parts[0]
            if tag == "path" and len(parts) >= 2:
                main_module = parts[1]
            elif tag == "dep" and len(parts) >= 3:
                pkg_path = parts[1]
                pkg_ver = parts[2]
                pkg_hash = parts[3] if len(parts) >= 4 else ""
                deps.append((pkg_path, pkg_ver, pkg_hash))
            elif tag == "build" and len(parts) >= 2:
                kv = parts[1].split("=", 1)
                if len(kv) == 2:
                    k, v = kv[0].strip(), kv[1].strip()
                    settings[k] = v
                    if k == "GOARCH":
                        arch = v
                    elif k == "GOOS":
                        go_os = v
                    elif k == "vcs.revision":
                        vcs_rev = v

        return GoBuildInfo(
            version=version,
            main_module=main_module,
            dependencies=tuple(deps),
            build_settings=settings,
            architecture=arch,
            os=go_os,
            vcs_revision=vcs_rev,
        )
