"""Static Rust binary dependency and rustc commit parser."""

from __future__ import annotations

import json
import re
import zlib
from dataclasses import dataclass
from pathlib import Path

MAX_UNCOMPRESSED_AUDIT_BYTES = 8 * 1024 * 1024
RUSTC_COMMIT_PATTERN = re.compile(rb"/rustc/([0-9a-f]{40})/")


@dataclass(frozen=True)
class RustCrate:
    """A crate package recorded in cargo-auditable metadata."""

    name: str
    version: str
    source: str | None = None
    kind: str | None = None
    is_root: bool = False


@dataclass(frozen=True)
class RustBuildInfo:
    """Parsed Rust cargo-auditable dependencies and compiler commit."""

    crates: tuple[RustCrate, ...]
    rustc_commit: str | None = None
    root_package: str | None = None

    @property
    def notes(self) -> tuple[str, ...]:
        entries: list[str] = [f"rust crates: {len(self.crates)}"]
        if self.root_package:
            entries.append(f"root package: {self.root_package}")
        if self.rustc_commit:
            entries.append(f"rustc commit: {self.rustc_commit[:12]}")
        return tuple(entries)


class RustScanner:
    """Zero-dependency static parser for Rust cargo-auditable and rustc metadata."""

    @classmethod
    def probe_bytes(cls, data: bytes) -> RustBuildInfo | None:
        """Scan raw binary bytes for cargo-auditable metadata and rustc commits."""
        crates, root_pkg = cls._extract_auditable_crates(data)
        commit = cls._extract_rustc_commit(data)

        if not crates and not commit:
            return None

        return RustBuildInfo(
            crates=crates,
            rustc_commit=commit,
            root_package=root_pkg,
        )

    @classmethod
    def probe_file(cls, path: str | Path, max_bytes: int = 64 * 1024 * 1024) -> RustBuildInfo | None:
        """Probe an executable file for Rust build information."""
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
    def _extract_auditable_crates(cls, data: bytes) -> tuple[tuple[RustCrate, ...], str | None]:
        """Locate and decompress cargo-auditable .dep-v0 payload."""
        # Find auditable container signature or zlib magic near section headers
        signatures = (b"\x00rust\x00", b"auditable", b".dep-v0")
        offset = -1
        for sig in signatures:
            pos = data.find(sig)
            if pos != -1:
                offset = pos
                break

        if offset == -1:
            return (), None

        # Search forward for zlib header 0x78 0x9c or 0x78 0x01 or 0x78 0xda within 512 bytes
        slice_end = min(len(data), offset + 512)
        zlib_pos = -1
        for i in range(offset, slice_end - 2):
            if data[i] == 0x78 and data[i + 1] in (0x01, 0x9C, 0xDA, 0x5E):
                zlib_pos = i
                break

        if zlib_pos == -1:
            # Fallback: search anywhere in data for zlib chunks that decompress to {"format":
            return cls._scan_for_decompressed_json(data, offset)

        try:
            decomp = zlib.decompress(data[zlib_pos:], bufsize=MAX_UNCOMPRESSED_AUDIT_BYTES)
            if len(decomp) > MAX_UNCOMPRESSED_AUDIT_BYTES:
                return (), None
            return cls._parse_auditable_json(decomp)
        except Exception:
            return cls._scan_for_decompressed_json(data, offset)

    @classmethod
    def _scan_for_decompressed_json(
        cls,
        data: bytes,
        start_hint: int,
    ) -> tuple[tuple[RustCrate, ...], str | None]:
        """Fallback search trying zlib decompress at plausible offsets."""
        window_start = max(0, start_hint - 256)
        window_end = min(len(data) - 64, start_hint + 1024)
        for i in range(window_start, window_end):
            if data[i] == 0x78 and data[i + 1] in (0x01, 0x9C, 0xDA, 0x5E):
                try:
                    decomp = zlib.decompress(data[i:i + 256 * 1024])
                    if b'"packages"' in decomp and b'"version"' in decomp:
                        return cls._parse_auditable_json(decomp)
                except Exception:
                    continue
        return (), None

    @classmethod
    def _parse_auditable_json(cls, raw: bytes) -> tuple[tuple[RustCrate, ...], str | None]:
        """Parse uncompressed cargo-auditable JSON document."""
        try:
            doc = json.loads(raw.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return (), None

        packages = doc.get("packages")
        if not isinstance(packages, list):
            return (), None

        crates: list[RustCrate] = []
        root_name: str | None = None

        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            source = pkg.get("source") if isinstance(pkg.get("source"), str) else None
            kind = pkg.get("kind") if isinstance(pkg.get("kind"), str) else None
            is_root = bool(pkg.get("root", False))
            if is_root and root_name is None:
                root_name = f"{name} {version}"

            crates.append(
                RustCrate(
                    name=name,
                    version=version,
                    source=source,
                    kind=kind,
                    is_root=is_root,
                )
            )

        return tuple(crates), root_name

    @classmethod
    def _extract_rustc_commit(cls, data: bytes) -> str | None:
        """Scan binary for /rustc/<40-hex-commit>/ path components."""
        matches = RUSTC_COMMIT_PATTERN.findall(data)
        if not matches:
            return None
        first_match = matches[0]
        if isinstance(first_match, bytes):
            return first_match.decode("ascii", errors="ignore")
        return str(first_match)
