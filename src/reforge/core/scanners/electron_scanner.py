"""Static Electron desktop application and security fuse parser."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

ELECTRON_FUSE_SENTINEL = b"dL7h2TvoWupn74WftndoSmAE33vdZup8"
ASAR_PICKLE_MAGIC = 4


@dataclass(frozen=True)
class ElectronFuseInfo:
    """Parsed Electron binary compile-time security fuses."""

    is_electron: bool
    run_as_node_disabled: bool = False
    only_load_from_asar: bool = False
    cookie_encryption_enabled: bool = False
    fuse_version: int = 1

    @property
    def notes(self) -> tuple[str, ...]:
        entries: list[str] = ["engine: Electron Desktop"]
        if self.run_as_node_disabled:
            entries.append("fuse: runAsNode disabled (hardened)")
        if self.only_load_from_asar:
            entries.append("fuse: onlyLoadAppFromAsar enabled")
        if self.cookie_encryption_enabled:
            entries.append("fuse: cookieEncryption enabled")
        return tuple(entries)


class ElectronScanner:
    """Zero-dependency static parser for Electron binary security fuses and ASAR containers."""

    @classmethod
    def probe_bytes(cls, data: bytes) -> ElectronFuseInfo | None:
        """Scan raw binary bytes for Electron compile-time fuse sentinel."""
        pos = data.find(ELECTRON_FUSE_SENTINEL)
        if pos == -1:
            return None

        # Fuse sentinel length is 32 bytes
        fuse_start = pos + len(ELECTRON_FUSE_SENTINEL)
        if fuse_start + 16 > len(data):
            return ElectronFuseInfo(is_electron=True)

        fuse_version = data[fuse_start]
        # Fuses are stored as 1-byte ASCII values: 0x30 ('0') or 0x31 ('1')
        # Fuse 1: runAsNode (0 = disabled, 1 = enabled)
        # Fuse 2: enableCookieEncryption (1 = enabled)
        # Fuse 3: onlyLoadAppFromAsar (1 = enabled)
        run_as_node_disabled = data[fuse_start + 1] == ord("0")
        cookie_enc = data[fuse_start + 2] == ord("1")
        only_asar = data[fuse_start + 3] == ord("1")

        return ElectronFuseInfo(
            is_electron=True,
            run_as_node_disabled=run_as_node_disabled,
            only_load_from_asar=only_asar,
            cookie_encryption_enabled=cookie_enc,
            fuse_version=fuse_version,
        )

    @classmethod
    def probe_file(cls, path: str | Path, max_bytes: int = 64 * 1024 * 1024) -> ElectronFuseInfo | None:
        """Probe an executable file for Electron security fuses."""
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
    def is_asar_archive(cls, path: str | Path) -> bool:
        """Check if file has a valid Chromium Pickle header for an ASAR archive."""
        p = Path(path)
        if not p.is_file() or p.suffix.lower() != ".asar":
            return False
        try:
            with p.open("rb") as f:
                header = f.read(16)
            if len(header) < 16:
                return False
            pickle_magic, header_bytes, payload_bytes, json_bytes = struct.unpack("<IIII", header)
            return bool(pickle_magic == ASAR_PICKLE_MAGIC and json_bytes > 0)
        except OSError:
            return False
