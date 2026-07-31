"""Centralized binary magic byte detection."""

from __future__ import annotations

from pathlib import Path


def get_magic_bytes(path: Path) -> bytes:
    """Read the first 4 bytes of a file safely."""
    try:
        with path.open("rb") as binary:
            return binary.read(4)
    except OSError:
        return b""


def is_mach_o(path: Path) -> bool:
    """Determine if a file is a Mach-O binary based on magic numbers."""
    magic = get_magic_bytes(path)
    return magic in {
        b"\xfe\xed\xfa\xce",  # MH_MAGIC
        b"\xce\xfa\xed\xfe",  # MH_CIGAM
        b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
        b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
        b"\xca\xfe\xba\xbe",  # FAT_MAGIC
        b"\xbe\xba\xfe\xca",  # FAT_CIGAM
        b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
        b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64
    }
