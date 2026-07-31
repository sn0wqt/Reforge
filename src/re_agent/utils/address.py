"""Address normalization and formatting utilities."""
from __future__ import annotations

import re


def normalize_address(addr: str) -> str:
    """Normalize an address to lowercase, no prefix, zero-padded to 8 chars.

    Examples:
        >>> normalize_address("0x5E3E90")
        '005e3e90'
        >>> normalize_address("5e3e90")
        '005e3e90'
        >>> normalize_address("0x005E3E90")
        '005e3e90'
    """
    cleaned = addr.strip().lower()
    if ":" in cleaned:
        cleaned = cleaned.rsplit(":", 1)[1]
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        return ""
    if re.fullmatch(r"[0-9a-f]{1,16}", cleaned) is None:
        raise ValueError(f"Invalid hexadecimal address: {addr!r}")
    return cleaned.rjust(8, "0")


def format_address(addr: str) -> str:
    """Ensure an address has a ``0x`` prefix and is lowercase.

    Examples:
        >>> format_address("5E3E90")
        '0x5e3e90'
        >>> format_address("0x5E3E90")
        '0x5e3e90'
    """
    cleaned = addr.strip().lower()
    normalized = normalize_address(cleaned)
    if not normalized:
        raise ValueError("Address may not be empty")
    return "0x" + normalized.lstrip("0") if normalized.strip("0") else "0x0"
