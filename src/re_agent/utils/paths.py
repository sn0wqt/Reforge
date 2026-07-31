"""Portable path-component validation for generated artifacts."""

from __future__ import annotations

import re

_UNSAFE_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def safe_filename(value: str, *, suffix: str = "", max_length: int = 180) -> str:
    """Return a deterministic cross-platform filename with no path semantics."""
    cleaned = _UNSAFE_COMPONENT.sub("_", value).strip(" ._")
    if not cleaned:
        cleaned = "artifact"
    if cleaned.upper() in _WINDOWS_RESERVED:
        cleaned = f"_{cleaned}"
    suffix_value = suffix if suffix.startswith(".") or not suffix else f".{suffix}"
    room = max(1, max_length - len(suffix_value))
    return f"{cleaned[:room]}{suffix_value}"


def safe_identifier(value: str, *, fallback: str = "symbol", max_length: int = 120) -> str:
    """Return an ASCII C/C++/Rust identifier for generated scaffold names."""
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")[:max_length]
    if not cleaned:
        cleaned = fallback
    if cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned
