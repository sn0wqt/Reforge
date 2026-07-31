"""Byte signature generation and pattern scanning for binary relocation analysis."""

from __future__ import annotations

import re
from typing import Any


def parse_signature(signature: str) -> list[int | None]:
    """Parse a signature string (e.g. '55 48 89 ?? E5') into a list of byte integers or None for wildcards."""
    tokens = signature.strip().split()
    pattern: list[int | None] = []
    for token in tokens:
        if token in ("?", "??", "*"):
            pattern.append(None)
        else:
            if not re.fullmatch(r"[0-9A-Fa-f]{1,2}", token):
                raise ValueError(f"Invalid signature token: {token!r}")
            pattern.append(int(token, 16))
    return pattern


def match_signature(
    binary_bytes: bytes | bytearray,
    signature: str,
    alignment: int = 1,
) -> list[int]:
    """Scan a binary buffer for matches against a signature pattern with wildcards.

    Args:
        binary_bytes: Raw binary buffer to scan.
        signature: Space-separated hex pattern with wildcards (e.g. '55 48 89 ?? E5').
        alignment: Memory alignment requirement (e.g. 4 for ARM64 instructions, 1 for x86).

    Returns a list of 0-based offset positions where the pattern matches.
    """
    pattern = parse_signature(signature)
    if not pattern:
        return []

    pat_len = len(pattern)
    data_len = len(binary_bytes)
    if pat_len > data_len:
        return []

    matches: list[int] = []
    first_idx = next((i for i, b in enumerate(pattern) if b is not None), None)

    for i in range(0, data_len - pat_len + 1, max(1, alignment)):
        if first_idx is not None and binary_bytes[i + first_idx] != pattern[first_idx]:
            continue

        match = True
        for j, p_byte in enumerate(pattern):
            if p_byte is not None and binary_bytes[i + j] != p_byte:
                match = False
                break
        if match:
            matches.append(i)

    return matches


def generate_signature(instructions: list[dict[str, Any]], mask_relocations: bool = True) -> str:
    """Generate a masked byte signature from a sequence of instruction dictionaries.

    Each instruction dict should contain 'bytes' (e.g. '55 48 89 e5' or [0x55, 0x48])
    and optionally 'is_relocated' or 'mnemonic' to apply wildcard masks.
    """
    sig_tokens: list[str] = []
    for inst in instructions:
        bytes_val = inst.get("bytes", "")
        is_relocated = inst.get("is_relocated", False)

        if isinstance(bytes_val, str):
            raw_bytes = [b for b in bytes_val.replace(",", " ").split() if b]
        elif isinstance(bytes_val, (bytes, bytearray, list)):
            raw_bytes = [f"{b:02X}" if isinstance(b, int) else str(b) for b in bytes_val]
        else:
            raw_bytes = []

        if mask_relocations and is_relocated:
            sig_tokens.extend(["??"] * len(raw_bytes))
        else:
            for b in raw_bytes:
                sig_tokens.append(f"{int(b, 16):02X}" if re.match(r"^[0-9A-Fa-f]{1,2}$", b) else "??")

    return " ".join(sig_tokens)
