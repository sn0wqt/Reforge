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


def match_signature(binary_bytes: bytes | bytearray, signature: str) -> list[int]:
    """Scan a binary buffer for matches against a signature pattern with wildcards.

    Returns a list of 0-based offset positions where the pattern matches.
    """
    pattern = parse_signature(signature)
def match_signature(data: bytes, signature_str: str, alignment: int = 1) -> list[int]:
    """Search byte data for a pattern signature with wildcards.

    Args:
        data: Raw binary byte buffer.
        signature_str: Hex pattern string (e.g. "55 48 89 ?? E5").
        alignment: Boundary alignment step (e.g. 4 for 32-bit instructions).

    Returns:
        List of byte offsets where the signature matched.
    """
    pattern = parse_signature(signature_str)
    if not pattern or len(pattern) > len(data):
        return []

    matches: list[int] = []
    pat_len = len(pattern)
    step = max(1, alignment)
    for i in range(0, len(data) - pat_len + 1, step):
        matched = True
        for j, byte_val in enumerate(pattern):
            if byte_val is not None and data[i + j] != byte_val:
                matched = False
                break
        if matched:
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
