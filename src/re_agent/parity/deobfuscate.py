"""De-obfuscation heuristics for string encryption and constant unpacking in P-code evidence."""
from __future__ import annotations

import re
from typing import Any

STACK_STORE_PATTERN = re.compile(
    r"(?:mov|str|movb|movl|movw)\b.*"
    r"\[(?:rsp|rbp|sp|x\d+|r\d+)\s*[\+\-]\s*"
    r"(0x[0-9a-fA-F]+|\d+)\]\s*,\s*(0x[0-9a-fA-F]+|\d+)",
    re.IGNORECASE,
)


def detect_xor_loops(pcode_lines: list[str]) -> list[dict[str, Any]]:
    """Scan P-code lines for XOR decryption loop patterns (e.g., XOR, INT_XOR operations in loops)."""
    results: list[dict[str, Any]] = []
    xor_pattern = re.compile(r"(?:INT_XOR|XOR|xor)\b", re.IGNORECASE)
    loop_pattern = re.compile(r"(?:BRANCH|CBRANCH|goto|while)\b", re.IGNORECASE)

    has_loop = any(loop_pattern.search(line) for line in pcode_lines)
    for idx, line in enumerate(pcode_lines):
        if xor_pattern.search(line):
            results.append({
                "line_index": idx,
                "line": line.strip(),
                "in_loop": has_loop,
                "type": "xor_op",
            })
    return results


def detect_stack_strings(assembly: list[str]) -> list[dict[str, Any]]:
    """Detect stack string construction patterns in assembly.

    Finds instructions that move immediate bytes onto stack offsets.
    """
    entries: list[dict[str, Any]] = []
    for line in assembly:
        match = STACK_STORE_PATTERN.search(line)
        if match:
            entries.append(
                {
                    "offset": match.group(1),
                    "value": match.group(2),
                    "line": line.strip(),
                }
            )
    return entries


def reconstruct_stack_strings(assembly: list[str]) -> str:
    """Reconstruct ASCII strings assembled piece-by-piece on the stack."""
    chars: list[tuple[int, str]] = []
    for line in assembly:
        match = STACK_STORE_PATTERN.search(line)
        if match:
            try:
                offset = int(match.group(1), 16) if match.group(1).startswith("0x") else int(match.group(1))
                raw_val = match.group(2)
                val = int(raw_val, 16) if raw_val.startswith("0x") else int(raw_val)
                # Unpack 32-bit dword packed ASCII integers if present
                if val > 255 and val <= 0xFFFFFFFF:
                    packed_bytes = val.to_bytes(4, byteorder="little", signed=False)
                    for idx, b in enumerate(packed_bytes):
                        if 32 <= b <= 126:
                            chars.append((offset + idx, chr(b)))
                elif 32 <= val <= 126:
                    chars.append((offset, chr(val)))
            except ValueError:
                continue
    chars.sort(key=lambda x: x[0])
    return "".join(c[1] for c in chars)


def deobfuscate_xor_buffer(data: bytes | bytearray, key: bytes | bytearray) -> bytes:
    """Deobfuscate a byte buffer using repeated XOR key decryption."""
    if not key or not data:
        return bytes(data)
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))
