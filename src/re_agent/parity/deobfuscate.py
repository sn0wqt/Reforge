"""De-obfuscation heuristics for string encryption and constant unpacking in P-code evidence."""

from __future__ import annotations

import re
from typing import Any


def detect_xor_loops(pcode_lines: list[str]) -> list[dict[str, Any]]:
    """Scan P-code lines for XOR decryption loop patterns (e.g., XOR, INT_XOR operations in loops)."""
    results: list[dict[str, Any]] = []
    xor_pattern = re.compile(r"(?:INT_XOR|XOR|xor)\b", re.IGNORECASE)
    loop_pattern = re.compile(r"(?:BRANCH|CBRANCH|goto|while)\b", re.IGNORECASE)

    has_loop = any(loop_pattern.search(line) for line in pcode_lines)
    for idx, line in enumerate(pcode_lines):
        if xor_pattern.search(line):
            results.append(
                {
                    "line_index": idx,
                    "line": line.strip(),
                    "in_loop": has_loop,
                    "type": "xor_op",
                }
            )
    return results


def detect_stack_strings(assembly_lines: list[str]) -> list[dict[str, Any]]:
    """Scan assembly lines for stack string construction (byte and 32-bit dword assignments)."""
    stack_string_entries: list[dict[str, Any]] = []
    mov_stack_pattern = re.compile(
        r"(?:mov|str|movb|movl|movw)\b.*"
        r"\[(?:rsp|rbp|sp|x\d+|r\d+)\s*[\+\-]\s*"
        r"(?:0x[0-9a-fA-F]+|\d+)\],\s*(0x[0-9a-fA-F]+|\d+)",
        re.IGNORECASE,
    )

    for idx, line in enumerate(assembly_lines):
        match = mov_stack_pattern.search(line)
        if match:
            raw_val = match.group(1)
            try:
                val = int(raw_val, 0)
                # Handle 32-bit dword packed ASCII (little endian 4 bytes)
                if val > 255 and val <= 0xFFFFFFFF:
                    b0 = val & 0xFF
                    b1 = (val >> 8) & 0xFF
                    b2 = (val >> 16) & 0xFF
                    b3 = (val >> 24) & 0xFF
                    for b in (b0, b1, b2, b3):
                        if b != 0:
                            stack_string_entries.append(
                                {
                                    "line_index": idx,
                                    "line": line.strip(),
                                    "value": hex(b),
                                }
                            )
                else:
                    stack_string_entries.append(
                        {
                            "line_index": idx,
                            "line": line.strip(),
                            "value": raw_val,
                        }
                    )
            except (ValueError, TypeError):
                continue

    return stack_string_entries


def reconstruct_stack_strings(assembly_lines: list[str]) -> list[str]:
    """Reconstruct ASCII strings constructed on the stack via sequential MOV byte instructions."""
    entries = detect_stack_strings(assembly_lines)
    if not entries:
        return []

    chars: list[str] = []
    for entry in entries:
        try:
            val = int(entry["value"], 0)
            if 32 <= val <= 126:
                chars.append(chr(val))
            elif val == 0 and chars:
                chars.append("\0")
        except (ValueError, TypeError):
            continue

    raw_str = "".join(chars)
    # Split on null terminators and filter strings >= 3 chars
    extracted = [s.strip() for s in raw_str.split("\0") if len(s.strip()) >= 3]
    return extracted


def deobfuscate_xor_buffer(data: bytes | bytearray, key: bytes | bytearray) -> bytes:
    """Deobfuscate a byte buffer using repeated XOR key decryption."""
    if not key or not data:
        return bytes(data)
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))
