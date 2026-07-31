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
            results.append({
                "line_index": idx,
                "line": line.strip(),
                "in_loop": has_loop,
                "type": "xor_op",
            })
    return results


def detect_stack_strings(assembly_lines: list[str]) -> list[dict[str, Any]]:
    """Scan assembly lines for stack string construction (e.g. MOV [RBP+...], byte/dword)."""
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
            stack_string_entries.append({
                "line_index": idx,
                "line": line.strip(),
                "value": match.group(1),
            })
    return stack_string_entries


def deobfuscate_xor_buffer(data: bytes | bytearray, key: bytes | bytearray) -> bytes:
    """Deobfuscate a byte buffer using repeated XOR key decryption."""
    if not key or not data:
        return bytes(data)
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))
