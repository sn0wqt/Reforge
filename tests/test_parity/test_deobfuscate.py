"""Unit tests for de-obfuscation heuristics."""
from __future__ import annotations

from re_agent.parity.deobfuscate import deobfuscate_xor_buffer, detect_stack_strings, detect_xor_loops


def test_detect_xor_loops() -> None:
    pcode_lines = [
        "uVar1 = INT_XOR r0, r1",
        "CBRANCH lab_100, uVar1",
    ]
    results = detect_xor_loops(pcode_lines)
    assert len(results) == 1
    assert results[0]["in_loop"] is True


def test_detect_stack_strings() -> None:
    assembly = [
        "mov [rsp+0x10], 0x41",
        "mov [rsp+0x14], 0x42",
    ]
    entries = detect_stack_strings(assembly)
    assert len(entries) == 2
    assert entries[0]["value"] == "0x41"


def test_detect_stack_strings_with_decimal_stack_offset() -> None:
    entries = detect_stack_strings(["mov [rsp+16], 65"])

    assert len(entries) == 1
    assert entries[0]["value"] == "65"


def test_deobfuscate_xor_buffer() -> None:
    plaintext = b"Hello World"
    key = b"\x5A"
    encrypted = bytes(b ^ 0x5A for b in plaintext)
    decrypted = deobfuscate_xor_buffer(encrypted, key)
    assert decrypted == plaintext


def test_reconstruct_stack_strings_single_bytes() -> None:
    from re_agent.parity.deobfuscate import reconstruct_stack_strings

    asm = [
        "mov [rsp+0x10], 0x63",  # 'c'
        "mov [rsp+0x11], 0x6F",  # 'o'
        "mov [rsp+0x12], 0x69",  # 'i'
        "mov [rsp+0x13], 0x6E",  # 'n'
    ]
    res = reconstruct_stack_strings(asm)
    assert res == "coin"


def test_reconstruct_stack_strings_dword_packed() -> None:
    from re_agent.parity.deobfuscate import reconstruct_stack_strings

    # 0x6E696F63 in little endian -> 'c', 'o', 'i', 'n'
    asm = ["mov [rsp+0x20], 0x6E696F63"]
    res = reconstruct_stack_strings(asm)
    assert res == "coin"
