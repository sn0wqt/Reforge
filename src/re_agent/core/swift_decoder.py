"""ARM64 Swift String Decoder & Inspection Module.

Extracts Swift strings from Mach-O binaries by decoding ARM64 instruction sequences
(ADR/SUB #0x20, ADRP/ADD page-based addressing, and inline small strings).
"""

from __future__ import annotations

import logging
import struct
from typing import Any

logger = logging.getLogger(__name__)

SWIFT_SMALL_STRING_FLAG = 0xF000000000000000


def decode_swift_small_string(value: int) -> str | None:
    """Decode Swift bit-packed small/inline string from 64-bit register value."""
    try:
        clean_val = value & 0x0FFFFFFFFFFFFFFF
        result: list[str] = []
        for i in range(7):
            byte = (clean_val >> (i * 8)) & 0xFF
            if byte == 0:
                break
            if 0x20 <= byte <= 0x7E:
                result.append(chr(byte))
        return "".join(result) if result else None
    except Exception:
        return None


def extract_swift_strings_from_bytes(
    data: bytes,
    base_address: int | None = None,
) -> list[dict[str, Any]]:
    """Scan bytes for printable and length-prefixed string evidence.

    This function does not decode ARM64 instructions. ``base_address`` is
    retained only for backwards-compatible callers; Mach-O scanners should
    map offsets through load-command segments instead.
    """
    results: list[dict[str, Any]] = []

    # 1. Null-terminated ASCII/UTF-8 strings with Swift mangled symbol detection ($s, _$s)
    current: list[str] = []
    start_offset = 0

    for i, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if not current:
                start_offset = i
            current.append(chr(byte))
        else:
            if len(current) >= 4:
                s_val = "".join(current).strip()
                if s_val:
                    is_swift_symbol = s_val.startswith(("$s", "_$s"))
                    result = {
                        "offset": start_offset,
                        "string": s_val,
                        "type": "swift_symbol" if is_swift_symbol else "c_string",
                    }
                    if base_address is not None:
                        result["virtual_address"] = hex(base_address + start_offset)
                    results.append(result)
            current = []

    if len(current) >= 4:
        s_val = "".join(current).strip()
        if s_val:
            result = {
                "offset": start_offset,
                "string": s_val,
                "type": "c_string",
            }
            if base_address is not None:
                result["virtual_address"] = hex(base_address + start_offset)
            results.append(result)

    # 2. Length-prefixed Swift / Unity asset strings (uint32 len followed by UTF-8 bytes)
    for i in range(0, max(0, len(data) - 8), 4):
        try:
            length = struct.unpack("<I", data[i : i + 4])[0]
            if 4 <= length <= 256:
                str_bytes = data[i + 4 : i + 4 + length]
                if len(str_bytes) == length and all(0x20 <= b <= 0x7E for b in str_bytes):
                    decoded = str_bytes.decode("utf-8", errors="ignore").strip()
                    if decoded and len(decoded) >= 4:
                        result = {
                            "offset": i + 4,
                            "string": decoded,
                            "type": "length_prefixed",
                        }
                        if base_address is not None:
                            result["virtual_address"] = hex(base_address + i + 4)
                        results.append(result)
        except Exception:
            continue

    return results
