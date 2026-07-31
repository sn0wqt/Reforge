"""Bounded Mach-O segment parsing and unslid file-offset mapping."""
from __future__ import annotations

import struct
from dataclasses import dataclass

_THIN_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xcf\xfa\xed\xfe": ("<", True),
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xfe\xed\xfa\xcf": (">", True),
}
_FAT_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
_LC_SEGMENT = 0x1
_LC_SEGMENT_64 = 0x19
_MAX_FAT_SLICES = 64
_MAX_LOAD_COMMANDS = 16_384


@dataclass(frozen=True)
class MachOSegment:
    """One segment's absolute file range and unslid virtual address."""

    file_offset: int
    file_size: int
    virtual_address: int
    name: str


def _u32(data: bytes, offset: int, endian: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("Mach-O integer is out of bounds")
    return int(struct.unpack_from(f"{endian}I", data, offset)[0])


def _parse_thin_slice(
    data: bytes,
    slice_offset: int,
    slice_size: int,
) -> tuple[MachOSegment, ...]:
    if slice_offset < 0 or slice_size < 0 or slice_offset + slice_size > len(data):
        return ()
    magic = data[slice_offset:slice_offset + 4]
    format_info = _THIN_MAGICS.get(magic)
    if format_info is None:
        return ()
    endian, is_64 = format_info
    header_size = 32 if is_64 else 28
    if slice_size < header_size:
        return ()
    try:
        command_count = _u32(data, slice_offset + 16, endian)
        command_bytes = _u32(data, slice_offset + 20, endian)
    except ValueError:
        return ()
    if (
        command_count > _MAX_LOAD_COMMANDS
        or command_bytes > slice_size - header_size
    ):
        return ()

    cursor = slice_offset + header_size
    command_end = cursor + command_bytes
    segments: list[MachOSegment] = []
    for _index in range(command_count):
        if cursor + 8 > command_end:
            return ()
        command = _u32(data, cursor, endian)
        command_size = _u32(data, cursor + 4, endian)
        if command_size < 8 or cursor + command_size > command_end:
            return ()

        try:
            if command == _LC_SEGMENT_64 and command_size >= 72:
                name_bytes = data[cursor + 8:cursor + 24]
                virtual_address, _virtual_size, file_offset, file_size = (
                    int(value)
                    for value in struct.unpack_from(f"{endian}QQQQ", data, cursor + 24)
                )
            elif command == _LC_SEGMENT and command_size >= 56:
                name_bytes = data[cursor + 8:cursor + 24]
                virtual_address, _virtual_size, file_offset, file_size = (
                    int(value)
                    for value in struct.unpack_from(f"{endian}IIII", data, cursor + 24)
                )
            else:
                cursor += command_size
                continue
        except struct.error:
            return ()

        if file_size and file_offset + file_size <= slice_size:
            segments.append(
                MachOSegment(
                    file_offset=slice_offset + file_offset,
                    file_size=file_size,
                    virtual_address=virtual_address,
                    name=name_bytes.split(b"\0", 1)[0].decode(
                        "ascii",
                        errors="replace",
                    ),
                )
            )
        cursor += command_size
    return tuple(segments)


def parse_macho_segments(data: bytes) -> tuple[MachOSegment, ...]:
    """Parse every valid thin/fat slice without applying an ASLR slide."""
    if len(data) < 4:
        return ()
    if data[:4] in _THIN_MAGICS:
        return _parse_thin_slice(data, 0, len(data))
    fat_info = _FAT_MAGICS.get(data[:4])
    if fat_info is None or len(data) < 8:
        return ()
    endian, is_64 = fat_info
    try:
        slice_count = _u32(data, 4, endian)
    except ValueError:
        return ()
    if slice_count > _MAX_FAT_SLICES:
        return ()
    entry_size = 32 if is_64 else 20
    if 8 + slice_count * entry_size > len(data):
        return ()

    segments: list[MachOSegment] = []
    for index in range(slice_count):
        cursor = 8 + index * entry_size
        try:
            if is_64:
                _cpu, _subtype, offset, size, _align, _reserved = (
                    int(value)
                    for value in struct.unpack_from(f"{endian}IIQQII", data, cursor)
                )
            else:
                _cpu, _subtype, offset, size, _align = (
                    int(value)
                    for value in struct.unpack_from(f"{endian}IIIII", data, cursor)
                )
        except struct.error:
            return ()
        segments.extend(_parse_thin_slice(data, offset, size))
    return tuple(segments)


def macho_vm_address_for_file_offset(data: bytes, file_offset: int) -> int | None:
    """Map an absolute file offset to an unslid Mach-O virtual address."""
    if file_offset < 0:
        return None
    for segment in parse_macho_segments(data):
        if segment.file_offset <= file_offset < segment.file_offset + segment.file_size:
            return segment.virtual_address + (file_offset - segment.file_offset)
    return None
