"""Unit tests for the pure-Python static binary security mitigation scanner."""

from __future__ import annotations

import struct
from pathlib import Path

from reforge.core.scanners.mitigation_scanner import (
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
    IMAGE_DLLCHARACTERISTICS_NO_SEH,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    LC_CODE_SIGNATURE,
    LC_RPATH,
    LC_SEGMENT_64,
    LC_SYMTAB,
    MH_ALLOW_STACK_EXECUTION,
    MH_PIE,
    PF_R,
    PF_W,
    PF_X,
    PT_DYNAMIC,
    PT_GNU_RELRO,
    PT_GNU_STACK,
    PT_LOAD,
    MitigationScanner,
)

# =============================================================================
# Helper Builders for Synthetic Binaries
# =============================================================================


def build_synthetic_elf64(
    *,
    is_pie: bool = True,
    has_gnu_stack: bool = True,
    stack_executable: bool = False,
    relro_mode: str = "full",  # "full", "partial", "none"
    canary: bool = True,
    fortify: bool = True,
    rpath: str | None = None,
    runpath: str | None = None,
) -> bytes:
    """Build a minimal valid 64-bit little-endian ELF binary with specified mitigations."""
    data = bytearray()
    endian = "<"

    # 1. ELF Header (64 bytes)
    e_type = 3 if is_pie else 2  # ET_DYN vs ET_EXEC
    e_machine = 62  # EM_X86_64
    e_phoff = 64
    e_phentsize = 56
    e_phnum = 4  # PT_LOAD, PT_DYNAMIC, PT_GNU_STACK (optional), PT_GNU_RELRO (optional)
    if not has_gnu_stack:
        e_phnum -= 1
    if relro_mode == "none":
        e_phnum -= 1

    # Placeholder for e_shoff, e_shentsize, e_shnum, e_shstrndx
    data.extend(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
    data.extend(
        struct.pack(
            f"{endian}HHIQQQIHHHHHH",
            e_type,
            e_machine,
            1,
            0x1000,
            e_phoff,
            0,
            0,
            64,
            e_phentsize,
            e_phnum,
            64,
            0,
            0,
        )
    )
    assert len(data) == 64

    # Space for program headers
    ph_table_offset = len(data)
    ph_bytes = e_phnum * e_phentsize
    data.extend(b"\x00" * ph_bytes)

    # 2. Dynamic section (PT_DYNAMIC)
    dyn_offset = len(data)
    dyn_entries: list[tuple[int, int]] = []
    if relro_mode == "full":
        dyn_entries.append((24, 0))  # DT_BIND_NOW
    elif relro_mode == "partial":
        dyn_entries.append((30, 0))  # DT_FLAGS (no DF_BIND_NOW)

    strtab_data = bytearray(b"\x00")
    if rpath:
        off = len(strtab_data)
        strtab_data.extend(rpath.encode("utf-8") + b"\x00")
        dyn_entries.append((15, off))  # DT_RPATH
    if runpath:
        off = len(strtab_data)
        strtab_data.extend(runpath.encode("utf-8") + b"\x00")
        dyn_entries.append((29, off))  # DT_RUNPATH

    # Append DT_STRTAB and DT_STRSZ
    dyn_entries.append((10, 0))  # DT_STRSZ placeholder
    dyn_entries.append((5, 0))  # DT_STRTAB placeholder
    dyn_entries.append((0, 0))  # DT_NULL

    # Write dynamic entries
    dyn_start = len(data)
    for tag, val in dyn_entries:
        data.extend(struct.pack(f"{endian}QQ", tag, val))
    dyn_size = len(data) - dyn_start

    # Write STRTAB
    strtab_file_offset = len(data)
    data.extend(strtab_data)
    strtab_size = len(strtab_data)

    # Fixup DT_STRTAB and DT_STRSZ in dynamic table
    dt_strsz_pos = dyn_start + (len(dyn_entries) - 3) * 16
    struct.pack_into(f"{endian}QQ", data, dt_strsz_pos, 10, strtab_size)
    dt_strtab_pos = dyn_start + (len(dyn_entries) - 2) * 16
    struct.pack_into(f"{endian}QQ", data, dt_strtab_pos, 5, strtab_file_offset)

    # 3. Symbol Table (.dynsym) and String Table (.dynstr)
    sym_strtab = bytearray(b"\x00")
    symbols: list[tuple[int, int]] = [(0, 0)]  # STN_UNDEF

    if canary:
        canary_off = len(sym_strtab)
        sym_strtab.extend(b"__stack_chk_fail\x00")
        symbols.append((canary_off, 0x12))
    if fortify:
        fortify_off = len(sym_strtab)
        sym_strtab.extend(b"__snprintf_chk\x00")
        symbols.append((fortify_off, 0x12))

    symtab_offset = len(data)
    for st_name, st_info in symbols:
        # Elf64_Sym: st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
        data.extend(struct.pack(f"{endian}IBBHQQ", st_name, st_info, 0, 0, 0, 0))
    symtab_size = len(data) - symtab_offset

    sym_strtab_offset = len(data)
    data.extend(sym_strtab)
    sym_strtab_size = len(sym_strtab)

    # 4. Section headers
    sh_offset = len(data)
    # Section 0: NULL
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        # Section 1: .dynsym (SHT_DYNSYM = 11, link=2 -> .dynstr)
        (0, 11, 2, 0, symtab_offset, symtab_size, 2, 1, 8, 24),
        # Section 2: .dynstr (SHT_STRTAB = 3)
        (0, 3, 2, 0, sym_strtab_offset, sym_strtab_size, 0, 0, 1, 0),
    ]
    for s_entry in sections:
        data.extend(struct.pack(f"{endian}IIQQQQIIQQ", *s_entry))
    sh_num = len(sections)

    # Fixup ELF header section table fields
    struct.pack_into(f"{endian}Q", data, 40, sh_offset)
    struct.pack_into(f"{endian}H", data, 60, sh_num)

    # 5. Populate Program Headers
    cursor = ph_table_offset

    # Phdr 0: PT_LOAD covering whole file
    data[cursor : cursor + e_phentsize] = struct.pack(
        f"{endian}IIQQQQQQ",
        PT_LOAD,
        PF_R | PF_W | PF_X,
        0,
        0,
        0,
        len(data),
        len(data),
        0x1000,
    )
    cursor += e_phentsize

    # Phdr 1: PT_DYNAMIC
    data[cursor : cursor + e_phentsize] = struct.pack(
        f"{endian}IIQQQQQQ",
        PT_DYNAMIC,
        PF_R | PF_W,
        dyn_offset,
        dyn_offset,
        dyn_offset,
        dyn_size,
        dyn_size,
        8,
    )
    cursor += e_phentsize

    if has_gnu_stack:
        flags = PF_R | PF_W | (PF_X if stack_executable else 0)
        data[cursor : cursor + e_phentsize] = struct.pack(
            f"{endian}IIQQQQQQ",
            PT_GNU_STACK,
            flags,
            0,
            0,
            0,
            0,
            0,
            8,
        )
        cursor += e_phentsize

    if relro_mode in ("full", "partial"):
        data[cursor : cursor + e_phentsize] = struct.pack(
            f"{endian}IIQQQQQQ",
            PT_GNU_RELRO,
            PF_R,
            dyn_offset,
            dyn_offset,
            dyn_offset,
            dyn_size,
            dyn_size,
            1,
        )
        cursor += e_phentsize

    return bytes(data)


def build_synthetic_pe(
    *,
    is_64: bool = True,
    aslr: bool = True,
    high_entropy: bool = True,
    dep: bool = True,
    cfg: bool = True,
    safeseh: bool = True,
    no_seh: bool = False,
    canary: bool = True,
    authenticode: bool = True,
) -> bytes:
    """Build a minimal valid PE32 or PE32+ executable with specified mitigations."""
    data = bytearray()
    endian = "<"

    # DOS Header (64 bytes)
    e_lfanew = 128
    dos_header = bytearray(b"MZ" + b"\x00" * 58)
    dos_header.extend(struct.pack(f"{endian}I", e_lfanew))
    assert len(dos_header) == 64
    data.extend(dos_header)
    data.extend(b"\x00" * 64)  # Padding to e_lfanew

    # PE Signature (4 bytes)
    assert len(data) == e_lfanew
    data.extend(b"PE\x00\x00")

    # COFF File Header (20 bytes)
    machine = 0x8664 if is_64 else 0x14C
    num_sections = 1
    size_of_opt = 240 if is_64 else 224
    characteristics = 0x0002  # IMAGE_FILE_EXECUTABLE_IMAGE (relocs not stripped)
    data.extend(struct.pack(f"{endian}HHIIIHH", machine, num_sections, 0, 0, 0, size_of_opt, characteristics))

    # Optional Header
    opt_magic = 0x20B if is_64 else 0x10B
    dll_characteristics = 0
    if aslr:
        dll_characteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    if high_entropy and is_64:
        dll_characteristics |= IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
    if dep:
        dll_characteristics |= IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    if cfg:
        dll_characteristics |= IMAGE_DLLCHARACTERISTICS_GUARD_CF
    if no_seh:
        dll_characteristics |= IMAGE_DLLCHARACTERISTICS_NO_SEH

    num_rva_and_sizes = 16
    opt_start = len(data)
    data.extend(struct.pack(f"{endian}H", opt_magic))
    data.extend(b"\x00" * 68)  # Skip to DllCharacteristics at offset 70
    data.extend(struct.pack(f"{endian}H", dll_characteristics))
    data.extend(b"\x00" * (20 if not is_64 else 36))  # Skip to NumberOfRvaAndSizes
    data.extend(struct.pack(f"{endian}I", num_rva_and_sizes))

    # Data Directories (16 entries * 8 bytes = 128 bytes)
    dd_offset = len(data)
    data.extend(b"\x00" * (16 * 8))
    # Pad remainder of optional header
    opt_used = len(data) - opt_start
    if opt_used < size_of_opt:
        data.extend(b"\x00" * (size_of_opt - opt_used))

    # Section Table: 1 section (.rdata)
    rdata_vaddr = 0x1000
    rdata_vsize = 0x1000
    rdata_raw_off = 0x400
    rdata_raw_sz = 0x400
    data.extend(b".rdata\x00\x00")
    data.extend(
        struct.pack(
            f"{endian}IIIIIIHHI",
            rdata_vsize,
            rdata_vaddr,
            rdata_raw_sz,
            rdata_raw_off,
            0,
            0,
            0,
            0,
            0x40000040,
        )
    )

    # Pad until section raw data offset
    if len(data) < rdata_raw_off:
        data.extend(b"\x00" * (rdata_raw_off - len(data)))

    # Inside .rdata: Load Config Directory
    load_cfg_file_off = len(data)
    load_cfg_rva = rdata_vaddr + (load_cfg_file_off - rdata_raw_off)

    if not is_64:
        # IMAGE_LOAD_CONFIG_DIRECTORY32: size >= 72
        cfg_size = 72
        sec_cookie = 0x12345678 if canary else 0
        se_table = 0x1000 if (safeseh and not no_seh) else 0
        se_count = 1 if (safeseh and not no_seh) else 0
        cfg_blob = bytearray(b"\x00" * cfg_size)
        struct.pack_into(f"{endian}I", cfg_blob, 0, cfg_size)
        struct.pack_into(f"{endian}I", cfg_blob, 60, sec_cookie)
        struct.pack_into(f"{endian}II", cfg_blob, 64, se_table, se_count)
        data.extend(cfg_blob)
    else:
        # IMAGE_LOAD_CONFIG_DIRECTORY64: size >= 96
        cfg_size = 96
        sec_cookie = 0x1234567890ABCDEF if canary else 0
        cfg_blob = bytearray(b"\x00" * cfg_size)
        struct.pack_into(f"{endian}I", cfg_blob, 0, cfg_size)
        struct.pack_into(f"{endian}Q", cfg_blob, 88, sec_cookie)
        data.extend(cfg_blob)

    load_cfg_len = cfg_size

    # Fixup Data Directories:
    # Directory 10: Load Config
    struct.pack_into(f"{endian}II", data, dd_offset + 10 * 8, load_cfg_rva, load_cfg_len)

    # Directory 4: Security / Authenticode (direct file offset)
    if authenticode:
        cert_file_off = len(data)
        cert_len = 64
        data.extend(b"\x00" * cert_len)
        struct.pack_into(f"{endian}II", data, dd_offset + 4 * 8, cert_file_off, cert_len)

    return bytes(data)


def build_synthetic_macho(
    *,
    is_64: bool = True,
    pie: bool = True,
    allow_stack_exec: bool = False,
    rpaths: list[str] | None = None,
    canary: bool = True,
    fortify: bool = True,
    has_signature: bool = True,
    restrict: bool = False,
) -> bytes:
    """Build a minimal valid thin Mach-O binary with specified mitigations."""
    data = bytearray()
    endian = "<"

    magic = 0xFEEDFACF if is_64 else 0xFEEDFACE
    cputype = 0x0100000C if is_64 else 12  # arm64 or arm
    cpusubtype = 0
    filetype = 2  # MH_EXECUTE
    flags = 0
    if pie:
        flags |= MH_PIE
    if allow_stack_exec:
        flags |= MH_ALLOW_STACK_EXECUTION

    header_size = 32 if is_64 else 28
    data.extend(struct.pack(f"{endian}IIIIIII", magic, cputype, cpusubtype, filetype, 0, 0, flags))
    if is_64:
        data.extend(b"\x00\x00\x00\x00")  # reserved
    assert len(data) == header_size

    ncmds = 0
    cmd_start = len(data)

    # 1. LC_RPATH
    if rpaths:
        for rpath in rpaths:
            ncmds += 1
            cmd_payload = bytearray(struct.pack(f"{endian}III", LC_RPATH, 0, 12))  # str_offset = 12
            cmd_payload.extend(rpath.encode("utf-8") + b"\x00")
            # 8-byte alignment
            pad = (8 - (len(cmd_payload) % 8)) % 8
            cmd_payload.extend(b"\x00" * pad)
            struct.pack_into(f"{endian}I", cmd_payload, 4, len(cmd_payload))
            data.extend(cmd_payload)

    # 2. LC_CODE_SIGNATURE
    if has_signature:
        ncmds += 1
        data.extend(struct.pack(f"{endian}IIII", LC_CODE_SIGNATURE, 16, 0x1000, 0x200))

    # 3. LC_SEGMENT_64 with __RESTRICT
    if restrict and is_64:
        ncmds += 1
        seg_data = bytearray(struct.pack(f"{endian}II", LC_SEGMENT_64, 72))
        seg_name = b"__RESTRICT" + b"\x00" * 6
        seg_data.extend(seg_name)
        seg_data.extend(b"\x00" * 48)
        data.extend(seg_data)

    # 4. LC_SYMTAB with stack canary and fortify symbols
    if canary or fortify:
        ncmds += 1
        sym_strtab = bytearray(b"\x00")
        symbols: list[int] = []
        if canary:
            symbols.append(len(sym_strtab))
            sym_strtab.extend(b"___stack_chk_fail\x00")
        if fortify:
            symbols.append(len(sym_strtab))
            sym_strtab.extend(b"__sprintf_chk\x00")

        # Reserve space for load command (24 bytes)
        lc_symtab_off = len(data)
        data.extend(b"\x00" * 24)

        # Write symbol entries and string table
        symoff = len(data)
        for strx in symbols:
            # nlist_64: n_strx(4), n_type(1), n_sect(1), n_desc(2), n_value(8)
            if is_64:
                data.extend(struct.pack(f"{endian}IBBHQ", strx, 0x01, 1, 0, 0))
            else:
                data.extend(struct.pack(f"{endian}IBBHI", strx, 0x01, 1, 0, 0))
        nsyms = len(symbols)

        stroff = len(data)
        strsize = len(sym_strtab)
        data.extend(sym_strtab)

        # Write LC_SYMTAB
        struct.pack_into(f"{endian}IIIIII", data, lc_symtab_off, LC_SYMTAB, 24, symoff, nsyms, stroff, strsize)

    sizeofcmds = len(data) - cmd_start

    # Fixup header ncmds and sizeofcmds
    struct.pack_into(f"{endian}II", data, 16, ncmds, sizeofcmds)
    return bytes(data)


# =============================================================================
# Tests
# =============================================================================


def test_elf_full_hardening() -> None:
    blob = build_synthetic_elf64(
        is_pie=True,
        has_gnu_stack=True,
        stack_executable=False,
        relro_mode="full",
        canary=True,
        fortify=True,
        rpath="/opt/app/lib",
        runpath="/opt/app/run",
    )
    report = MitigationScanner.scan_bytes(blob)
    assert report.format == "elf"
    assert report.bits == 64
    assert report.architecture == "x86_64"
    assert report.pie is True
    assert report.nx is True
    assert report.stack_canary is True
    assert report.relro == "Full"
    assert report.fortify is True
    assert "/opt/app/lib" in report.rpath
    assert "/opt/app/run" in report.runpath

    # Verify notes formatting
    notes_str = " ".join(report.notes)
    assert "PIE/ASLR: enabled" in notes_str
    assert "NX/DEP: enabled" in notes_str
    assert "Stack Canary: detected" in notes_str
    assert "RELRO: Full" in notes_str
    assert "FORTIFY: detected" in notes_str
    assert "RPATH: /opt/app/lib" in notes_str


def test_elf_plain_unhardened() -> None:
    blob = build_synthetic_elf64(
        is_pie=False,
        has_gnu_stack=True,
        stack_executable=True,
        relro_mode="none",
        canary=False,
        fortify=False,
    )
    report = MitigationScanner.scan_bytes(blob)
    assert report.format == "elf"
    assert report.pie is False
    assert report.nx is False
    assert report.stack_canary is False
    assert report.relro == "None"
    assert report.fortify is False
    assert report.details["executable_stack"] is True


def test_elf_partial_relro_no_gnu_stack() -> None:
    blob = build_synthetic_elf64(
        is_pie=True,
        has_gnu_stack=False,
        relro_mode="partial",
        canary=False,
        fortify=False,
    )
    report = MitigationScanner.scan_bytes(blob)
    assert report.format == "elf"
    assert report.pie is True
    assert report.nx is None  # Unknown because PT_GNU_STACK is absent
    assert report.relro == "Partial"
    assert report.details["gnu_stack"] == "absent"


def test_pe64_full_hardening() -> None:
    blob = build_synthetic_pe(
        is_64=True,
        aslr=True,
        high_entropy=True,
        dep=True,
        cfg=True,
        canary=True,
        authenticode=True,
    )
    report = MitigationScanner.scan_bytes(blob)
    assert report.format == "pe"
    assert report.bits == 64
    assert report.architecture == "x86_64"
    assert report.pie is True
    assert report.nx is True
    assert report.cfg is True
    assert report.stack_canary is True
    assert report.code_signature is True
    assert report.safeseh is None  # x64 does not use SafeSEH
    assert report.details["high_entropy_va"] is True

    # Check summary_dict
    s_dict = report.summary_dict
    assert s_dict["pie"] is True
    assert s_dict["nx"] is True
    assert s_dict["cfg"] is True


def test_pe32_safeseh() -> None:
    blob = build_synthetic_pe(
        is_64=False,
        aslr=True,
        dep=True,
        cfg=False,
        safeseh=True,
        no_seh=False,
        canary=True,
        authenticode=False,
    )
    report = MitigationScanner.scan_bytes(blob)
    assert report.format == "pe"
    assert report.bits == 32
    assert report.architecture == "x86"
    assert report.pie is True
    assert report.nx is True
    assert report.safeseh is True
    assert report.stack_canary is True
    assert report.code_signature is False


def test_pe32_no_seh_flag() -> None:
    blob = build_synthetic_pe(
        is_64=False,
        aslr=False,
        dep=False,
        cfg=False,
        safeseh=False,
        no_seh=True,
        canary=False,
        authenticode=False,
    )
    report = MitigationScanner.scan_bytes(blob)
    assert report.format == "pe"
    assert report.pie is False
    assert report.nx is False
    assert report.safeseh is True  # IMAGE_DLLCHARACTERISTICS_NO_SEH is safe against SEH attacks
    assert report.details["no_seh"] is True


def test_macho64_hardened() -> None:
    blob = build_synthetic_macho(
        is_64=True,
        pie=True,
        allow_stack_exec=False,
        rpaths=["@loader_path/../Frameworks"],
        canary=True,
        fortify=True,
        has_signature=True,
        restrict=True,
    )
    report = MitigationScanner.scan_bytes(blob)
    assert report.format == "macho"
    assert report.bits == 64
    assert report.architecture == "arm64"
    assert report.pie is True
    assert report.nx is True
    assert report.stack_canary is True
    assert report.fortify is True
    assert report.code_signature is True
    assert "@loader_path/../Frameworks" in report.rpath
    assert report.details["restrict_segment"] is True


def test_macho_executable_stack() -> None:
    blob = build_synthetic_macho(
        is_64=True,
        pie=False,
        allow_stack_exec=True,
        canary=False,
        fortify=False,
        has_signature=False,
        restrict=False,
    )
    report = MitigationScanner.scan_bytes(blob)
    assert report.format == "macho"
    assert report.pie is False
    assert report.nx is False
    assert report.stack_canary is False


def test_macho_fat_slice_selection() -> None:
    arm64_slice = build_synthetic_macho(is_64=True, pie=True, allow_stack_exec=False, canary=True)
    fat_header = bytearray(b"\xca\xfe\xba\xbe" + struct.pack(">I", 1))  # 1 slice
    # Fat arch entry (20 bytes big endian): cputype(0x0100000C), cpusubtype(0), offset(4096), size, align(14)
    slice_offset = 4096
    fat_header.extend(struct.pack(">IIIII", 0x0100000C, 0, slice_offset, len(arm64_slice), 14))
    fat_header.extend(b"\x00" * (slice_offset - len(fat_header)))
    fat_binary = bytes(fat_header) + arm64_slice

    report = MitigationScanner.scan_bytes(fat_binary)
    assert report.format == "macho"
    assert report.architecture == "arm64"
    assert report.pie is True
    assert report.nx is True
    assert report.stack_canary is True


def test_scan_file_and_errors(tmp_path: Path) -> None:
    elf_blob = build_synthetic_elf64(is_pie=True)
    p = tmp_path / "test.elf"
    p.write_bytes(elf_blob)

    report = MitigationScanner.scan_file(p)
    assert report is not None
    assert report.format == "elf"
    assert report.pie is True

    # Non-existent file
    assert MitigationScanner.scan_file(tmp_path / "missing.bin") is None

    # Truncated data
    short_report = MitigationScanner.scan_bytes(b"\x7fELF\x02\x01")
    assert short_report.format == "elf"
    assert len(short_report.limitations) > 0

    # Random data
    rnd_report = MitigationScanner.scan_bytes(b"RANDOM_NON_BINARY_DATA_HERE")
    assert rnd_report.format == "unknown"
