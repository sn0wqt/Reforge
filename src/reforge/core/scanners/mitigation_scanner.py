"""Pure-Python static binary security mitigation scanner for ELF, PE, and Mach-O."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Magic bytes
ELF_MAGIC = b"\x7fELF"
DOS_MAGIC = b"MZ"
PE_MAGIC = b"PE\x00\x00"

# Mach-O magics
MACHO_THIN_32_BE = b"\xfe\xed\xfa\xce"
MACHO_THIN_32_LE = b"\xce\xfa\xed\xfe"
MACHO_THIN_64_BE = b"\xfe\xed\xfa\xcf"
MACHO_THIN_64_LE = b"\xcf\xfa\xed\xfe"
MACHO_FAT_BE = b"\xca\xfe\xba\xbe"
MACHO_FAT_LE = b"\xbe\xba\xfe\xca"
MACHO_FAT_64_BE = b"\xca\xfe\xba\xbf"
MACHO_FAT_64_LE = b"\xbf\xba\xfe\xca"

# ELF constants
PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

DT_NULL = 0
DT_STRTAB = 5
DT_STRSZ = 10
DT_RPATH = 15
DT_RUNPATH = 29
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11

CANARY_SYMBOLS = {
    "__stack_chk_fail",
    "__stack_chk_guard",
    "__intel_security_cookie",
    "___stack_chk_fail",
    "___stack_chk_guard",
    "__security_check_cookie",
    "__security_cookie",
}

FORTIFY_PREFIXES = (
    "__memcpy_chk",
    "__memmove_chk",
    "__memset_chk",
    "__strcpy_chk",
    "__strncpy_chk",
    "__strcat_chk",
    "__strncat_chk",
    "__sprintf_chk",
    "__snprintf_chk",
    "__vsprintf_chk",
    "__vsnprintf_chk",
    "__printf_chk",
    "__fprintf_chk",
    "__vprintf_chk",
    "__vfprintf_chk",
    "__read_chk",
    "__pread_chk",
)

# PE DllCharacteristics
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
IMAGE_FILE_RELOCS_STRIPPED = 0x0001

# Mach-O header flags
MH_PIE = 0x00200000
MH_ALLOW_STACK_EXECUTION = 0x00020000
MH_NO_HEAP_EXECUTION = 0x01000000

# Mach-O load commands
LC_SEGMENT = 0x01
LC_SYMTAB = 0x02
LC_SEGMENT_64 = 0x19
LC_RPATH = 0x1C
LC_RPATH_REQ = 0x8000001C
LC_CODE_SIGNATURE = 0x1D
LC_LOAD_DYLIB = 0x0C

MAX_SYMBOLS_TO_SCAN = 100_000


@dataclass(frozen=True)
class MitigationReport:
    """Security mitigation scan results for a single binary."""

    format: str
    architecture: str
    bits: int
    endian: str
    pie: bool | None = None
    nx: bool | None = None
    stack_canary: bool | None = None
    relro: str | None = None
    cfg: bool | None = None
    safeseh: bool | None = None
    code_signature: bool | None = None
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()
    fortify: bool | None = None
    details: dict[str, Any] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()

    @property
    def notes(self) -> tuple[str, ...]:
        """Human-readable bullet points summarizing mitigations."""
        items: list[str] = [f"format: {self.format.upper()}{self.bits} ({self.architecture}, {self.endian}-endian)"]
        if self.pie is not None:
            items.append(f"PIE/ASLR: {'enabled' if self.pie else 'disabled'}")
        if self.nx is not None:
            items.append(f"NX/DEP: {'enabled' if self.nx else 'disabled'}")
        if self.stack_canary is not None:
            items.append(f"Stack Canary: {'detected' if self.stack_canary else 'not detected'}")
        if self.relro is not None:
            items.append(f"RELRO: {self.relro}")
        if self.cfg is not None:
            items.append(f"Control Flow Guard: {'enabled' if self.cfg else 'disabled'}")
        if self.safeseh is not None:
            items.append(f"SafeSEH: {'enabled' if self.safeseh else 'disabled'}")
        elif self.format == "pe" and self.bits == 64:
            items.append("SafeSEH: N/A (x64 table-based exception handling)")
        if self.fortify is not None:
            items.append(f"FORTIFY: {'detected' if self.fortify else 'not detected'}")
        if self.rpath:
            items.append(f"RPATH: {':'.join(self.rpath)}")
        if self.runpath:
            items.append(f"RUNPATH: {':'.join(self.runpath)}")
        if self.code_signature is not None:
            items.append(f"Code Signature: {'present' if self.code_signature else 'absent'}")
        if self.limitations:
            items.append(f"limitations: {'; '.join(self.limitations)}")
        return tuple(items)

    @property
    def summary_dict(self) -> dict[str, Any]:
        """Convert report to dictionary suitable for JSON serialization."""
        return {
            "format": self.format,
            "architecture": self.architecture,
            "bits": self.bits,
            "endian": self.endian,
            "pie": self.pie,
            "nx": self.nx,
            "stack_canary": self.stack_canary,
            "relro": self.relro,
            "cfg": self.cfg,
            "safeseh": self.safeseh,
            "code_signature": self.code_signature,
            "rpath": list(self.rpath),
            "runpath": list(self.runpath),
            "fortify": self.fortify,
            "details": self.details,
            "limitations": list(self.limitations),
        }


class MitigationScanner:
    """Pure-Python static parser for binary security mitigations across ELF, PE, and Mach-O."""

    @classmethod
    def scan_file(cls, path: str | Path, max_bytes: int = 64 * 1024 * 1024) -> MitigationReport | None:
        """Scan a binary file on disk for security mitigations."""
        p = Path(path)
        if not p.is_file():
            return None
        try:
            with p.open("rb") as f:
                data = f.read(max_bytes)
            return cls.scan_bytes(data, filename=p.name)
        except OSError:
            return None

    @classmethod
    def scan_bytes(cls, data: bytes, filename: str | None = None) -> MitigationReport:
        """Inspect binary bytes and return security mitigation analysis."""
        if len(data) < 4:
            return MitigationReport(
                format="unknown",
                architecture="unknown",
                bits=0,
                endian="unknown",
                limitations=("Binary data is too small to identify format.",),
            )

        if data.startswith(ELF_MAGIC):
            return cls._scan_elf(data)

        if data.startswith(DOS_MAGIC):
            return cls._scan_pe(data)

        if cls._is_macho_magic(data[:4]):
            return cls._scan_macho(data)

        return MitigationReport(
            format="unknown",
            architecture="unknown",
            bits=0,
            endian="unknown",
            limitations=("Unrecognized binary header or format.",),
        )

    # =========================================================================
    # ELF Mitigation Scanner
    # =========================================================================

    @classmethod
    def _scan_elf(cls, data: bytes) -> MitigationReport:
        limitations: list[str] = []
        details: dict[str, Any] = {}

        if len(data) < 52:
            return MitigationReport(
                format="elf",
                architecture="unknown",
                bits=0,
                endian="unknown",
                limitations=("Truncated ELF identification.",),
            )

        ei_class = data[4]
        ei_data = data[5]

        if ei_class == 1:
            bits = 32
        elif ei_class == 2:
            bits = 64
        else:
            return MitigationReport(
                format="elf",
                architecture="unknown",
                bits=0,
                endian="unknown",
                limitations=(f"Invalid ELF class: {ei_class}",),
            )

        if ei_data == 1:
            endian = "little"
            endian_prefix = "<"
        elif ei_data == 2:
            endian = "big"
            endian_prefix = ">"
        else:
            return MitigationReport(
                format="elf",
                architecture="unknown",
                bits=bits,
                endian="unknown",
                limitations=(f"Invalid ELF endianness: {ei_data}",),
            )

        try:
            e_type, e_machine = struct.unpack_from(f"{endian_prefix}HH", data, 16)
        except struct.error:
            return MitigationReport(
                format="elf",
                architecture="unknown",
                bits=bits,
                endian=endian,
                limitations=("Truncated ELF header.",),
            )

        arch_map = {
            3: "x86",
            62: "x86_64",
            40: "arm",
            183: "aarch64",
            243: "riscv",
            8: "mips",
            20: "powerpc",
            21: "ppc64",
        }
        architecture = arch_map.get(e_machine, f"machine_{e_machine}")

        # Program header & section header table offsets
        try:
            if bits == 32:
                e_phoff, e_shoff = struct.unpack_from(f"{endian_prefix}II", data, 28)
                e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                    f"{endian_prefix}HHHHH", data, 42
                )
            else:
                e_phoff, e_shoff = struct.unpack_from(f"{endian_prefix}QQ", data, 32)
                e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                    f"{endian_prefix}HHHHH", data, 54
                )
        except struct.error:
            return MitigationReport(
                format="elf",
                architecture=architecture,
                bits=bits,
                endian=endian,
                limitations=("Truncated ELF header fields.",),
            )

        # 1. PIE detection
        # ET_DYN (3) = Shared library or PIE executable
        # ET_EXEC (2) = Fixed-address executable
        # ET_REL (1) = Relocatable object file
        pie: bool | None = None
        if e_type == 3:
            pie = True
            details["elf_type"] = "ET_DYN"
        elif e_type == 2:
            pie = False
            details["elf_type"] = "ET_EXEC"
        elif e_type == 1:
            pie = None
            details["elf_type"] = "ET_REL"
            limitations.append("Relocatable object file (ET_REL); runtime address space layout not applicable.")
        else:
            details["elf_type"] = f"type_{e_type}"

        # 2. Program Headers Scan (NX, RELRO, PT_DYNAMIC, PT_LOAD mapping)
        has_gnu_stack = False
        nx: bool | None = None
        executable_stack = False
        has_gnu_relro = False
        dynamic_offset: int | None = None
        dynamic_size: int | None = None
        load_segments: list[tuple[int, int, int]] = []  # (vaddr, offset, filesz)

        if e_phoff > 0 and e_phnum > 0 and e_phentsize >= (32 if bits == 32 else 56):
            for i in range(e_phnum):
                ph_offset = e_phoff + i * e_phentsize
                if ph_offset + e_phentsize > len(data):
                    limitations.append("Program header table truncated.")
                    break
                try:
                    if bits == 32:
                        p_type, p_offset, p_vaddr, _, p_filesz, _, p_flags, _ = struct.unpack_from(
                            f"{endian_prefix}IIIIIIII", data, ph_offset
                        )
                    else:
                        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
                            f"{endian_prefix}IIQQQQQQ", data, ph_offset
                        )
                except struct.error:
                    break

                if p_type == PT_LOAD:
                    load_segments.append((p_vaddr, p_offset, p_filesz))
                elif p_type == PT_GNU_STACK:
                    has_gnu_stack = True
                    if p_flags & PF_X:
                        nx = False
                        executable_stack = True
                    else:
                        nx = True
                        executable_stack = False
                elif p_type == PT_GNU_RELRO:
                    has_gnu_relro = True
                elif p_type == PT_DYNAMIC:
                    dynamic_offset = p_offset
                    dynamic_size = p_filesz

        if not has_gnu_stack:
            # Without PT_GNU_STACK, stack permissions depend on host/architecture defaults (legacy executable stack)
            nx = None
            executable_stack = True
            details["gnu_stack"] = "absent"
        else:
            details["gnu_stack"] = "present"
        details["executable_stack"] = executable_stack

        def vaddr_to_file_offset(vaddr: int) -> int | None:
            for seg_vaddr, seg_off, seg_filesz in load_segments:
                if seg_vaddr <= vaddr < seg_vaddr + seg_filesz:
                    return seg_off + (vaddr - seg_vaddr)
            return None

        # 3. Dynamic Tag Parsing (RELRO, RPATH, RUNPATH, DF_1_PIE)
        bind_now = False
        dt_strtab_vaddr: int | None = None
        dt_strsz: int | None = None
        rpath_offsets: list[int] = []
        runpath_offsets: list[int] = []

        if dynamic_offset is not None and dynamic_size is not None:
            tag_size = 8 if bits == 32 else 16
            tag_count = dynamic_size // tag_size
            for i in range(tag_count):
                entry_offset = dynamic_offset + i * tag_size
                if entry_offset + tag_size > len(data):
                    break
                try:
                    if bits == 32:
                        d_tag, d_val = struct.unpack_from(f"{endian_prefix}II", data, entry_offset)
                    else:
                        d_tag, d_val = struct.unpack_from(f"{endian_prefix}QQ", data, entry_offset)
                except struct.error:
                    break

                if d_tag == DT_NULL:
                    break
                elif d_tag == DT_BIND_NOW or (d_tag == DT_FLAGS and bool(d_val & DF_BIND_NOW)):
                    bind_now = True
                elif d_tag == DT_FLAGS_1:
                    if d_val & DF_1_NOW:
                        bind_now = True
                    if d_val & DF_1_PIE:
                        pie = True
                elif d_tag == DT_STRTAB:
                    dt_strtab_vaddr = d_val
                elif d_tag == DT_STRSZ:
                    dt_strsz = d_val
                elif d_tag == DT_RPATH:
                    rpath_offsets.append(d_val)
                elif d_tag == DT_RUNPATH:
                    runpath_offsets.append(d_val)

        # Evaluate RELRO
        relro = ("Full" if bind_now else "Partial") if has_gnu_relro else "None"
        details["relro"] = relro

        # Resolve RPATH / RUNPATH strings
        rpath_list: list[str] = []
        runpath_list: list[str] = []
        dynstr_data: bytes | None = None

        if dt_strtab_vaddr is not None:
            strtab_file_offset = vaddr_to_file_offset(dt_strtab_vaddr)
            if strtab_file_offset is not None and dt_strsz is not None:
                end_off = min(len(data), strtab_file_offset + dt_strsz)
                dynstr_data = data[strtab_file_offset:end_off]
            elif strtab_file_offset is not None:
                dynstr_data = data[strtab_file_offset : min(len(data), strtab_file_offset + 65536)]

        def extract_string(blob: bytes | None, off: int) -> str | None:
            if blob is None or off < 0 or off >= len(blob):
                return None
            nul = blob.find(b"\x00", off)
            if nul == -1:
                nul = len(blob)
            return blob[off:nul].decode("utf-8", errors="replace")

        for off in rpath_offsets:
            s = extract_string(dynstr_data, off)
            if s:
                rpath_list.append(s)
        for off in runpath_offsets:
            s = extract_string(dynstr_data, off)
            if s:
                runpath_list.append(s)

        # 4. Symbol table parsing for Stack Canary and Fortify
        stack_canary = False
        fortify = False
        found_symbols = False

        if e_shoff > 0 and e_shnum > 0 and e_shentsize >= (40 if bits == 32 else 64):
            for i in range(e_shnum):
                sh_offset = e_shoff + i * e_shentsize
                if sh_offset + e_shentsize > len(data):
                    break
                try:
                    if bits == 32:
                        _, sh_type, _, _, sh_offset_val, sh_size, sh_link, _, _, sh_entsize = struct.unpack_from(
                            f"{endian_prefix}IIIIIIIIII", data, sh_offset
                        )
                    else:
                        _, sh_type, _, _, sh_offset_val, sh_size, sh_link, _, _, sh_entsize = struct.unpack_from(
                            f"{endian_prefix}IIQQQQIIQQ", data, sh_offset
                        )
                except struct.error:
                    break

                if sh_type in (SHT_SYMTAB, SHT_DYNSYM):
                    sym_ent_size = 16 if bits == 32 else 24
                    if sh_entsize >= sym_ent_size and sh_size > 0:
                        # Find corresponding string table
                        strtab_blob: bytes | None = None
                        if sh_link < e_shnum:
                            strtab_header_off = e_shoff + sh_link * e_shentsize
                            if strtab_header_off + e_shentsize <= len(data):
                                try:
                                    if bits == 32:
                                        _, _, _, _, str_off, str_size, _, _, _, _ = struct.unpack_from(
                                            f"{endian_prefix}IIIIIIIIII", data, strtab_header_off
                                        )
                                    else:
                                        _, _, _, _, str_off, str_size, _, _, _, _ = struct.unpack_from(
                                            f"{endian_prefix}IIQQQQIIQQ", data, strtab_header_off
                                        )
                                    if str_off + str_size <= len(data):
                                        strtab_blob = data[str_off : str_off + str_size]
                                except struct.error:
                                    pass

                        if strtab_blob is not None:
                            num_syms = min(sh_size // sh_entsize, MAX_SYMBOLS_TO_SCAN)
                            for s_idx in range(num_syms):
                                sym_offset = sh_offset_val + s_idx * sh_entsize
                                if sym_offset + 4 > len(data):
                                    break
                                try:
                                    st_name = struct.unpack_from(f"{endian_prefix}I", data, sym_offset)[0]
                                    sym_name = extract_string(strtab_blob, st_name)
                                    if sym_name:
                                        found_symbols = True
                                        if sym_name in CANARY_SYMBOLS:
                                            stack_canary = True
                                        if any(sym_name.startswith(f) for f in FORTIFY_PREFIXES) or sym_name.endswith(
                                            "_chk"
                                        ):
                                            fortify = True
                                except struct.error:
                                    break

        # Fallback for canary/fortify if section headers were stripped or empty
        if not found_symbols:
            if dynstr_data is not None:
                # Check for canary in dynamic string table
                for canary_name in CANARY_SYMBOLS:
                    if canary_name.encode("ascii") in dynstr_data:
                        stack_canary = True
                        break
                for fortify_func in FORTIFY_PREFIXES:
                    if fortify_func.encode("ascii") in dynstr_data:
                        fortify = True
                        break
            else:
                limitations.append("Symbol and string tables absent or stripped; canary and fortify status unverified.")

        return MitigationReport(
            format="elf",
            architecture=architecture,
            bits=bits,
            endian=endian,
            pie=pie,
            nx=nx,
            stack_canary=stack_canary,
            relro=relro,
            rpath=tuple(rpath_list),
            runpath=tuple(runpath_list),
            fortify=fortify,
            details=details,
            limitations=tuple(limitations),
        )

    # =========================================================================
    # PE Mitigation Scanner
    # =========================================================================

    @classmethod
    def _scan_pe(cls, data: bytes) -> MitigationReport:
        limitations: list[str] = []
        details: dict[str, Any] = {}

        if len(data) < 64:
            return MitigationReport(
                format="pe",
                architecture="unknown",
                bits=0,
                endian="little",
                limitations=("Truncated DOS header.",),
            )

        try:
            e_lfanew = struct.unpack_from("<I", data, 60)[0]
        except struct.error:
            return MitigationReport(
                format="pe",
                architecture="unknown",
                bits=0,
                endian="little",
                limitations=("Invalid DOS header e_lfanew offset.",),
            )

        if e_lfanew < 0 or e_lfanew + 24 > len(data):
            return MitigationReport(
                format="pe",
                architecture="unknown",
                bits=0,
                endian="little",
                limitations=("PE header offset lies outside file bounds.",),
            )

        if data[e_lfanew : e_lfanew + 4] != PE_MAGIC:
            return MitigationReport(
                format="pe",
                architecture="unknown",
                bits=0,
                endian="little",
                limitations=("Missing PE signature.",),
            )

        try:
            machine, num_sections, _, _, _, size_of_opt_header, characteristics = struct.unpack_from(
                "<HHIIIHH", data, e_lfanew + 4
            )
        except struct.error:
            return MitigationReport(
                format="pe",
                architecture="unknown",
                bits=0,
                endian="little",
                limitations=("Truncated COFF file header.",),
            )

        arch_map = {
            0x14C: "x86",
            0x8664: "x86_64",
            0xAA64: "arm64",
            0x1C0: "arm",
        }
        architecture = arch_map.get(machine, f"machine_{machine:#x}")

        opt_offset = e_lfanew + 24
        if size_of_opt_header < 64 or opt_offset + size_of_opt_header > len(data):
            return MitigationReport(
                format="pe",
                architecture=architecture,
                bits=32 if machine == 0x14C else 64,
                endian="little",
                limitations=("Truncated PE optional header.",),
            )

        opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
        if opt_magic == 0x10B:
            bits = 32
            dll_char_offset = opt_offset + 70
            num_rva_offset = opt_offset + 92
            data_dir_offset = opt_offset + 96
        elif opt_magic == 0x20B:
            bits = 64
            dll_char_offset = opt_offset + 70
            num_rva_offset = opt_offset + 108
            data_dir_offset = opt_offset + 112
        else:
            return MitigationReport(
                format="pe",
                architecture=architecture,
                bits=0,
                endian="little",
                limitations=(f"Unsupported optional header magic: {opt_magic:#x}",),
            )

        dll_characteristics = struct.unpack_from("<H", data, dll_char_offset)[0]
        num_rva_and_sizes = struct.unpack_from("<I", data, num_rva_offset)[0]

        # 1. ASLR / DynamicBase & High Entropy VA
        relocs_stripped = bool(characteristics & IMAGE_FILE_RELOCS_STRIPPED)
        aslr = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) and not relocs_stripped
        high_entropy_va = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
        details["high_entropy_va"] = high_entropy_va
        details["relocs_stripped"] = relocs_stripped

        # 2. DEP / NX
        dep = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

        # 3. Control Flow Guard (CFG)
        cfg = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)

        # 4. AppContainer / Isolation
        appcontainer = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
        details["appcontainer"] = appcontainer

        # 5. Parse Section Table for RVA mapping
        section_table_offset = opt_offset + size_of_opt_header
        sections: list[tuple[int, int, int, int]] = []  # (rva, virt_size, raw_offset, raw_size)
        if section_table_offset + num_sections * 40 <= len(data):
            for i in range(num_sections):
                s_off = section_table_offset + i * 40
                try:
                    virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, s_off + 8)
                    sections.append((virt_addr, virt_size, raw_ptr, raw_size))
                except struct.error:
                    break

        def rva_to_offset(rva: int) -> int | None:
            for v_addr, v_size, raw_ptr, raw_size in sections:
                extent = max(v_size, raw_size)
                if v_addr <= rva < v_addr + extent:
                    return raw_ptr + (rva - v_addr)
            return None

        # 6. Data Directories (Certificates / Authenticode & Load Config)
        authenticode = False
        stack_canary = False
        safeseh: bool | None = None

        if num_rva_and_sizes > 4 and data_dir_offset + 5 * 8 <= len(data):
            # Certificate table (Directory 4) - Note: RVA is a direct file offset!
            try:
                cert_file_off, cert_size = struct.unpack_from("<II", data, data_dir_offset + 4 * 8)
                if cert_file_off > 0 and cert_size > 0 and cert_file_off + cert_size <= len(data):
                    authenticode = True
            except struct.error:
                pass

        no_seh = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
        details["no_seh"] = no_seh

        if bits == 64:
            safeseh = None  # x64 uses table-driven exception handling (.pdata)
        elif no_seh:
            safeseh = True  # Binary explicitly declares no SEH tables needed

        if num_rva_and_sizes > 10 and data_dir_offset + 11 * 8 <= len(data):
            # Load Config Directory (Directory 10)
            try:
                load_cfg_rva, load_cfg_size = struct.unpack_from("<II", data, data_dir_offset + 10 * 8)
                if load_cfg_rva > 0 and load_cfg_size > 0:
                    cfg_file_off = rva_to_offset(load_cfg_rva)
                    if cfg_file_off is not None and cfg_file_off + 4 <= len(data):
                        cfg_size = struct.unpack_from("<I", data, cfg_file_off)[0]
                        if bits == 32 and cfg_file_off + min(cfg_size, 72) <= len(data):
                            if cfg_size >= 64:
                                sec_cookie = struct.unpack_from("<I", data, cfg_file_off + 60)[0]
                                if sec_cookie != 0:
                                    stack_canary = True
                            if cfg_size >= 72 and not no_seh:
                                se_handler_table, se_handler_count = struct.unpack_from("<II", data, cfg_file_off + 64)
                                safeseh = bool(se_handler_table != 0 and se_handler_count > 0)
                        elif bits == 64 and cfg_file_off + min(cfg_size, 96) <= len(data):
                            if cfg_size >= 96:
                                sec_cookie = struct.unpack_from("<Q", data, cfg_file_off + 88)[0]
                                if sec_cookie != 0:
                                    stack_canary = True
            except struct.error:
                pass

        if bits == 32 and safeseh is None and not no_seh:
            safeseh = False

        # Fallback canary detection via string matching if Load Config cookie not resolved
        if not stack_canary:
            canary_candidates = (b"__security_check_cookie", b"__security_cookie")
            if any(cand in data for cand in canary_candidates):
                stack_canary = True

        return MitigationReport(
            format="pe",
            architecture=architecture,
            bits=bits,
            endian="little",
            pie=aslr,
            nx=dep,
            stack_canary=stack_canary,
            cfg=cfg,
            safeseh=safeseh,
            code_signature=authenticode,
            details=details,
            limitations=tuple(limitations),
        )

    # =========================================================================
    # Mach-O Mitigation Scanner
    # =========================================================================

    @classmethod
    def _is_macho_magic(cls, magic: bytes) -> bool:
        return magic in {
            MACHO_THIN_32_BE,
            MACHO_THIN_32_LE,
            MACHO_THIN_64_BE,
            MACHO_THIN_64_LE,
            MACHO_FAT_BE,
            MACHO_FAT_LE,
            MACHO_FAT_64_BE,
            MACHO_FAT_64_LE,
        }

    @classmethod
    def _scan_macho(cls, data: bytes) -> MitigationReport:
        details: dict[str, Any] = {}

        if len(data) < 4:
            return MitigationReport(
                format="macho",
                architecture="unknown",
                bits=0,
                endian="unknown",
                limitations=("Truncated Mach-O data.",),
            )

        magic = data[:4]

        # Handle FAT / Universal Mach-O
        if magic in (MACHO_FAT_BE, MACHO_FAT_LE, MACHO_FAT_64_BE, MACHO_FAT_64_LE):
            fat_endian = ">" if magic in (MACHO_FAT_BE, MACHO_FAT_64_BE) else "<"
            is_fat_64 = magic in (MACHO_FAT_64_BE, MACHO_FAT_64_LE)
            if len(data) < 8:
                return MitigationReport(
                    format="macho",
                    architecture="unknown",
                    bits=0,
                    endian="unknown",
                    limitations=("Truncated fat Mach-O header.",),
                )
            nfat_arch = struct.unpack_from(f"{fat_endian}I", data, 4)[0]
            details["fat_slices"] = nfat_arch

            # Scan fat slices for arm64 (0x0100000C) or x86_64 (0x01000007)
            best_slice: tuple[int, int] | None = None
            first_slice: tuple[int, int] | None = None
            arch_header_size = 32 if is_fat_64 else 20

            for i in range(min(nfat_arch, 64)):
                entry_offset = 8 + i * arch_header_size
                if entry_offset + arch_header_size > len(data):
                    break
                try:
                    if is_fat_64:
                        cputype, _, slice_off, slice_sz = struct.unpack_from(f"{fat_endian}IIQQ", data, entry_offset)
                    else:
                        cputype, _, slice_off, slice_sz = struct.unpack_from(f"{fat_endian}IIII", data, entry_offset)
                    if first_slice is None:
                        first_slice = (slice_off, slice_sz)
                    if cputype in (0x0100000C, 0x01000007):  # arm64, x86_64
                        best_slice = (slice_off, slice_sz)
                        break
                except struct.error:
                    break

            chosen = best_slice or first_slice
            if chosen is not None:
                s_off, s_sz = chosen
                if s_off + s_sz <= len(data):
                    sub_report = cls._scan_macho_slice(data[s_off : s_off + s_sz])
                    merged_details = dict(sub_report.details)
                    merged_details.update(details)
                    return MitigationReport(
                        format=sub_report.format,
                        architecture=sub_report.architecture,
                        bits=sub_report.bits,
                        endian=sub_report.endian,
                        pie=sub_report.pie,
                        nx=sub_report.nx,
                        stack_canary=sub_report.stack_canary,
                        cfg=sub_report.cfg,
                        safeseh=sub_report.safeseh,
                        code_signature=sub_report.code_signature,
                        rpath=sub_report.rpath,
                        runpath=sub_report.runpath,
                        fortify=sub_report.fortify,
                        details=merged_details,
                        limitations=sub_report.limitations,
                    )

        # Thin Mach-O
        return cls._scan_macho_slice(data)

    @classmethod
    def _scan_macho_slice(cls, data: bytes) -> MitigationReport:
        limitations: list[str] = []
        details: dict[str, Any] = {}

        if len(data) < 28:
            return MitigationReport(
                format="macho",
                architecture="unknown",
                bits=0,
                endian="unknown",
                limitations=("Truncated thin Mach-O slice.",),
            )

        magic = data[:4]
        if magic in (MACHO_THIN_32_LE, MACHO_THIN_64_LE):
            endian = "little"
            endian_prefix = "<"
        elif magic in (MACHO_THIN_32_BE, MACHO_THIN_64_BE):
            endian = "big"
            endian_prefix = ">"
        else:
            return MitigationReport(
                format="macho",
                architecture="unknown",
                bits=0,
                endian="unknown",
                limitations=(f"Unrecognized Mach-O magic: {magic!r}",),
            )

        is_64 = magic in (MACHO_THIN_64_LE, MACHO_THIN_64_BE)
        bits = 64 if is_64 else 32
        header_size = 32 if is_64 else 28

        try:
            cputype, _, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(f"{endian_prefix}IIIIII", data, 4)
        except struct.error:
            return MitigationReport(
                format="macho",
                architecture="unknown",
                bits=bits,
                endian=endian,
                limitations=("Truncated Mach-O header.",),
            )

        arch_map = {
            7: "x86",
            0x01000007: "x86_64",
            12: "arm",
            0x0100000C: "arm64",
        }
        architecture = arch_map.get(cputype, f"cputype_{cputype:#x}")

        # 1. PIE & NX flags from Mach-O header
        # MH_PIE (0x200000) or filetype == 6 (MH_DYLIB, which is relocatable/PIE by design)
        pie = bool(flags & MH_PIE) or (filetype == 6)

        # NX: MH_ALLOW_STACK_EXECUTION (0x20000) allows stack execution. If 0, NX is active.
        allow_stack_exec = bool(flags & MH_ALLOW_STACK_EXECUTION)
        nx = not allow_stack_exec
        details["allow_stack_execution"] = allow_stack_exec
        details["no_heap_execution"] = bool(flags & MH_NO_HEAP_EXECUTION)

        # 2. Iterate Load Commands
        cursor = header_size
        command_limit = min(len(data), cursor + sizeofcmds)
        rpaths: list[str] = []
        code_signature = False
        restrict_segment = False
        stack_canary = False
        fortify = False

        symtab_info: tuple[int, int, int, int] | None = None  # (symoff, nsyms, stroff, strsize)

        for _ in range(min(ncmds, 16384)):
            if cursor + 8 > command_limit:
                break
            try:
                cmd, cmdsize = struct.unpack_from(f"{endian_prefix}II", data, cursor)
            except struct.error:
                break

            if cmdsize < 8 or cursor + cmdsize > command_limit:
                break

            if cmd in (LC_RPATH, LC_RPATH_REQ):
                if cursor + 12 <= command_limit:
                    try:
                        str_offset = struct.unpack_from(f"{endian_prefix}I", data, cursor + 8)[0]
                        if cursor + str_offset < cursor + cmdsize:
                            raw_str = data[cursor + str_offset : cursor + cmdsize]
                            nul = raw_str.find(b"\x00")
                            if nul != -1:
                                raw_str = raw_str[:nul]
                            rpath_str = raw_str.decode("utf-8", errors="replace")
                            if rpath_str:
                                rpaths.append(rpath_str)
                    except struct.error:
                        pass
            elif cmd == LC_CODE_SIGNATURE:
                code_signature = True
            elif cmd in (LC_SEGMENT, LC_SEGMENT_64):
                if cursor + 24 <= command_limit:
                    seg_name = data[cursor + 8 : cursor + 24].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
                    if seg_name == "__RESTRICT":
                        restrict_segment = True
            elif cmd == LC_SYMTAB and cursor + 24 <= command_limit:
                try:
                    symoff, nsyms, stroff, strsize = struct.unpack_from(f"{endian_prefix}IIII", data, cursor + 8)
                    symtab_info = (symoff, nsyms, stroff, strsize)
                except struct.error:
                    pass

            cursor += cmdsize

        details["restrict_segment"] = restrict_segment

        # 3. Parse Mach-O Symbol Table for Stack Canary and Fortify
        if symtab_info is not None:
            symoff, nsyms, stroff, strsize = symtab_info
            if stroff + strsize <= len(data) and symoff <= len(data):
                strtab_data = data[stroff : stroff + strsize]
                sym_entry_size = 16 if is_64 else 12
                max_syms = min(nsyms, MAX_SYMBOLS_TO_SCAN)
                for s_i in range(max_syms):
                    s_offset = symoff + s_i * sym_entry_size
                    if s_offset + 4 > len(data):
                        break
                    try:
                        n_strx = struct.unpack_from(f"{endian_prefix}I", data, s_offset)[0]
                        if 0 <= n_strx < len(strtab_data):
                            nul = strtab_data.find(b"\x00", n_strx)
                            if nul == -1:
                                nul = len(strtab_data)
                            s_name = strtab_data[n_strx:nul].decode("utf-8", errors="replace")
                            if s_name in CANARY_SYMBOLS:
                                stack_canary = True
                            if s_name.endswith("_chk") or any(s_name.startswith(f) for f in FORTIFY_PREFIXES):
                                fortify = True
                    except struct.error:
                        break

        # Fallback if symbols were stripped
        if not stack_canary and (b"___stack_chk_fail" in data or b"___stack_chk_guard" in data):
            stack_canary = True

        return MitigationReport(
            format="macho",
            architecture=architecture,
            bits=bits,
            endian=endian,
            pie=pie,
            nx=nx,
            stack_canary=stack_canary,
            code_signature=code_signature,
            rpath=tuple(rpaths),
            fortify=fortify,
            details=details,
            limitations=tuple(limitations),
        )
