"""Pure-Python WebAssembly (WASM) binary format scanner.

Inspects WebAssembly modules (.wasm) without external tools or heavy runtimes:
- Parses binary headers, section tables, and LEB128 lengths.
- Recovers declared imported modules and functions (env, wasi, go, etc.).
- Recovers exported function names and memory interfaces.
- Extracts custom sections (e.g. 'name' function symbols and 'producers' compiler metadata).
- Classifies runtime environment: emscripten, wasi, rust, go, unity-webgl, or generic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

WASM_MAGIC = b"\x00asm"
WASM_VERSION_1 = 1

# WebAssembly Section IDs
SECTION_CUSTOM = 0
SECTION_TYPE = 1
SECTION_IMPORT = 2
SECTION_FUNCTION = 3
SECTION_TABLE = 4
SECTION_MEMORY = 5
SECTION_GLOBAL = 6
SECTION_EXPORT = 7
SECTION_START = 8
SECTION_ELEMENT = 9
SECTION_CODE = 10
SECTION_DATA = 11
SECTION_DATA_COUNT = 12

IMPORT_KIND_FUNC = 0
IMPORT_KIND_TABLE = 1
IMPORT_KIND_MEM = 2
IMPORT_KIND_GLOBAL = 3

EXPORT_KIND_FUNC = 0
EXPORT_KIND_TABLE = 1
EXPORT_KIND_MEM = 2
EXPORT_KIND_GLOBAL = 3


def _read_leb128_u32(data: bytes, offset: int) -> tuple[int, int]:
    """Decode an unsigned 32-bit LEB128 integer."""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("Truncated LEB128 integer")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
        if shift > 35:
            raise ValueError("Overflow in LEB128 integer")
    return result, offset


def _read_string(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a length-prefixed UTF-8 string."""
    length, offset = _read_leb128_u32(data, offset)
    if offset + length > len(data):
        raise ValueError("String payload exceeds data boundary")
    raw = data[offset : offset + length]
    return raw.decode("utf-8", errors="replace"), offset + length


@dataclass(frozen=True)
class WasmImport:
    """Imported symbol in a WASM module."""

    module: str
    field: str
    kind: str  # "func", "table", "memory", "global"
    type_index: int | None = None


@dataclass(frozen=True)
class WasmExport:
    """Exported symbol in a WASM module."""

    name: str
    kind: str  # "func", "table", "memory", "global"
    index: int


@dataclass(frozen=True)
class WasmInfo:
    """Extracted WebAssembly module metadata."""

    version: int
    runtime: str  # "emscripten", "wasi", "unity-webgl", "rust", "go", "generic"
    imported_modules: tuple[str, ...]
    imports: tuple[WasmImport, ...]
    exports: tuple[WasmExport, ...]
    function_count: int
    code_section_bytes: int
    custom_sections: tuple[str, ...]
    producers: dict[str, list[str]] = field(default_factory=dict)
    has_memory: bool = False
    details: dict[str, object] = field(default_factory=dict)

    @property
    def exported_functions(self) -> list[str]:
        return [exp.name for exp in self.exports if exp.kind == "func"]

    @property
    def imported_functions(self) -> list[str]:
        return [f"{imp.module}.{imp.field}" for imp in self.imports if imp.kind == "func"]

    @property
    def notes(self) -> list[str]:
        lines: list[str] = [
            f"WASM v{self.version} ({self.runtime})",
            f"Functions: {self.function_count} (Code size: {self.code_section_bytes} bytes)",
        ]
        if self.imported_modules:
            lines.append(f"Imports ({len(self.imports)}): {', '.join(sorted(self.imported_modules))}")
        if self.exports:
            top_exports = [e.name for e in self.exports[:8]]
            lines.append(f"Exports ({len(self.exports)}): {', '.join(top_exports)}")
        if self.producers:
            for k, vals in self.producers.items():
                lines.append(f"Producer ({k}): {', '.join(vals)}")
        return lines


class WasmScanner:
    """Pure-Python scanner for WebAssembly binary modules."""

    @staticmethod
    def is_wasm_binary(data: bytes) -> bool:
        """Check if bytes begin with WASM magic."""
        return len(data) >= 8 and data[:4] == WASM_MAGIC

    @classmethod
    def scan_bytes(cls, data: bytes, max_items: int = 1000) -> WasmInfo | None:
        """Parse WASM binary bytes into structured WasmInfo."""
        if not cls.is_wasm_binary(data):
            return None

        version = int.from_bytes(data[4:8], "little")
        offset = 8
        length = len(data)

        imports: list[WasmImport] = []
        exports: list[WasmExport] = []
        custom_sections: list[str] = []
        producers: dict[str, list[str]] = {}
        func_types_count = 0
        code_section_bytes = 0
        has_memory = False

        while offset < length:
            if offset + 1 > length:
                break
            sec_id = data[offset]
            offset += 1
            try:
                sec_size, offset = _read_leb128_u32(data, offset)
            except ValueError:
                break
            if offset + sec_size > length:
                # Truncated section
                break

            sec_data = data[offset : offset + sec_size]
            offset += sec_size

            if sec_id == SECTION_CUSTOM:
                try:
                    name, name_end = _read_string(sec_data, 0)
                    custom_sections.append(name)
                    if name == "producers":
                        cls._parse_producers_section(sec_data[name_end:], producers)
                except Exception:
                    pass
            elif sec_id == SECTION_IMPORT:
                cls._parse_import_section(sec_data, imports, max_items)
            elif sec_id == SECTION_FUNCTION:
                try:
                    count, _ = _read_leb128_u32(sec_data, 0)
                    func_types_count = count
                except Exception:
                    pass
            elif sec_id == SECTION_MEMORY:
                has_memory = True
            elif sec_id == SECTION_EXPORT:
                cls._parse_export_section(sec_data, exports, max_items)
            elif sec_id == SECTION_CODE:
                code_section_bytes = sec_size
                try:
                    code_funcs, _ = _read_leb128_u32(sec_data, 0)
                    if code_funcs > func_types_count:
                        func_types_count = code_funcs
                except Exception:
                    pass

        imported_modules = tuple(sorted({imp.module for imp in imports}))
        runtime = cls._detect_runtime(imported_modules, imports, exports, producers)

        total_funcs = func_types_count + len([i for i in imports if i.kind == "func"])

        return WasmInfo(
            version=version,
            runtime=runtime,
            imported_modules=imported_modules,
            imports=tuple(imports),
            exports=tuple(exports),
            function_count=total_funcs,
            code_section_bytes=code_section_bytes,
            custom_sections=tuple(custom_sections),
            producers=producers,
            has_memory=has_memory,
            details={
                "custom_section_count": len(custom_sections),
                "import_count": len(imports),
                "export_count": len(exports),
            },
        )

    @classmethod
    def scan_file(cls, path: str | Path, max_bytes: int = 128 * 1024 * 1024) -> WasmInfo | None:
        """Scan a .wasm file on disk."""
        target = Path(path)
        if not target.is_file():
            return None
        try:
            with open(target, "rb") as f:
                header = f.read(8)
                if not cls.is_wasm_binary(header):
                    return None
                f.seek(0)
                data = f.read(max_bytes)
                return cls.scan_bytes(data)
        except (OSError, ValueError):
            return None

    @staticmethod
    def _parse_import_section(data: bytes, imports: list[WasmImport], max_items: int) -> None:
        """Decode WASM import section."""
        try:
            count, offset = _read_leb128_u32(data, 0)
            kind_map = {
                IMPORT_KIND_FUNC: "func",
                IMPORT_KIND_TABLE: "table",
                IMPORT_KIND_MEM: "memory",
                IMPORT_KIND_GLOBAL: "global",
            }
            for _ in range(min(count, max_items)):
                if offset >= len(data):
                    break
                module, offset = _read_string(data, offset)
                field_name, offset = _read_string(data, offset)
                kind_byte = data[offset]
                offset += 1
                type_idx: int | None = None
                if kind_byte == IMPORT_KIND_FUNC:
                    type_idx, offset = _read_leb128_u32(data, offset)
                elif kind_byte == IMPORT_KIND_TABLE:
                    # skip element type & limits
                    offset += 1
                    flags, offset = _read_leb128_u32(data, offset)
                    _, offset = _read_leb128_u32(data, offset)
                    if flags & 1:
                        _, offset = _read_leb128_u32(data, offset)
                elif kind_byte == IMPORT_KIND_MEM:
                    flags, offset = _read_leb128_u32(data, offset)
                    _, offset = _read_leb128_u32(data, offset)
                    if flags & 1:
                        _, offset = _read_leb128_u32(data, offset)
                elif kind_byte == IMPORT_KIND_GLOBAL:
                    offset += 2  # valtype + mutability

                imports.append(
                    WasmImport(
                        module=module,
                        field=field_name,
                        kind=kind_map.get(kind_byte, "unknown"),
                        type_index=type_idx,
                    )
                )
        except Exception:
            pass

    @staticmethod
    def _parse_export_section(data: bytes, exports: list[WasmExport], max_items: int) -> None:
        """Decode WASM export section."""
        try:
            count, offset = _read_leb128_u32(data, 0)
            kind_map = {
                EXPORT_KIND_FUNC: "func",
                EXPORT_KIND_TABLE: "table",
                EXPORT_KIND_MEM: "memory",
                EXPORT_KIND_GLOBAL: "global",
            }
            for _ in range(min(count, max_items)):
                if offset >= len(data):
                    break
                name, offset = _read_string(data, offset)
                kind_byte = data[offset]
                offset += 1
                index, offset = _read_leb128_u32(data, offset)
                exports.append(
                    WasmExport(
                        name=name,
                        kind=kind_map.get(kind_byte, "unknown"),
                        index=index,
                    )
                )
        except Exception:
            pass

    @staticmethod
    def _parse_producers_section(data: bytes, producers: dict[str, list[str]]) -> None:
        """Decode WASM producers custom section."""
        try:
            field_count, offset = _read_leb128_u32(data, 0)
            for _ in range(field_count):
                if offset >= len(data):
                    break
                sec_name, offset = _read_string(data, offset)
                val_count, offset = _read_leb128_u32(data, offset)
                vals: list[str] = []
                for _ in range(val_count):
                    val_name, offset = _read_string(data, offset)
                    val_version, offset = _read_string(data, offset)
                    vals.append(f"{val_name} {val_version}".strip())
                producers[sec_name] = vals
        except Exception:
            pass

    @staticmethod
    def _detect_runtime(
        imported_modules: tuple[str, ...],
        imports: list[WasmImport],
        exports: list[WasmExport],
        producers: dict[str, list[str]],
    ) -> str:
        """Heuristically identify the language / framework compiler runtime."""
        # 1. Unity WebGL
        export_names = {e.name for e in exports}
        import_names = {f"{i.module}.{i.field}" for i in imports}
        if any("Unity" in name or "invoke_viii" in name for name in export_names):
            return "unity-webgl"
        if any("unity" in name.casefold() for name in import_names):
            return "unity-webgl"

        # 2. Go WebAssembly
        if "go" in imported_modules or any("runtime.wasmExit" in name or "go." in name for name in import_names):
            return "go"

        # 3. WASI
        if any("wasi_snapshot_preview1" in mod or "wasi_unstable" in mod for mod in imported_modules):
            return "wasi"

        # 4. Emscripten
        if "env" in imported_modules:
            emscripten_indicators = {"___syscall", "emscripten_", "stackSave", "stackAlloc", "setThrew"}
            if any(any(ind in name for ind in emscripten_indicators) for name in import_names | export_names):
                return "emscripten"

        # 5. Rust
        for vals in producers.values():
            if any("rustc" in v.casefold() for v in vals):
                return "rust"
        if any("rust_" in name for name in export_names):
            return "rust"

        return "generic"
