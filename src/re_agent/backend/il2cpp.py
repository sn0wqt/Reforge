"""IL2CPP metadata backend implementation for REBackend protocol."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from re_agent.backend.protocol import BackendCapabilities, REBackend
from re_agent.core.il2cpp_parser import find_il2cpp_metadata_in_dir
from re_agent.core.models import DecompileResult, EnumDef, FunctionEntry, StructDef, XRef


class IL2CPPBackend(REBackend):
    """REBackend implementation consuming dump.cs, script.json, and il2cpp.h directly."""

    def __init__(self, metadata_dir: str | Path) -> None:
        self.metadata_dir = Path(metadata_dir)
        self.parsed = find_il2cpp_metadata_in_dir(self.metadata_dir)
        self._capabilities = BackendCapabilities(
            has_decompile=True,
            has_asm=False,
            has_structs=True,
            has_xrefs=False,
            has_search=True,
            has_enums=False,
        )

    @property
    def capabilities(self) -> BackendCapabilities:
        return self._capabilities

    def remaining(self, class_name: str | None = None) -> list[FunctionEntry]:
        results: list[FunctionEntry] = []
        target_cls = (class_name or "").casefold()

        # Extract from parsed dump.cs classes
        classes = self.parsed.get("classes", [])
        for cls in classes:
            c_name = str(cls.get("name", ""))
            if target_cls and c_name.casefold() != target_cls and target_cls not in c_name.casefold():
                continue
            for m in cls.get("methods", []):
                rva = m.get("method_rva") or m.get("rva")
                if isinstance(rva, int) and rva > 0:
                    addr_str = f"0x{rva:X}"
                    results.append(
                        FunctionEntry(
                            address=addr_str,
                            name=str(m.get("name", "")),
                            class_name=c_name,
                            caller_count=1,
                        )
                    )

        # Fallback to script.json methods if dump.cs gave no entries
        if not results:
            methods = self.parsed.get("methods", [])
            for m in methods:
                c_name = str(m.get("class", ""))
                if target_cls and c_name.casefold() != target_cls and target_cls not in c_name.casefold():
                    continue
                rva = m.get("rva") or m.get("Address")
                if isinstance(rva, int) and rva > 0:
                    results.append(
                        FunctionEntry(
                            address=f"0x{rva:X}",
                            name=str(m.get("name", "")),
                            class_name=c_name,
                            caller_count=1,
                        )
                    )

        return results

    def unimplemented(self, filter_pattern: str | None = None) -> list[FunctionEntry]:
        return self.remaining(filter_pattern)

    def decompile(self, target: str) -> DecompileResult:
        # Match by address (0x...) or method name
        target_clean = target.strip().casefold()
        target_rva = None
        if target_clean.startswith("0x"):
            try:
                target_rva = int(target_clean, 16)
            except ValueError:
                pass

        classes = self.parsed.get("classes", [])
        for cls in classes:
            c_name = str(cls.get("name", ""))
            for m in cls.get("methods", []):
                rva = m.get("method_rva") or m.get("rva")
                m_name = str(m.get("name", ""))
                full_name = f"{c_name}::{m_name}"

                if (target_rva is not None and rva == target_rva) or target_clean in full_name.casefold():
                    ret_t = str(m.get("return_type", "void"))
                    params = m.get("parameter_types", ())
                    params_str = ", ".join(params) if isinstance(params, (list, tuple)) else ""
                    synthetic_code = f"// Address: 0x{rva:X} (RVA)\n{ret_t} {c_name}::{m_name}({params_str}) {{\n    // IL2CPP metadata representation\n}}"
                    addr_str = f"0x{rva:X}"
                    return DecompileResult(
                        address=addr_str,
                        name=full_name,
                        signature=f"{ret_t} {m_name}({params_str})",
                        decompiled=synthetic_code,
                        raw_output=synthetic_code,
                    )

        return DecompileResult(
            address=target if target.startswith("0x") else "0x0",
            name=target,
            signature=f"void {target}()",
            decompiled=f"// Unresolved IL2CPP metadata target: {target}\nvoid {target}() {{}}",
            raw_output=f"// Unresolved IL2CPP metadata target: {target}\nvoid {target}() {{}}",
        )

    def xrefs_to(self, target: str) -> list[XRef]:
        return []

    def xrefs_from(self, target: str) -> list[XRef]:
        return []

    def get_struct(self, name: str) -> StructDef | None:
        structs = self.parsed.get("structs", {})
        if name in structs:
            fields = structs[name]
            return StructDef(
                name=name,
                size=0,
                fields=[(str(f.get("type")), str(f.get("name")), int(f.get("offset", 0))) for f in fields],
            )
        return None

    def get_enum(self, name: str) -> EnumDef | None:
        return None

    def get_asm(self, target: str) -> Any | None:
        return None

    def search(self, pattern: str) -> list[FunctionEntry]:
        return self.remaining(pattern)
