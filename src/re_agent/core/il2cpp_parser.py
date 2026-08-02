"""IL2CPP metadata, script.json, and Rodroid IL2CPP Dumper parser for Unity game binary analysis."""

from __future__ import annotations

import contextlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from re_agent.utils.toolchain import resolve_il2cpp_dumper

MAX_METADATA_TEXT_BYTES = 268_435_456


def find_il2cpp_dumper(explicit_path: str | Path | None = None) -> str | None:
    """Single source of truth for resolving the Il2CppDumper CLI executable path."""
    if explicit_path:
        explicit = Path(explicit_path).expanduser()
        if explicit.is_file():
            return str(explicit_path)
    cargo_bin = Path.home() / ".cargo" / "bin" / "il2cpp_dumper.exe"
    resolved = resolve_il2cpp_dumper()
    if resolved is not None:
        return str(resolved)
    if cargo_bin.is_file():
        return str(cargo_bin.resolve())
    return None


def run_il2cpp_dumper_cli(
    binary_path: str | Path,
    metadata_path: str | Path,
    output_dir: str | Path = ".",
    dumper_path: str | Path | None = None,
    timeout_s: int = 600,
) -> dict[str, Any]:
    """Run Il2CppDumper / Rodroid IL2CPP Dumper CLI executable automatically."""
    bin_p = Path(binary_path)
    meta_p = Path(metadata_path)
    out_p = Path(output_dir)
    out_p.mkdir(parents=True, exist_ok=True)

    if not bin_p.is_file():
        return {
            "success": False,
            "error": f"IL2CPP binary not found: {bin_p}",
            "output_dir": str(out_p),
        }
    if not meta_p.is_file():
        return {
            "success": False,
            "error": f"IL2CPP metadata not found: {meta_p}",
            "output_dir": str(out_p),
        }
    if timeout_s <= 0:
        return {
            "success": False,
            "error": "Il2CppDumper timeout must be greater than zero.",
            "output_dir": str(out_p),
        }

    dumper_bin = find_il2cpp_dumper(dumper_path)
    if not dumper_bin:
        return {
            "success": False,
            "error": "Il2CppDumper CLI executable not found.",
            "output_dir": str(out_p),
        }

    artifact_paths = tuple(out_p / name for name in ("script.json", "dump.cs", "il2cpp.h", "static_metadata.json"))

    try:
        import shutil

        def _cleanup_dump_subdirs() -> None:
            if out_p.exists():
                for d in list(out_p.iterdir()):
                    if d.is_dir() and d.name.startswith("Dump"):
                        if (d / "dump.cs").exists():
                            for item in d.iterdir():
                                dest = out_p / item.name
                                if dest.exists():
                                    if dest.is_dir():
                                        shutil.rmtree(dest)
                                    else:
                                        dest.unlink()
                                shutil.move(str(item), str(dest))
                        shutil.rmtree(d, ignore_errors=True)

        _cleanup_dump_subdirs()

        for stale_file in artifact_paths:
            stale_file.unlink(missing_ok=True)

        commands_to_try = [
            # Rust dumper
            [dumper_bin, "-b", str(bin_p), "-m", str(meta_p), "-o", str(out_p)],
            # Standard C# dumper
            [dumper_bin, str(bin_p), str(meta_p), str(out_p)],
        ]

        artifacts: tuple[Path, ...] = ()
        res: subprocess.CompletedProcess[str] | None = None
        for cmd in commands_to_try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_s,
                check=False,
            )
            _cleanup_dump_subdirs()
            artifacts = tuple(
                candidate for candidate in artifact_paths if candidate.is_file() and candidate.stat().st_size > 0
            )
            if res.returncode == 0 and bool(artifacts):
                break

        success = bool(artifacts)
        stdout = res.stdout if res is not None else ""
        stderr = res.stderr if res is not None else ""
        if success:
            error = None
        else:
            output_msg = (stderr or stdout or "").strip()
            detail = f": {output_msg[:500]}" if output_msg else ""
            error = f"Il2CppDumper exited without producing a new supported metadata sidecar{detail}."
        return {
            "success": success,
            "stdout": stdout,
            "stderr": stderr,
            "output_dir": str(out_p),
            "artifacts": [str(artifact) for artifact in artifacts],
            "error": error,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Il2CppDumper timed out after {timeout_s} seconds.",
            "output_dir": str(out_p),
        }
    except OSError as e:
        return {
            "success": False,
            "error": str(e),
            "output_dir": str(out_p),
        }


def parse_script_json(content: str | dict[str, Any]) -> dict[str, Any]:
    """Parse Il2CppDumper script.json output containing ScriptMethod and ScriptString lists."""
    if isinstance(content, str):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return {"methods": [], "strings": []}
    else:
        data = content

    methods: list[dict[str, Any]] = []
    raw_methods = data.get("ScriptMethod", data.get("methods", []))
    if not isinstance(raw_methods, list):
        raw_methods = []
    for m in raw_methods[:2_000_000]:
        if not isinstance(m, dict):
            continue
        methods.append(
            {
                "name": m.get("Name", m.get("name", "")),
                "address": m.get("Address", m.get("address", 0)),
                "signature": m.get("Signature", m.get("signature", "")),
                "type_signature": m.get("TypeSignature", m.get("type_signature", "")),
                "dotnet_signature": m.get("DotNetSignature", m.get("dotnet_signature", "")),
                "group": m.get("Group", m.get("group", "")),
            }
        )

    strings: list[dict[str, Any]] = []
    raw_strings = data.get("ScriptString", data.get("strings", []))
    if not isinstance(raw_strings, list):
        raw_strings = []
    for s in raw_strings[:2_000_000]:
        if not isinstance(s, dict):
            continue
        strings.append(
            {
                "value": s.get("Value", s.get("value", "")),
                "address": s.get("Address", s.get("address", 0)),
            }
        )

    return {"methods": methods, "strings": strings}


def parse_rodroid_static_metadata(content: str | dict[str, Any]) -> dict[str, Any]:
    """Parse Rodroid Il2CppDumper static_metadata.json for thread-static fields and FieldRVA initializers."""
    if isinstance(content, str):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return {"static_fields": []}
    else:
        data = content

    return {"static_fields": data.get("static_fields", data.get("FieldRVA", []))}


def _parse_csharp_parameter_types(arguments: str) -> tuple[str, ...]:
    """Extract C# parameter types without splitting nested generic types."""
    text = arguments.strip()
    if not text:
        return ()

    parts: list[str] = []
    start = 0
    nesting = 0
    for index, character in enumerate(text):
        if character in "<[(":
            nesting += 1
        elif character in ">])":
            nesting = max(0, nesting - 1)
        elif character == "," and nesting == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])

    parameter_types: list[str] = []
    modifiers = {"in", "out", "params", "ref", "this"}
    for part in parts:
        declaration = part.split("=", 1)[0].strip()
        tokens = declaration.split()
        while tokens and tokens[0] in modifiers:
            tokens.pop(0)
        if len(tokens) < 2:
            continue
        parameter_types.append(" ".join(tokens[:-1]))
    return tuple(parameter_types)


def parse_dump_cs(content: str) -> list[dict[str, Any]]:
    """Parse Il2CppDumper dump.cs for class definitions, fields, and method signatures."""
    classes: list[dict[str, Any]] = []
    field_pattern = re.compile(
        r"(?:^[ \t]*//[ \t]*(0x[0-9a-fA-F]+)[ \t]*\r?\n[ \t]*|^[ \t]*)"
        r"(?:public|private|protected|internal)?[ \t]*"
        r"(?:(?:const|readonly|static|virtual|volatile)[ \t]+)*"
        r"([\w<>.,\[\]* \t]+?)[ \t]+(\w+);"
        r"(?:[ \t]*//[ \t]*(0x[0-9a-fA-F]+))?",
        re.MULTILINE,
    )
    method_pattern = re.compile(
        r"//\s*RVA:\s*(0x[0-9a-fA-F]+).*?\r?\n\s*(?:public|private|protected|internal)?\s*(?:static|virtual|override|abstract)?\s*([\w<>.,\s*]+?)\s+(\w+)\s*\((.*?)\)",
        re.MULTILINE,
    )

    splits = re.split(
        r"(?:^|\n)\s*(?:public|private|internal|protected)?\s*(?:abstract|sealed|static|partial)?\s*(?:class|struct|interface|enum)\s+(\w+)",
        content,
    )
    for i in range(1, len(splits), 2):
        cls_name = splits[i]
        body = splits[i + 1]
        fields: list[dict[str, Any]] = []
        seen_fields: set[tuple[str, int]] = set()
        for f_match in field_pattern.finditer(body):
            offset_str = f_match.group(1) or f_match.group(4)
            if not offset_str:
                continue
            field_key = (f_match.group(3).strip(), int(offset_str, 16))
            if field_key in seen_fields:
                continue
            seen_fields.add(field_key)
            fields.append(
                {
                    "type": f_match.group(2).strip(),
                    "name": field_key[0],
                    "offset": field_key[1],
                    "address_kind": "field_offset",
                }
            )

        methods: list[dict[str, Any]] = []
        for m_match in method_pattern.finditer(body):
            ret_t = m_match.group(2).strip()
            m_name = m_match.group(3).strip()
            args = m_match.group(4).strip()
            parameter_types = _parse_csharp_parameter_types(args)
            is_event = (
                m_name.startswith(("add_", "remove_", "subscribe", "unsubscribe"))
                or "delegate" in args.lower()
                or "event" in ret_t.lower()
            )

            methods.append(
                {
                    "name": m_name,
                    "method_name": m_name,
                    "return_type": ret_t,
                    "address": int(m_match.group(1), 16),
                    "rva": int(m_match.group(1), 16),
                    "address_kind": "method_rva",
                    "args": args,
                    "parameter_types": parameter_types,
                    "parameters": [{"type": parameter_type} for parameter_type in parameter_types],
                    "is_event": is_event,
                }
            )

        classes.append(
            {
                "name": cls_name,
                "fields": fields,
                "methods": methods,
            }
        )

    return classes


def parse_il2cpp_header(header_content: str) -> list[dict[str, Any]]:
    """Parse il2cpp.h struct definitions to extract field names and hex offsets (0x18, 0x20)."""
    struct_pattern = re.compile(r"struct\s+(\w+)\s*\{([^}]+)\};", re.MULTILINE)
    field_pattern = re.compile(r"(\w+)\s+(\w+);\s*//\s*(0x[0-9a-fA-F]+)", re.IGNORECASE)

    structs: list[dict[str, Any]] = []
    for match in struct_pattern.finditer(header_content):
        struct_name = match.group(1)
        body = match.group(2)

        fields: list[dict[str, Any]] = []
        for f_match in field_pattern.finditer(body):
            fields.append(
                {
                    "type": f_match.group(1),
                    "name": f_match.group(2),
                    "offset": int(f_match.group(3), 16),
                    "address_kind": "field_offset",
                }
            )
        structs.append(
            {
                "name": struct_name,
                "fields": fields,
            }
        )

    return structs


def find_il2cpp_metadata_in_dir(directory: str | Path) -> dict[str, Any] | None:
    """Check directory or file path for script.json, static_metadata.json, dump.cs, or il2cpp.h."""
    path = Path(directory)
    if path.is_file():
        path = path.parent

    script_json_path = path / "script.json"
    static_meta_path = path / "static_metadata.json"
    dump_cs_path = path / "dump.cs"
    il2cpp_h_path = path / "il2cpp.h"

    meta: dict[str, Any] = {}

    def read_limited(path_value: Path) -> str:
        if path_value.stat().st_size > MAX_METADATA_TEXT_BYTES:
            raise ValueError(f"IL2CPP metadata file exceeds size limit: {path_value}")
        return path_value.read_text(encoding="utf-8", errors="replace")

    if script_json_path.exists():
        with contextlib.suppress(Exception):
            meta.update(parse_script_json(read_limited(script_json_path)))

    if static_meta_path.exists():
        with contextlib.suppress(Exception):
            meta.update(parse_rodroid_static_metadata(read_limited(static_meta_path)))

    if dump_cs_path.exists():
        with contextlib.suppress(Exception):
            meta["classes"] = parse_dump_cs(read_limited(dump_cs_path))

    if il2cpp_h_path.exists():
        with contextlib.suppress(Exception):
            meta["structs"] = parse_il2cpp_header(read_limited(il2cpp_h_path))

    return meta if meta else None
