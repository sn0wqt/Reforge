"""JavaScript unbundling, de-minification, and Electron IPC/bridge analysis for Web and Hybrid pathways.

Inspired by REA's JavaScript recovery architecture (Wakaru CLI integration, Webpack/Rspack
AST recovery, Babel Electron IPC visitors, and contextBridge exposure analyzers).
Provides zero-dependency fallback static unbundling and deobfuscation, with seamless
external Wakaru toolchain escalation when available.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from reforge.utils.process import run_cmd_split
from reforge.utils.toolchain import resolve_wakaru

_IPC_CALL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""\b(?P<target>ipcRenderer|ipcMain)\s*\.\s*(?P<method>send|sendSync|invoke|postMessage|sendToHost|on|once|addListener|handle|handleOnce)\s*\(\s*(?P<args>[^;)]*)\)""",
    re.MULTILINE,
)

_CONTEXT_BRIDGE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""\bcontextBridge\s*\.\s*(?P<method>exposeInMainWorld|exposeInIsolatedWorld)\s*\(""",
    re.MULTILINE,
)

_REQUIRE_DEPENDENCY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""\b(?:require|__webpack_require__)\s*\(\s*["']([^"']+)["']\s*\)""",
)

_IMPORT_DEPENDENCY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""\bimport\s*\(\s*["']([^"']+)["']\s*\)""",
)

_COMMONJS_EXPORTS_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""\b(?:module\s*\.\s*exports\s*\.\s*([a-zA-Z_$][a-zA-Z0-9_$]*)|exports\s*\.\s*([a-zA-Z_$][a-zA-Z0-9_$]*))\s*=""",
)

_ESM_EXPORTS_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""\bexport\s+(?:default|const|let|var|function|class)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)""",
)


@dataclass(frozen=True)
class ExtractedModule:
    """Individual JavaScript module recovered from a bundle."""

    module_id: str
    code: str
    size_bytes: int
    sha256: str
    dependencies: tuple[str, ...] = ()
    start_offset: int = 0
    end_offset: int = 0
    export_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class IpcChannelFinding:
    """Electron IPC communication channel observation."""

    side: str  # "renderer" | "main"
    operation: str  # "send" | "send-sync" | "invoke" | "on" | "once" | "handle" | etc.
    channel: str | None
    channel_expression: str | None
    mode: str  # "send" | "invoke" | "listen" | "handle"
    line_number: int = 1


@dataclass(frozen=True)
class ContextBridgeFinding:
    """Electron contextBridge exposure observation."""

    world: str  # "main" | "isolated"
    api_key: str | None
    api_key_expression: str | None
    members: tuple[str, ...] = ()
    line_number: int = 1


@dataclass(frozen=True)
class BundleSignature:
    """Detected bundler type and bundle metadata."""

    bundler: str  # "webpack" | "vite" | "rollup" | "esbuild" | "browserify" | "unknown"
    chunk_ids: tuple[str, ...] = ()
    runtime_name: str | None = None
    is_chunk: bool = False
    is_bootstrap: bool = False


@dataclass(frozen=True)
class WebDeobfuscationResult:
    """Comprehensive recovery result from a JavaScript bundle or script."""

    bundler_signature: BundleSignature
    modules: tuple[ExtractedModule, ...] = ()
    ipc_channels: tuple[IpcChannelFinding, ...] = ()
    context_bridge_apis: tuple[ContextBridgeFinding, ...] = ()
    deobfuscated_code: str | None = None
    warnings: tuple[str, ...] = ()
    engine_used: str = "reforge-builtin"


def find_matching_delimiter(
    text: str,
    start_index: int,
    open_char: str = "{",
    close_char: str = "}",
) -> int:
    """Find the index of the matching close_char starting at start_index (where text[start_index] == open_char).

    Properly respects strings (single, double, template backtick) and comments (line and block).
    Returns -1 if not found or unbalanced.
    """
    if start_index < 0 or start_index >= len(text) or text[start_index] != open_char:
        return -1

    depth = 0
    in_string: str | None = None
    in_single_comment = False
    in_multi_comment = False
    i = start_index
    n = len(text)

    while i < n:
        char = text[i]

        if in_single_comment:
            if char == "\n":
                in_single_comment = False
            i += 1
            continue

        if in_multi_comment:
            if char == "*" and i + 1 < n and text[i + 1] == "/":
                in_multi_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_string is not None:
            if char == "\\":
                i += 2  # skip escaped character
                continue
            if char == in_string:
                in_string = None
            i += 1
            continue

        if char == "/" and i + 1 < n:
            next_char = text[i + 1]
            if next_char == "/":
                in_single_comment = True
                i += 2
                continue
            if next_char == "*":
                in_multi_comment = True
                i += 2
                continue

        if char in ('"', "'", "`"):
            in_string = char
            i += 1
            continue

        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return i

        i += 1

    return -1


def detect_bundler(source_code: str) -> BundleSignature:
    """Detect bundler signatures (Webpack chunk push, Webpack bootstrap, Vite, Rollup, Esbuild, Browserify)."""
    # 1. Webpack 5 / 4 chunk push: (self.webpackChunk... || []).push([[chunkIds], { ... }])
    webpack_chunk_match = re.search(
        r"""\b(webpackChunk[a-zA-Z0-9_$]*)\b[^;]*?\.\s*push\s*\(\s*\[""",
        source_code,
    )
    if webpack_chunk_match:
        runtime_name = webpack_chunk_match.group(1)
        push_start = webpack_chunk_match.end() - 1  # points to '['
        chunk_array_end = find_matching_delimiter(source_code, push_start, "[", "]")
        chunk_ids: list[str] = []
        if chunk_array_end != -1:
            first_element_start = source_code.find("[", push_start + 1)
            if first_element_start != -1 and first_element_start < chunk_array_end:
                first_element_end = find_matching_delimiter(source_code, first_element_start, "[", "]")
                if first_element_end != -1:
                    inner = source_code[first_element_start + 1 : first_element_end]
                    for id_match in re.finditer(r"""["']([^"']+)["']|(\d+)""", inner):
                        chunk_ids.append(id_match.group(1) or id_match.group(2))
        return BundleSignature(
            bundler="webpack",
            chunk_ids=tuple(chunk_ids),
            runtime_name=runtime_name,
            is_chunk=True,
            is_bootstrap=False,
        )

    # 2. Webpack JSONP (older Webpack 3/4)
    if "webpackJsonp" in source_code:
        jsonp_match = re.search(r"""webpackJsonp(?:Callback)?\s*\(\s*\[""", source_code)
        if jsonp_match or ".webpackJsonp" in source_code:
            return BundleSignature(
                bundler="webpack",
                runtime_name="webpackJsonp",
                is_chunk=True,
                is_bootstrap=False,
            )

    # 3. Standalone Webpack Bootstrap IIFE
    if re.search(
        r"""(?:\!function\s*\(\s*(\w+)\s*\)|\(function\s*\(\s*(\w+)\s*\))\s*\{\s*var\s+(\w+)\s*=\s*\{\};.*?\b(?:\1|\w+)\[\w+\]\.call\(o\.exports""",
        source_code,
        re.DOTALL,
    ) or ("__webpack_require__" in source_code and re.search(r"""function\s+__webpack_require__\s*\(""", source_code)):
        return BundleSignature(
            bundler="webpack",
            runtime_name="webpack-bootstrap",
            is_chunk=False,
            is_bootstrap=True,
        )

    # 4. Esbuild wrappers
    if re.search(r"""\b(?:__commonJS|__esm)\b""", source_code):
        return BundleSignature(
            bundler="esbuild",
            runtime_name="esbuild",
            is_chunk=False,
            is_bootstrap=True,
        )

    # 5. Vite / Rollup
    if "import.meta" in source_code or "__vite__" in source_code or "/* @vite-ignore */" in source_code:
        return BundleSignature(
            bundler="vite",
            runtime_name="vite-rollup",
            is_chunk=False,
            is_bootstrap=False,
        )
    if "__rollup_plugin_" in source_code or "/* rollup */" in source_code:
        return BundleSignature(
            bundler="rollup",
            runtime_name="rollup",
            is_chunk=False,
            is_bootstrap=False,
        )

    # 6. Browserify
    if re.search(r"""\(function\s*e\s*\(\s*t\s*,\s*n\s*,\s*r\s*\)""", source_code):
        return BundleSignature(
            bundler="browserify",
            runtime_name="browserify",
            is_chunk=False,
            is_bootstrap=True,
        )

    return BundleSignature(
        bundler="unknown",
        is_chunk=False,
        is_bootstrap=False,
    )


def extract_module_dependencies(module_code: str) -> tuple[str, ...]:
    """Extract required or imported module specifiers from a JavaScript module."""
    deps: list[str] = []
    for match in _REQUIRE_DEPENDENCY_PATTERN.finditer(module_code):
        deps.append(match.group(1))
    for match in _IMPORT_DEPENDENCY_PATTERN.finditer(module_code):
        deps.append(match.group(1))
    return tuple(dict.fromkeys(deps))


def extract_module_exports(module_code: str) -> tuple[str, ...]:
    """Extract exported property names from a CommonJS or ESM module."""
    exports: list[str] = []
    for match in _COMMONJS_EXPORTS_PATTERN.finditer(module_code):
        name = match.group(1) or match.group(2)
        if name:
            exports.append(name)
    for match in _ESM_EXPORTS_PATTERN.finditer(module_code):
        name = match.group(1)
        if name:
            exports.append(name)
    return tuple(dict.fromkeys(exports))


def unpack_webpack_bundle(source_code: str) -> list[ExtractedModule]:
    """Extract individual modules from a Webpack chunk push or standalone bootstrap IIFE."""
    modules: list[ExtractedModule] = []

    # Case A: Chunk push - e.g. (self.webpackChunk_name = self.webpackChunk_name || []).push([[chunkIds], { ... }])
    chunk_push_match = re.search(
        r"""\b(?:webpackChunk[a-zA-Z0-9_$]*|webpackJsonp)\b[^;]*?\.\s*push\s*\(\s*\[""",
        source_code,
    )
    if chunk_push_match:
        outer_array_start = chunk_push_match.end() - 1  # points to '['
        outer_array_end = find_matching_delimiter(source_code, outer_array_start, "[", "]")
        if outer_array_end != -1:
            modules.extend(_extract_modules_from_container(source_code, outer_array_start, outer_array_end))
            if modules:
                return modules

    # Case B: Standalone Webpack Bootstrap IIFE - e.g. (function(e){...})({ 0: function(...){...}, ... })
    bootstrap_match = re.search(
        r"""(?:\!function|\(function)\s*\([^\)]*\)\s*\{""",
        source_code,
    )
    if bootstrap_match:
        iife_body_start = bootstrap_match.end() - 1
        iife_body_end = find_matching_delimiter(source_code, iife_body_start, "{", "}")
        if iife_body_end != -1:
            call_start = source_code.find("(", iife_body_end)
            if call_start != -1 and call_start - iife_body_end < 10:
                call_end = find_matching_delimiter(source_code, call_start, "(", ")")
                if call_end != -1:
                    modules.extend(_extract_modules_from_container(source_code, call_start, call_end))
                    if modules:
                        return modules

    # Case C: Fallback search for any large module object literal { "path": function(...) { ... } }
    modules.extend(_extract_heuristic_modules(source_code))
    return modules


def _extract_modules_from_container(
    source_code: str, container_start: int, container_end: int
) -> list[ExtractedModule]:
    """Find and parse module table (object or array) within container bounds."""
    first_elem_start = -1
    for i in range(container_start + 1, container_end):
        if source_code[i] in "[{":
            first_elem_start = i
            break
    if first_elem_start == -1:
        return []

    first_char = source_code[first_elem_start]
    first_elem_end = find_matching_delimiter(
        source_code,
        first_elem_start,
        first_char,
        "]" if first_char == "[" else "}",
    )
    if first_elem_end == -1:
        return []

    # If container holds [ [chunkIds], { ...modules... } ], look for 2nd element
    comma_idx = source_code.find(",", first_elem_end)
    if comma_idx != -1 and comma_idx < container_end:
        second_start = -1
        for i in range(comma_idx + 1, container_end):
            if source_code[i] in "[{":
                second_start = i
                break
        if second_start != -1:
            second_char = source_code[second_start]
            second_end = find_matching_delimiter(
                source_code,
                second_start,
                second_char,
                "]" if second_char == "[" else "}",
            )
            if second_end != -1 and second_end <= container_end:
                if second_char == "{":
                    return _parse_module_object(source_code, second_start, second_end)
                return _parse_module_array(source_code, second_start, second_end)

    # Standalone bootstrap with single object/array container:
    if first_char == "{":
        return _parse_module_object(source_code, first_elem_start, first_elem_end)
    return _parse_module_array(source_code, first_elem_start, first_elem_end)


def _parse_module_object(source_code: str, obj_start: int, obj_end: int) -> list[ExtractedModule]:
    """Parse key-value module entries in an object literal { moduleId: function(...) { ... }, ... }."""
    modules: list[ExtractedModule] = []

    pos = obj_start + 1
    while pos < obj_end:
        while pos < obj_end and source_code[pos] in " \t\r\n,":
            pos += 1
        if pos >= obj_end:
            break

        match = re.match(
            r"""(?:["']([^"']+)["']|([a-zA-Z_$][a-zA-Z0-9_$]*)|(\d+))\s*(?::\s*|(?=\())""",
            source_code[pos:obj_end],
        )
        if not match:
            pos += 1
            continue

        raw_key = match.group(1) or match.group(2) or match.group(3)
        colon_offset = pos + match.end()

        val_start = colon_offset
        while val_start < obj_end and source_code[val_start] in " \t\r\n":
            val_start += 1
        if val_start >= obj_end:
            break

        module_code = ""
        val_end = -1

        if source_code[val_start] == "(":
            paren_end = find_matching_delimiter(source_code, val_start, "(", ")")
            if paren_end != -1 and paren_end < obj_end:
                val_end = paren_end
                module_code = source_code[val_start + 1 : val_end].strip()

        if not module_code:
            body_brace = source_code.find("{", val_start)
            if body_brace != -1 and body_brace < obj_end:
                val_end = find_matching_delimiter(source_code, body_brace, "{", "}")
                if val_end != -1:
                    module_code = source_code[val_start : val_end + 1].strip()

        if not module_code:
            comma_idx = source_code.find(",", val_start)
            if comma_idx != -1 and comma_idx < obj_end:
                val_end = comma_idx
                module_code = source_code[val_start:val_end].strip()
            else:
                val_end = obj_end - 1
                module_code = source_code[val_start:val_end].strip()

        module_bytes = module_code.encode("utf-8")
        modules.append(
            ExtractedModule(
                module_id=raw_key,
                code=module_code,
                size_bytes=len(module_bytes),
                sha256=hashlib.sha256(module_bytes).hexdigest(),
                dependencies=extract_module_dependencies(module_code),
                start_offset=val_start,
                end_offset=val_end + 1 if val_end != -1 else val_start + len(module_code),
                export_names=extract_module_exports(module_code),
            )
        )

        pos = val_end + 1 if val_end != -1 else colon_offset + len(module_code)

    return modules


def _parse_module_array(source_code: str, arr_start: int, arr_end: int) -> list[ExtractedModule]:
    """Parse indexed module functions in an array [ function(...) { ... }, ... ]."""
    modules: list[ExtractedModule] = []
    idx = 0
    pos = arr_start + 1

    while pos < arr_end:
        while pos < arr_end and source_code[pos] in " \t\r\n,":
            pos += 1
        if pos >= arr_end:
            break

        body_brace = source_code.find("{", pos)
        if body_brace == -1 or body_brace >= arr_end:
            break
        body_end = find_matching_delimiter(source_code, body_brace, "{", "}")
        if body_end == -1 or body_end > arr_end:
            break

        module_code = source_code[pos : body_end + 1]
        module_bytes = module_code.encode("utf-8")
        modules.append(
            ExtractedModule(
                module_id=str(idx),
                code=module_code.strip(),
                size_bytes=len(module_bytes),
                sha256=hashlib.sha256(module_bytes).hexdigest(),
                dependencies=extract_module_dependencies(module_code),
                start_offset=pos,
                end_offset=body_end + 1,
                export_names=extract_module_exports(module_code),
            )
        )
        idx += 1
        pos = body_end + 1

    return modules


def _extract_heuristic_modules(source_code: str) -> list[ExtractedModule]:
    """Heuristic extraction for isolated module definitions in minified scripts."""
    modules: list[ExtractedModule] = []
    pattern = re.compile(r"""(?:\bfunction\s*\([a-zA-Z0-9_$,\s]+\)|\([a-zA-Z0-9_$,\s]+\)\s*=>)\s*\{""")
    for match in pattern.finditer(source_code):
        start = match.start()
        brace_start = match.end() - 1
        brace_end = find_matching_delimiter(source_code, brace_start, "{", "}")
        if brace_end != -1 and brace_end - start > 100:
            candidate_code = source_code[start : brace_end + 1]
            deps = extract_module_dependencies(candidate_code)
            exports = extract_module_exports(candidate_code)
            if deps or exports:
                code_bytes = candidate_code.encode("utf-8")
                modules.append(
                    ExtractedModule(
                        module_id=f"module_{len(modules)}",
                        code=candidate_code.strip(),
                        size_bytes=len(code_bytes),
                        sha256=hashlib.sha256(code_bytes).hexdigest(),
                        dependencies=deps,
                        start_offset=start,
                        end_offset=brace_end + 1,
                        export_names=exports,
                    )
                )
    return modules


def decode_escaped_strings(source_code: str) -> str:
    """Safely decode \\xHH and \\uHHHH escape sequences inside string literals.

    Preserves quotes, newlines, and non-printable control bytes to prevent breaking code structure.
    """

    def _decode_string_literal(match: re.Match[str]) -> str:
        quote = match.group(1)
        content = match.group(2)

        def _replace_hex(hex_match: re.Match[str]) -> str:
            hex_str = hex_match.group(1)
            code = int(hex_str, 16)
            if 32 <= code <= 126 and chr(code) not in (quote, "\\"):
                return chr(code)
            return hex_match.group(0)

        def _replace_unicode(uni_match: re.Match[str]) -> str:
            uni_str = uni_match.group(1)
            code = int(uni_str, 16)
            if code >= 32 and chr(code) not in (quote, "\\", "\n", "\r") and code != 0x7F:
                return chr(code)
            return uni_match.group(0)

        decoded = re.sub(r"""\\x([0-9a-fA-F]{2})""", _replace_hex, content)
        decoded = re.sub(r"""\\u([0-9a-fA-F]{4})""", _replace_unicode, decoded)
        return f"{quote}{decoded}{quote}"

    return re.sub(
        r"""(["'])(.*?)(?<!\\)\1""",
        _decode_string_literal,
        source_code,
        flags=re.DOTALL,
    )


def normalize_booleans_and_literals(source_code: str) -> str:
    """Normalize common minification idioms (!0 -> true, !1 -> false, void 0 -> undefined)."""
    text = re.sub(r"""(?<![a-zA-Z0-9_$])!0(?![0-9])""", "true", source_code)
    text = re.sub(r"""(?<![a-zA-Z0-9_$])!1(?![0-9])""", "false", text)
    text = re.sub(r"""(?<![a-zA-Z0-9_$])!!\[\](?![a-zA-Z0-9_$])""", "true", text)
    text = re.sub(r"""(?<![a-zA-Z0-9_$])!\[\](?![a-zA-Z0-9_$])""", "false", text)
    text = re.sub(r"""(?<![a-zA-Z0-9_$])void\s*0(?![0-9])""", "undefined", text)
    text = re.sub(r"""(?<![a-zA-Z0-9_$])void\s*\(\s*0\s*\)""", "undefined", text)
    return text


def unpack_string_arrays(source_code: str) -> str:
    """Detect and inline string array lookup tables common in obfuscated JavaScript."""
    array_pattern = re.compile(
        r"""\b(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\[\s*(['"][^'"]*['"](?:\s*,\s*['"][^'"]*['"])*)\s*\];"""
    )
    result = source_code
    for match in array_pattern.finditer(source_code):
        var_name = match.group(1)
        raw_items = match.group(2)
        items: list[str] = []
        for item_match in re.finditer(r"""(['"])(.*?)(?<!\\)\1""", raw_items):
            items.append(item_match.group(2))

        if not items:
            continue

        def _replace_lookup(lookup_match: re.Match[str], captured_items: list[str] = items) -> str:
            idx_str = lookup_match.group(1)
            try:
                idx = int(idx_str, 0)
                if 0 <= idx < len(captured_items):
                    escaped_val = captured_items[idx].replace('"', '\\"')
                    return f'"{escaped_val}"'
            except ValueError:
                pass
            return lookup_match.group(0)

        lookup_pattern = re.compile(rf"""\b{re.escape(var_name)}\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]""")
        result = lookup_pattern.sub(_replace_lookup, result)

    return result


def normalize_commonjs_params(source_code: str) -> str:
    """Normalize Webpack module wrapper formal parameters to standard CommonJS."""
    return re.sub(
        r"""\bfunction\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*,\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*,\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\)""",
        r"function(module, exports, require)",
        source_code,
    )


def deobfuscate_javascript(
    source_code: str,
    *,
    decode_strings: bool = True,
    normalize_booleans: bool = True,
    unpack_arrays: bool = True,
    normalize_params: bool = True,
) -> str:
    """Apply zero-dependency JavaScript deobfuscation and syntax recovery passes."""
    code = source_code
    if decode_strings:
        code = decode_escaped_strings(code)
    if normalize_booleans:
        code = normalize_booleans_and_literals(code)
    if unpack_arrays:
        code = unpack_string_arrays(code)
    if normalize_params:
        code = normalize_commonjs_params(code)
    return code


def extract_electron_ipc(source_code: str) -> list[IpcChannelFinding]:
    """Statically trace Electron ipcRenderer and ipcMain channel operations."""
    findings: list[IpcChannelFinding] = []

    operation_mode_map = {
        "send": ("renderer", "send"),
        "sendSync": ("renderer", "send"),
        "invoke": ("renderer", "invoke"),
        "postMessage": ("renderer", "send"),
        "sendToHost": ("renderer", "send"),
        "on": ("unknown", "listen"),
        "once": ("unknown", "listen"),
        "addListener": ("unknown", "listen"),
        "handle": ("main", "handle"),
        "handleOnce": ("main", "handle"),
    }

    lines = source_code.splitlines(keepends=True)
    line_offsets: list[int] = [0]
    for line in lines[:-1]:
        line_offsets.append(line_offsets[-1] + len(line))

    def _get_line_number(offset: int) -> int:
        for idx, start in enumerate(line_offsets):
            if idx + 1 < len(line_offsets) and start <= offset < line_offsets[idx + 1]:
                return idx + 1
        return len(line_offsets)

    for match in _IPC_CALL_PATTERN.finditer(source_code):
        target = match.group("target")
        method = match.group("method")
        raw_args = match.group("args").strip()
        line_num = _get_line_number(match.start())

        _, mode = operation_mode_map.get(method, ("unknown", "unknown"))
        side = "renderer" if target == "ipcRenderer" else "main"

        first_arg = raw_args.split(",", 1)[0].strip()
        str_match = re.match(r"""^(['"])(.*?)(?<!\\)\1$""", first_arg)
        if str_match:
            channel: str | None = str_match.group(2)
            channel_expr: str | None = None
        else:
            channel = None
            channel_expr = first_arg if first_arg else None

        findings.append(
            IpcChannelFinding(
                side=side,
                operation=method,
                channel=channel,
                channel_expression=channel_expr,
                mode=mode,
                line_number=line_num,
            )
        )

    return findings


def extract_context_bridge(source_code: str) -> list[ContextBridgeFinding]:
    """Statically trace Electron contextBridge.exposeInMainWorld and exposeInIsolatedWorld exposures."""
    findings: list[ContextBridgeFinding] = []

    lines = source_code.splitlines(keepends=True)
    line_offsets: list[int] = [0]
    for line in lines[:-1]:
        line_offsets.append(line_offsets[-1] + len(line))

    def _get_line_number(offset: int) -> int:
        for idx, start in enumerate(line_offsets):
            if idx + 1 < len(line_offsets) and start <= offset < line_offsets[idx + 1]:
                return idx + 1
        return len(line_offsets)

    for match in _CONTEXT_BRIDGE_PATTERN.finditer(source_code):
        method = match.group("method")
        line_num = _get_line_number(match.start())
        call_start = match.end() - 1  # points to '('
        call_end = find_matching_delimiter(source_code, call_start, "(", ")")
        if call_end == -1:
            continue

        args_str = source_code[call_start + 1 : call_end].strip()
        world = "main" if method == "exposeInMainWorld" else "isolated"

        api_key: str | None = None
        api_key_expr: str | None = None
        api_object_str: str | None = None

        if world == "main":
            first_comma = args_str.find(",")
            if first_comma != -1:
                key_part = args_str[:first_comma].strip()
                str_match = re.match(r"""^(['"])(.*?)(?<!\\)\1$""", key_part)
                if str_match:
                    api_key = str_match.group(2)
                else:
                    api_key_expr = key_part
                api_object_str = args_str[first_comma + 1 :].strip()
        else:
            parts = args_str.split(",", 2)
            if len(parts) >= 2:
                key_part = parts[1].strip()
                str_match = re.match(r"""^(['"])(.*?)(?<!\\)\1$""", key_part)
                if str_match:
                    api_key = str_match.group(2)
                else:
                    api_key_expr = key_part
            if len(parts) >= 3:
                api_object_str = parts[2].strip()

        members: list[str] = []
        if api_object_str and api_object_str.startswith("{"):
            obj_end = find_matching_delimiter(api_object_str, 0, "{", "}")
            if obj_end != -1:
                members = _parse_context_bridge_members(api_object_str[: obj_end + 1])

        findings.append(
            ContextBridgeFinding(
                world=world,
                api_key=api_key,
                api_key_expression=api_key_expr,
                members=tuple(sorted(set(members))),
                line_number=line_num,
            )
        )

    return findings


def _parse_context_bridge_members(obj_str: str, prefix: str = "", depth: int = 0) -> list[str]:
    """Recursively extract dotted member names from an exposed API object literal."""
    if depth > 4 or not obj_str.startswith("{") or not obj_str.endswith("}"):
        return []

    inner = obj_str[1:-1]
    members: list[str] = []
    pos = 0
    n = len(inner)
    while pos < n:
        while pos < n and inner[pos] in " \t\r\n,":
            pos += 1
        if pos >= n:
            break

        key_match = re.match(
            r"""(?:["']([^"']+)["']|([a-zA-Z_$][a-zA-Z0-9_$]*))\s*(?::\s*|(?=\())""",
            inner[pos:],
        )
        if not key_match:
            pos += 1
            continue

        key_name = key_match.group(1) or key_match.group(2)
        full_name = f"{prefix}.{key_name}" if prefix else key_name
        members.append(full_name)

        colon_pos = pos + key_match.end()
        val_start = colon_pos
        while val_start < n and inner[val_start] in " \t\r\n":
            val_start += 1
        if val_start >= n:
            break

        if inner[val_start] == "{":
            nested_end = find_matching_delimiter(inner, val_start, "{", "}")
            if nested_end != -1:
                nested_obj = inner[val_start : nested_end + 1]
                members.extend(_parse_context_bridge_members(nested_obj, prefix=full_name, depth=depth + 1))
                pos = nested_end + 1
                continue

        # Advance past property value by tracking nested brackets/parens to next comma at depth 0
        cur_depth = 0
        in_str: str | None = None
        i = val_start
        while i < n:
            ch = inner[i]
            if in_str is not None:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                i += 1
                continue
            if ch in ('"', "'", "`"):
                in_str = ch
                i += 1
                continue
            if ch in "({[":
                cur_depth += 1
            elif ch in ")}]":
                cur_depth -= 1
            elif ch == "," and cur_depth == 0:
                break
            i += 1

        pos = i + 1

    return members


def run_wakaru_unbundler(
    input_path: Path,
    output_dir: Path,
    *,
    rewrite_level: str = "standard",
    extraction_mode: str = "strict",
    timeout_s: int = 120,
) -> WebDeobfuscationResult | None:
    """Execute external Wakaru CLI engine with strict resource bounds, matching REA recovery."""
    wakaru_bin = resolve_wakaru()
    if wakaru_bin is None:
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    staging = output_dir / "modules"
    staging.mkdir(parents=True, exist_ok=True)

    args = [
        str(wakaru_bin),
        str(input_path),
        f"--unpack={extraction_mode}",
        f"--level={rewrite_level}",
        "--provenance",
        "--emit-source-map",
        "--json",
        "-o",
        str(staging),
    ]

    code, stdout, _stderr = run_cmd_split(args, timeout_s=timeout_s)
    if code not in (0, 1):
        return None

    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        return None

    provenance_file = staging / "provenance.json"
    provenance_data: dict[str, Any] = {}
    if provenance_file.is_file():
        with contextlib.suppress(OSError, json.JSONDecodeError):
            provenance_data = json.loads(provenance_file.read_text(encoding="utf-8"))

    extracted: list[ExtractedModule] = []
    for mod_info in report.get("modules", []):
        filename = mod_info.get("filename", "")
        mod_file = staging / filename
        if mod_file.is_file():
            mod_text = mod_file.read_text(encoding="utf-8", errors="replace")
            mod_bytes = mod_text.encode("utf-8")
            prov = provenance_data.get("modules", {}).get(filename, {})
            ranges = prov.get("ranges", [[0, len(mod_bytes)]])
            start_off = ranges[0][0] if ranges else 0
            end_off = ranges[0][1] if ranges else len(mod_bytes)
            extracted.append(
                ExtractedModule(
                    module_id=filename,
                    code=mod_text,
                    size_bytes=len(mod_bytes),
                    sha256=hashlib.sha256(mod_bytes).hexdigest(),
                    dependencies=extract_module_dependencies(mod_text),
                    start_offset=start_off,
                    end_offset=end_off,
                    export_names=extract_module_exports(mod_text),
                )
            )

    original_code = input_path.read_text(encoding="utf-8", errors="replace")
    ipc_findings = extract_electron_ipc(original_code)
    bridge_findings = extract_context_bridge(original_code)
    bundler_sig = detect_bundler(original_code)

    return WebDeobfuscationResult(
        bundler_signature=bundler_sig,
        modules=tuple(extracted),
        ipc_channels=tuple(ipc_findings),
        context_bridge_apis=tuple(bridge_findings),
        warnings=tuple(w.get("message", "") for w in report.get("warnings", [])),
        engine_used="wakaru",
    )


def analyze_web_bundle(
    source_or_path: str | Path,
    *,
    try_wakaru: bool = True,
    output_dir: Path | None = None,
) -> WebDeobfuscationResult:
    """Analyze a JavaScript bundle or script file for Web and Hybrid pathways."""
    source_code = ""
    file_path: Path | None = None

    if isinstance(source_or_path, Path):
        file_path = source_or_path
        source_code = file_path.read_text(encoding="utf-8", errors="replace")
    elif os.path.exists(source_or_path) and os.path.isfile(source_or_path):
        file_path = Path(source_or_path)
        source_code = file_path.read_text(encoding="utf-8", errors="replace")
    else:
        source_code = str(source_or_path)

    if try_wakaru and file_path is not None and resolve_wakaru() is not None:
        target_out = output_dir or file_path.parent / f"{file_path.stem}_recovered"
        res = run_wakaru_unbundler(file_path, target_out)
        if res is not None:
            return res

    bundler_sig = detect_bundler(source_code)
    extracted_modules = unpack_webpack_bundle(source_code)
    ipc_findings = extract_electron_ipc(source_code)
    bridge_findings = extract_context_bridge(source_code)
    deobfuscated = deobfuscate_javascript(source_code)

    return WebDeobfuscationResult(
        bundler_signature=bundler_sig,
        modules=tuple(extracted_modules),
        ipc_channels=tuple(ipc_findings),
        context_bridge_apis=tuple(bridge_findings),
        deobfuscated_code=deobfuscated,
        engine_used="reforge-builtin",
    )


def process_web_directory(
    directory_path: str | Path,
    *,
    file_patterns: Sequence[str] = ("*.js", "*.cjs", "*.mjs", "*.bundle"),
) -> dict[str, WebDeobfuscationResult]:
    """Scan and analyze all JavaScript bundles within an extracted APK assets or Electron directory."""
    root = Path(directory_path)
    results: dict[str, WebDeobfuscationResult] = {}
    if not root.is_dir():
        return results

    found_files: list[Path] = []
    for pattern in file_patterns:
        found_files.extend(root.rglob(pattern))

    for script_file in sorted(set(found_files)):
        try:
            rel_name = str(script_file.relative_to(root)).replace("\\", "/")
            results[rel_name] = analyze_web_bundle(script_file, try_wakaru=False)
        except OSError:
            continue

    return results
