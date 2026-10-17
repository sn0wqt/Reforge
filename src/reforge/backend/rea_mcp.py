"""REA MCP Backend: connects Reforge to REA's MCP reverse-engineering server."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shlex
import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from reforge.backend.protocol import BackendCapabilities, EvidenceBackend, REBackend
from reforge.core.models import (
    AnalysisArtifact,
    AsmResult,
    DecompileResult,
    EnumDef,
    EnumValue,
    FunctionEntry,
    StructDef,
    StructField,
    XRef,
)

logger = logging.getLogger(__name__)


class ReaMcpBackend(REBackend, EvidenceBackend):
    """REBackend implementation communicating with REA (rea-agents) over stdio MCP."""

    def __init__(
        self,
        binary_path: str | Path | None = None,
        *,
        provider_id: str = "auto",
        cli_cmd: str = "npx -y rea-agents mcp",
        timeout_s: float = 60.0,
        transport_call: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        """Initialize the REA MCP bridge.

        Args:
            binary_path: Optional path to binary file or archive to open.
            provider_id: REA decompiler engine ("auto", "ghidra", "hopper", "ida", "cutter", "rizin").
            cli_cmd: Shell command string to start the REA MCP server over stdio.
            timeout_s: Request timeout in seconds.
            transport_call: Optional custom transport callable for tests.
        """
        self.binary_path = str(binary_path) if binary_path is not None else None
        self.provider_id = provider_id
        self.cli_cmd = cli_cmd
        self.timeout_s = timeout_s
        self._custom_transport = transport_call

        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._msg_id = 0
        self._session_open = False

        if self._custom_transport is None:
            self._start_server()
        else:
            self._init_session()

    @property
    def capabilities(self) -> BackendCapabilities:
        """Return full spectrum capabilities supported via REA."""
        return BackendCapabilities(
            has_decompile=True,
            has_asm=True,
            has_structs=True,
            has_xrefs=True,
            has_search=True,
            has_enums=True,
            has_context=True,
            has_vtables=True,
            has_globals=True,
            has_strings=True,
            has_pcode=True,
            has_cfg=True,
        )

    def _start_server(self) -> None:
        """Spawn REA MCP server subprocess."""
        args = shlex.split(self.cli_cmd, posix=(os.name != "nt"))
        if os.name == "nt" and args:
            resolved_bin = shutil.which(args[0])
            if resolved_bin and resolved_bin.lower().endswith((".cmd", ".bat")):
                args = ["cmd.exe", "/c", resolved_bin, *args[1:]]
            elif args[0].lower() in {"npx", "rea"}:
                args = ["cmd.exe", "/c", *args]
        try:
            self._proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as e:
            raise RuntimeError(f"Failed to launch REA MCP server with command {self.cli_cmd!r}: {e}") from e

        self._init_session()

    def _call_raw_rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC request and read the response line."""
        if self._custom_transport is not None:
            req = {"jsonrpc": "2.0", "id": self._msg_id, "method": method, "params": params or {}}
            return self._custom_transport(req)

        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("REA MCP server process is not active")

        with self._lock:
            self._msg_id += 1
            req_id = self._msg_id
            payload = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params or {},
            }
            line = json.dumps(payload) + "\n"
            try:
                self._proc.stdin.write(line)
                self._proc.stdin.flush()
                resp_line = self._proc.stdout.readline()
                if not resp_line:
                    raise RuntimeError("REA MCP server closed connection unexpectedly")
                resp: dict[str, Any] = json.loads(resp_line)
                return resp
            except (OSError, json.JSONDecodeError) as e:
                raise RuntimeError(f"Error during REA MCP communication: {e}") from e

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute an MCP tool and return its result."""
        resp = self._call_raw_rpc("tools/call", {"name": tool_name, "arguments": arguments})
        if "error" in resp:
            err = resp["error"]
            raise RuntimeError(f"REA tool {tool_name!r} failed: {err.get('message', err)}")

        raw_result = resp.get("result")
        result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
        if result.get("isError"):
            # Check for resource_constraint and inspect continuation
            details = result.get("details", {})
            reported = details.get("reported_limits", {}) if isinstance(details, dict) else {}
            continuation = reported.get("continuation") if isinstance(reported, dict) else None
            if continuation and isinstance(continuation, dict):
                c_name = continuation.get("name")
                c_args = continuation.get("arguments", {})
                if c_name:
                    logger.info("REA resource constraint encountered; paging via %s", c_name)
                    return self.call_tool(c_name, c_args)

            err_text = ""
            for item in result.get("content", []):
                if isinstance(item, dict) and item.get("type") == "text":
                    err_text += item.get("text", "")
            raise RuntimeError(f"REA tool {tool_name!r} returned error: {err_text or result}")

        return result

    def _init_session(self) -> None:
        """Perform MCP initialization handshake and open target binary if configured."""
        try:
            self._call_raw_rpc(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "reforge", "version": "0.4.0"},
                },
            )
        except Exception as e:
            logger.debug("REA initialize handshake: %s", e)

        if self.binary_path:
            try:
                self.call_tool(
                    "open_binary",
                    {"path": self.binary_path, "provider_id": self.provider_id},
                )
                self._session_open = True
            except Exception as e:
                logger.warning("Could not open binary in REA: %s", e)

    # --- REBackend Protocol Implementation ---

    def decompile(self, target: str) -> DecompileResult:
        """Decompile a function via REA analyze_function."""
        res = self.call_tool("analyze_function", {"procedure": target})
        structured = res.get("structuredContent", {})
        norm = structured.get("normalized_result", {}) if isinstance(structured, dict) else {}

        pseudocode = norm.get("pseudocode", "")
        proc_addr = norm.get("procedure", target)
        proc_name = norm.get("name", target)
        callers = norm.get("callers", [])
        callees = norm.get("callees", [])

        caller_count = len(callers) if isinstance(callers, list) else 0
        callee_count = len(callees) if isinstance(callees, list) else 0

        return DecompileResult(
            address=str(proc_addr),
            name=str(proc_name),
            signature=str(norm.get("signature", "")),
            decompiled=str(pseudocode),
            raw_output=json.dumps(norm, indent=2),
            callers=caller_count,
            callees=callee_count,
        )

    def xrefs_to(self, target: str) -> list[XRef]:
        """Return callers targeting the procedure."""
        res = self.call_tool("analyze_function", {"procedure": target})
        structured = res.get("structuredContent", {})
        norm = structured.get("normalized_result", {}) if isinstance(structured, dict) else {}
        callers = norm.get("callers", [])
        xrefs: list[XRef] = []
        if isinstance(callers, list):
            for c in callers:
                if isinstance(c, dict):
                    addr = str(c.get("address", ""))
                    name = str(c.get("name", ""))
                    xrefs.append(XRef(address=addr, name=name, ref_type="CALL"))
        return xrefs

    def xrefs_from(self, target: str) -> list[XRef]:
        """Return callees invoked from the procedure."""
        res = self.call_tool("analyze_function", {"procedure": target})
        structured = res.get("structuredContent", {})
        norm = structured.get("normalized_result", {}) if isinstance(structured, dict) else {}
        callees = norm.get("callees", [])
        xrefs: list[XRef] = []
        if isinstance(callees, list):
            for c in callees:
                if isinstance(c, dict):
                    addr = str(c.get("address", ""))
                    name = str(c.get("name", ""))
                    xrefs.append(XRef(address=addr, name=name, ref_type="CALL"))
        return xrefs

    def get_struct(self, name: str) -> StructDef | None:
        """Retrieve structure definition via inspect_native_data_type."""
        try:
            res = self.call_tool("inspect_native_data_type", {"category_path": name})
        except Exception:
            return None

        structured = res.get("structuredContent", {})
        norm = structured.get("normalized_result", {}) if isinstance(structured, dict) else {}
        if not norm or norm.get("kind") not in ("structure", "composite"):
            return None

        fields: list[StructField] = []
        for f in norm.get("components", []):
            if isinstance(f, dict):
                fields.append(
                    StructField(
                        offset=int(f.get("offset", 0)),
                        name=str(f.get("field_name", "")),
                        type_str=str(f.get("data_type_name", "void*")),
                        size=int(f.get("length", 4)),
                    )
                )

        return StructDef(
            name=str(norm.get("name", name)),
            size=int(norm.get("length", 0)),
            fields=fields,
        )

    def get_enum(self, name: str) -> EnumDef | None:
        """Retrieve enum definition via inspect_native_data_type."""
        try:
            res = self.call_tool("inspect_native_data_type", {"category_path": name})
        except Exception:
            return None

        structured = res.get("structuredContent", {})
        norm = structured.get("normalized_result", {}) if isinstance(structured, dict) else {}
        if not norm or norm.get("kind") != "enum":
            return None

        values: list[EnumValue] = []
        for m in norm.get("members", []):
            if isinstance(m, dict):
                m_name = str(m.get("name", ""))
                m_val = int(m.get("value", 0))
                values.append(EnumValue(name=m_name, value=m_val))

        return EnumDef(
            name=str(norm.get("name", name)),
            values=values,
        )

    def get_asm(self, target: str) -> AsmResult | None:
        """Retrieve disassembly via analyze_function assembly facet."""
        try:
            res = self.call_tool("analyze_function", {"procedure": target})
        except Exception:
            return None

        structured = res.get("structuredContent", {})
        norm = structured.get("normalized_result", {}) if isinstance(structured, dict) else {}
        raw_asm = norm.get("assembly", "")
        if not raw_asm:
            return None

        lines = [line.strip() for line in str(raw_asm).splitlines() if line.strip()]
        call_count = sum(1 for line in lines if "call" in line.lower())
        has_fp = any(tok in raw_asm.lower() for tok in ("xmm", "ymm", "float", "double", "fld", "fst"))

        return AsmResult(
            address=target,
            instructions=str(raw_asm),
            instruction_count=len(lines),
            call_count=call_count,
            has_fp_sensitive=has_fp,
        )

    def search(self, pattern: str) -> list[FunctionEntry]:
        """Search functions matching a symbol or regex pattern."""
        try:
            res = self.call_tool("search_procedures", {"pattern": pattern, "regex": False})
        except Exception:
            return []

        structured = res.get("structuredContent", {})
        norm = structured.get("normalized_result", {}) if isinstance(structured, dict) else {}
        entries: list[FunctionEntry] = []
        for item in norm.get("procedures", []):
            if isinstance(item, dict):
                entries.append(
                    FunctionEntry(
                        address=str(item.get("address", "")),
                        name=str(item.get("name", "")),
                    )
                )
        return entries

    def unimplemented(self, filter_pattern: str | None = None) -> list[FunctionEntry]:
        return self.search(filter_pattern or "")

    def remaining(self, class_name: str | None = None) -> list[FunctionEntry]:
        return self.search(class_name or "")

    # --- EvidenceBackend Protocol Implementation ---

    def get_context(self, target: str) -> AnalysisArtifact | None:
        """Return the canonical function dossier as an evidence artifact."""
        try:
            res = self.call_tool("analyze_function", {"procedure": target})
            return AnalysisArtifact(
                kind="context",
                target=target,
                content=json.dumps(res, indent=2),
            )
        except Exception:
            return None

    def get_vtable(self, target: str) -> AnalysisArtifact | None:
        return None

    def get_global(self, target: str) -> AnalysisArtifact | None:
        return None

    def search_strings(self, pattern: str) -> AnalysisArtifact | None:
        """Search defined strings across the binary."""
        try:
            res = self.call_tool("search_strings", {"pattern": pattern, "regex": False})
            return AnalysisArtifact(
                kind="strings",
                target=pattern,
                content=json.dumps(res, indent=2),
            )
        except Exception:
            return None

    def get_pcode(self, target: str) -> AnalysisArtifact | None:
        """Extract high-Pcode def-use flow from REA trace_native_values."""
        try:
            res = self.call_tool("trace_native_values", {"procedure": target})
            return AnalysisArtifact(
                kind="pcode",
                target=target,
                content=json.dumps(res, indent=2),
            )
        except Exception:
            return None

    def get_cfg(self, target: str) -> AnalysisArtifact | None:
        """Extract basic block CFG graph from analyze_function."""
        try:
            res = self.call_tool("analyze_function", {"procedure": target})
            structured = res.get("structuredContent", {})
            norm = structured.get("normalized_result", {}) if isinstance(structured, dict) else {}
            cfg = norm.get("cfg", {})
            return AnalysisArtifact(
                kind="cfg",
                target=target,
                content=json.dumps(cfg, indent=2),
            )
        except Exception:
            return None

    def close(self) -> None:
        """Safely close active REA session and terminate server subprocess."""
        if self._session_open:
            with contextlib.suppress(Exception):
                self.call_tool("close_binary", {})
            self._session_open = False

        if self._proc is not None:
            try:
                if self._proc.stdin:
                    self._proc.stdin.close()
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(self._proc.pid), "/T", "/F"],
                        capture_output=True,
                        check=False,
                        timeout=5.0,
                    )
                else:
                    self._proc.terminate()
                self._proc.wait(timeout=5.0)
            except Exception:
                with contextlib.suppress(Exception):
                    self._proc.kill()
            self._proc = None
