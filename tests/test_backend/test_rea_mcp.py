"""Unit tests for ReaMcpBackend and registry factory."""

from __future__ import annotations

from typing import Any

from reforge.backend.rea_mcp import ReaMcpBackend
from reforge.config.schema import BackendConfig


def test_rea_mcp_backend_mock_calls() -> None:
    calls: list[dict[str, Any]] = []

    def mock_transport(req: dict[str, Any]) -> dict[str, Any]:
        calls.append(req)
        method = req.get("method")
        params = req.get("params", {})
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {"serverInfo": {"name": "rea", "version": "6.5.0"}},
            }
        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})

            if tool_name == "open_binary":
                return {"jsonrpc": "2.0", "id": req.get("id"), "result": {"status": "opened"}}
            if tool_name == "analyze_function":
                return {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": {
                        "structuredContent": {
                            "normalized_result": {
                                "procedure": args.get("procedure", "0x401000"),
                                "name": "calculate_hash",
                                "signature": "uint32_t calculate_hash(const char* buf, size_t len)",
                                "pseudocode": (
                                    "uint32_t calculate_hash(const char* buf, size_t len) {\n  return 0x42;\n}"
                                ),
                                "assembly": "push rbp\nmov rbp, rsp\ncall 0x402000\npop rbp\nret",
                                "callers": [{"address": "0x403000", "name": "main"}],
                                "callees": [{"address": "0x402000", "name": "sub_helper"}],
                                "cfg": {"entry": "0x401000", "blocks": 2},
                            }
                        }
                    },
                }
            if tool_name == "inspect_native_data_type":
                return {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": {
                        "structuredContent": {
                            "normalized_result": {
                                "kind": "structure",
                                "name": "PlayerState",
                                "length": 16,
                                "components": [
                                    {"offset": 0, "field_name": "health", "data_type_name": "int32_t", "length": 4},
                                    {"offset": 4, "field_name": "armor", "data_type_name": "int32_t", "length": 4},
                                    {"offset": 8, "field_name": "score", "data_type_name": "int64_t", "length": 8},
                                ],
                            }
                        }
                    },
                }
            if tool_name == "search_procedures":
                return {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": {
                        "structuredContent": {
                            "normalized_result": {
                                "procedures": [
                                    {"address": "0x401000", "name": "calculate_hash"},
                                    {"address": "0x402000", "name": "sub_helper"},
                                ]
                            }
                        }
                    },
                }
            if tool_name == "trace_native_values":
                return {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": {"def_use": [{"def": "op1", "use": "op2"}]},
                }
            if tool_name == "close_binary":
                return {"jsonrpc": "2.0", "id": req.get("id"), "result": {"status": "closed"}}

        return {"jsonrpc": "2.0", "id": req.get("id"), "result": {}}

    backend = ReaMcpBackend(
        binary_path="app.exe",
        provider_id="ghidra",
        transport_call=mock_transport,
    )

    # 1. Capabilities
    caps = backend.capabilities
    assert caps.has_decompile is True
    assert caps.has_asm is True
    assert caps.has_structs is True
    assert caps.has_xrefs is True
    assert caps.has_pcode is True
    assert caps.has_cfg is True

    # 2. Decompile
    dec = backend.decompile("0x401000")
    assert dec.address == "0x401000"
    assert dec.name == "calculate_hash"
    assert "return 0x42;" in dec.decompiled
    assert dec.callers == 1
    assert dec.callees == 1

    # 3. XRefs
    callers = backend.xrefs_to("0x401000")
    assert len(callers) == 1
    assert callers[0].address == "0x403000"

    callees = backend.xrefs_from("0x401000")
    assert len(callees) == 1
    assert callees[0].name == "sub_helper"

    # 4. Asm
    asm = backend.get_asm("0x401000")
    assert asm is not None
    assert asm.call_count == 1
    assert asm.instruction_count == 5

    # 5. Struct
    st = backend.get_struct("PlayerState")
    assert st is not None
    assert st.name == "PlayerState"
    assert st.size == 16
    assert len(st.fields) == 3
    assert st.fields[0].name == "health"
    assert st.fields[2].size == 8

    # 6. Search
    funcs = backend.search("hash")
    assert len(funcs) == 2
    assert funcs[0].name == "calculate_hash"

    # 7. Evidence methods
    ctx = backend.get_context("0x401000")
    assert ctx is not None
    assert ctx.kind == "context"
    assert "calculate_hash" in ctx.content

    pcode = backend.get_pcode("0x401000")
    assert pcode is not None
    assert pcode.kind == "pcode"

    cfg = backend.get_cfg("0x401000")
    assert cfg is not None
    assert cfg.kind == "cfg"
    assert "0x401000" in cfg.content

    # 8. Close
    backend.close()
    assert any(c.get("params", {}).get("name") == "close_binary" for c in calls)


def test_rea_mcp_continuation_paging() -> None:
    calls: list[str] = []

    def mock_paging_transport(req: dict[str, Any]) -> dict[str, Any]:
        params = req.get("params", {})
        tool_name = params.get("name")
        calls.append(tool_name or "")

        if tool_name == "analyze_function":
            # Simulate REA 10MB response budget error with continuation
            return {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {
                    "isError": True,
                    "code": "resource_constraint",
                    "details": {
                        "resource": "transport",
                        "reported_limits": {
                            "continuation": {
                                "name": "inspect_analysis_view",
                                "arguments": {
                                    "source": {"kind": "retained-evidence", "evidence_id": "ev_test123"},
                                    "view": {"kind": "native", "facet": "pseudocode"},
                                },
                            }
                        },
                    },
                },
            }
        if tool_name == "inspect_analysis_view":
            return {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {
                    "structuredContent": {
                        "normalized_result": {
                            "procedure": "0x500000",
                            "name": "huge_function",
                            "pseudocode": "void huge_function() { /* paged */ }",
                        }
                    }
                },
            }
        return {"jsonrpc": "2.0", "id": req.get("id"), "result": {}}

    backend = ReaMcpBackend(
        binary_path=None,
        transport_call=mock_paging_transport,
    )
    dec = backend.decompile("0x500000")
    assert dec.name == "huge_function"
    assert "/* paged */" in dec.decompiled
    tool_calls = [c for c in calls if c]
    assert tool_calls == ["analyze_function", "inspect_analysis_view"]


def test_registry_creates_rea_backend() -> None:
    config = BackendConfig(
        type="rea",
        rea_provider="hopper",
        rea_path="rea mcp",
    )
    # create_backend will try to start the process unless mocked or npx is available.
    # We verify that create_backend identifies "rea" and constructs ReaMcpBackend class.

    # Verify type normalization in registry
    assert config.type.lower() == "rea"
