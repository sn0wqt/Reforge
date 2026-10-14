"""Unit tests for SSA def-use value flow modeling, comparison, and parity verification."""

from __future__ import annotations

import json
from typing import Any

from reforge.config.schema import ParityConfig
from reforge.core.models import GhidraData, HookEntry, ParityStatus, SemanticRule, SourceMatch
from reforge.parity.engine import score_single
from reforge.parity.rules import apply_semantic_rules
from reforge.parity.value_flow import (
    Varnode,
    check_value_flow_branch_conditions,
    check_value_flow_memory_writes,
    check_value_flow_parameter_usage,
    compare_value_flow,
    evaluate_value_flow_checks,
    normalize_value_flow,
    parse_value_flow,
)


def _make_source(**kwargs: object) -> SourceMatch:
    defaults: dict[str, object] = dict(
        path="test.cpp",
        line=1,
        body="{ return 42; }",
        body_no_comments="{ return 42; }",
        body_lines=3,
        call_count=0,
        plugin_call_count=0,
        non_plugin_call_count=0,
        control_flow_count=0,
        has_stub_marker=False,
        has_fp_token=False,
        is_inline_internal_forwarder=False,
    )
    defaults.update(kwargs)
    return SourceMatch(**defaults)  # type: ignore[arg-type]


def _sample_native_value_flow() -> dict[str, Any]:
    """Sample JSON payload matching REA nativeValueFlowSchema."""
    return {
        "available": True,
        "provenance": "ghidra-high-pcode",
        "operations": [
            {
                "id": "0x10040#1",
                "address": "0x10040",
                "sequence": 1,
                "opcode": "LOAD",
                "is_dead": False,
                "block_membership": "member",
                "inputs": [
                    {"kind": "constant", "size_bytes": 4, "location": None, "constant_hex": "0"},
                    {"kind": "register", "size_bytes": 4, "location": "ECX", "constant_hex": None},
                ],
                "output": {"kind": "unique", "size_bytes": 4, "location": "u0x10", "constant_hex": None},
            },
            {
                "id": "0x10044#2",
                "address": "0x10044",
                "sequence": 2,
                "opcode": "INT_ADD",
                "is_dead": False,
                "block_membership": "member",
                "inputs": [
                    {"kind": "unique", "size_bytes": 4, "location": "u0x10", "constant_hex": None},
                    {"kind": "constant", "size_bytes": 4, "location": None, "constant_hex": "2a"},
                ],
                "output": {"kind": "unique", "size_bytes": 4, "location": "u0x20", "constant_hex": None},
            },
            {
                "id": "0x10048#3",
                "address": "0x10048",
                "sequence": 3,
                "opcode": "STORE",
                "is_dead": False,
                "block_membership": "member",
                "inputs": [
                    {"kind": "constant", "size_bytes": 4, "location": None, "constant_hex": "0"},
                    {"kind": "register", "size_bytes": 4, "location": "ECX", "constant_hex": None},
                    {"kind": "unique", "size_bytes": 4, "location": "u0x20", "constant_hex": None},
                ],
                "output": None,
            },
            {
                "id": "0x1004c#4",
                "address": "0x1004c",
                "sequence": 4,
                "opcode": "CBRANCH",
                "is_dead": False,
                "block_membership": "member",
                "inputs": [
                    {"kind": "address", "size_bytes": 4, "location": "0x10060", "constant_hex": None},
                    {"kind": "unique", "size_bytes": 1, "location": "u0x30", "constant_hex": None},
                ],
                "output": None,
            },
        ],
        "def_use": [
            {"definition": "0x10040#1", "use": "0x10044#2", "input_index": 0},
            {"definition": "0x10044#2", "use": "0x10048#3", "input_index": 2},
        ],
        "parameter_uses": [
            {"ordinal": 0, "use": "0x10040#1", "input_index": 1},
            {"ordinal": 0, "use": "0x10048#3", "input_index": 1},
        ],
        "effects": [
            {"operation": "0x10040#1", "kind": "memory_read", "operand_input": 1, "value_input": None},
            {"operation": "0x10048#3", "kind": "memory_write", "operand_input": 1, "value_input": 2},
            {"operation": "0x1004c#4", "kind": "conditional_branch", "operand_input": None, "value_input": 1},
        ],
        "parameters": [
            {"ordinal": 0, "name": "targetObj", "data_type": "CObject*"},
        ],
        "truncated": False,
        "omitted_operations_lower_bound": 0,
        "known_omitted_inputs": 0,
        "known_omitted_edges": 0,
        "limitations": [],
    }


def test_varnode_properties() -> None:
    v_const = Varnode(kind="constant", size_bytes=4, constant_hex="2a")
    assert v_const.is_constant
    assert not v_const.is_register
    assert v_const.constant_value == 42

    v_reg = Varnode(kind="register", size_bytes=4, location="EAX")
    assert v_reg.is_register
    assert not v_reg.is_constant
    assert v_reg.constant_value is None

    v_uniq = Varnode(kind="unique", size_bytes=4, location="u0x10")
    assert v_uniq.is_unique

    v_addr = Varnode(kind="address", size_bytes=4, location="0x1000")
    assert v_addr.is_address


def test_parse_native_value_flow() -> None:
    raw = _sample_native_value_flow()
    graph = parse_value_flow(raw)
    assert graph is not None
    assert graph.available
    assert len(graph.operations) == 4
    assert len(graph.def_use) == 2
    assert len(graph.parameter_uses) == 2
    assert len(graph.effects) == 3
    assert len(graph.parameters) == 1

    assert graph.get_memory_write_count() == 1
    assert graph.get_memory_read_count() == 1
    assert graph.get_conditional_branch_count() == 1
    assert graph.get_call_count() == 0

    assert graph.get_used_parameter_ordinals() == {0}

    op2 = graph.get_op("0x10044#2")
    assert op2 is not None
    assert op2.opcode == "INT_ADD"
    assert len(op2.inputs) == 2
    assert op2.inputs[1].constant_value == 42


def test_parse_from_json_string() -> None:
    raw_str = json.dumps(_sample_native_value_flow())
    graph = parse_value_flow(raw_str)
    assert graph is not None
    assert graph.available
    assert len(graph.operations) == 4


def test_parse_unavailable() -> None:
    raw = {
        "available": False,
        "reason": "Ghidra has no HighFunction model for this procedure",
        "limitations": ["No p-code recovered"],
    }
    graph = parse_value_flow(raw)
    assert graph is not None
    assert not graph.available
    assert "No p-code recovered" in graph.limitations


def test_parse_trace_format() -> None:
    trace_raw = {
        "nodes": [
            {
                "kind": "operation",
                "operation": {
                    "id": "op_load",
                    "address": "0x2000",
                    "sequence": 0,
                    "opcode": "LOAD",
                    "inputs": [{"kind": "register", "size_bytes": 4, "location": "EAX"}],
                    "output": {"kind": "unique", "size_bytes": 4, "location": "u1"},
                },
            },
            {
                "kind": "parameter",
                "parameter": {"ordinal": 0, "name": "arg0", "data_type": "int"},
            },
        ],
        "edges": [
            {"kind": "parameter-use", "source": "arg0", "target": "op_load", "input_index": 0},
        ],
    }
    graph = parse_value_flow(trace_raw)
    assert graph is not None
    assert graph.available
    assert len(graph.operations) == 1
    assert len(graph.parameters) == 1
    assert len(graph.parameter_uses) == 1
    assert graph.get_memory_read_count() == 1


def test_normalize_value_flow() -> None:
    graph = parse_value_flow(_sample_native_value_flow())
    assert graph is not None
    norm = normalize_value_flow(graph)
    assert norm is not None
    assert norm.opcodes == ["LOAD", "INT_ADD", "STORE", "CBRANCH"]
    # def-use edges should be mapped to local indices: 0 -> 1, 1 -> 2
    assert norm.indexed_edges == [(0, 1, 0), (1, 2, 2)]
    # param uses: (0, 0, 1), (0, 2, 1)
    assert (0, 0, 1) in norm.indexed_param_uses
    assert (0, 2, 1) in norm.indexed_param_uses
    # effects: (0, memory_read), (2, memory_write), (3, conditional_branch)
    assert (0, "memory_read") in norm.indexed_effects
    assert (2, "memory_write") in norm.indexed_effects


def test_compare_value_flow_identical() -> None:
    graph1 = parse_value_flow(_sample_native_value_flow())
    graph2 = parse_value_flow(_sample_native_value_flow())
    assert graph1 is not None and graph2 is not None

    res = compare_value_flow(graph1, graph2)
    assert res.status == "unchanged"
    assert len(res.differences) == 0


def test_compare_value_flow_changed() -> None:
    raw1 = _sample_native_value_flow()
    raw2 = _sample_native_value_flow()
    # Modify second graph to omit STORE operation and effect
    raw2["operations"] = [op for op in raw2["operations"] if op["opcode"] != "STORE"]
    raw2["effects"] = [e for e in raw2["effects"] if e["kind"] != "memory_write"]

    graph1 = parse_value_flow(raw1)
    graph2 = parse_value_flow(raw2)
    assert graph1 is not None and graph2 is not None

    res = compare_value_flow(graph1, graph2)
    assert res.status == "changed"
    assert any("Memory writes mismatch" in d for d in res.differences)


def test_compare_value_flow_unresolved() -> None:
    graph1 = parse_value_flow(_sample_native_value_flow())
    graph2 = parse_value_flow({"available": False, "limitations": ["Unavailable"]})
    assert graph1 is not None and graph2 is not None

    res = compare_value_flow(graph1, graph2)
    assert res.status == "unresolved"


def test_signal_memory_writes_violation() -> None:
    # High-Pcode has 1 STORE (memory_write)
    vf = parse_value_flow(_sample_native_value_flow())
    ghidra = GhidraData(decompile_ok=True, value_flow=vf)

    # Pure getter returning constant, no assignments/mutations
    source = _make_source(
        body="int GetVal() { return 42; }",
        body_no_comments="int GetVal() { return 42; }",
    )

    finding = check_value_flow_memory_writes(source=source, ghidra=ghidra)
    assert finding is not None
    assert finding.level == "red"
    assert "memory write" in finding.reason


def test_signal_memory_writes_satisfied() -> None:
    vf = parse_value_flow(_sample_native_value_flow())
    ghidra = GhidraData(decompile_ok=True, value_flow=vf)

    # Source has state mutation
    source = _make_source(
        body="void SetVal(int v) { m_nValue = v + 42; }",
        body_no_comments="void SetVal(int v) { m_nValue = v + 42; }",
    )

    finding = check_value_flow_memory_writes(source=source, ghidra=ghidra)
    assert finding is None


def test_signal_branch_conditions() -> None:
    # Add a second conditional branch to value flow
    raw = _sample_native_value_flow()
    raw["effects"].append({"operation": "0x10050#5", "kind": "conditional_branch", "value_input": 1})
    raw["operations"].append({
        "id": "0x10050#5",
        "address": "0x10050",
        "sequence": 5,
        "opcode": "CBRANCH",
        "inputs": [],
        "output": None,
    })
    vf = parse_value_flow(raw)
    ghidra = GhidraData(decompile_ok=True, value_flow=vf)

    # Source with control_flow_count == 0
    source = _make_source(control_flow_count=0)
    finding = check_value_flow_branch_conditions(source=source, ghidra=ghidra)
    assert finding is not None
    assert finding.level == "yellow"
    assert "conditional branch" in finding.reason

    # Source with control_flow_count > 0
    source_with_branch = _make_source(control_flow_count=2)
    assert check_value_flow_branch_conditions(source=source_with_branch, ghidra=ghidra) is None


def test_signal_parameter_usage() -> None:
    vf = parse_value_flow(_sample_native_value_flow())
    ghidra = GhidraData(decompile_ok=True, value_flow=vf)

    # Source does not reference param 'targetObj'
    source = _make_source(
        body="void Process() { DoSomething(); }",
        body_no_comments="void Process() { DoSomething(); }",
    )
    finding = check_value_flow_parameter_usage(source=source, ghidra=ghidra)
    assert finding is not None
    assert finding.level == "yellow"
    assert "targetObj" in finding.reason

    # Source references targetObj
    source_with_param = _make_source(
        body="void Process(CObject* targetObj) { targetObj->Update(); }",
        body_no_comments="void Process(CObject* targetObj) { targetObj->Update(); }",
    )
    assert check_value_flow_parameter_usage(source=source_with_param, ghidra=ghidra) is None


def test_evaluate_value_flow_checks() -> None:
    vf = parse_value_flow(_sample_native_value_flow())

    checks: list[dict[str, Any]] = [
        {"min_memory_writes": 1, "max_memory_writes": 2},
        {"min_memory_reads": 1},
        {"requires_effects": ["memory_write", "memory_read"]},
        {"forbidden_effects": ["direct_call"]},
        {"requires_param_use": [0]},
    ]
    errors = evaluate_value_flow_checks(vf, checks)
    assert len(errors) == 0

    failing_checks: list[dict[str, Any]] = [
        {"min_memory_writes": 5},
        {"forbidden_effects": ["memory_write"]},
        {"requires_param_use": [1]},
    ]
    errs = evaluate_value_flow_checks(vf, failing_checks)
    assert len(errs) == 3
    assert any("at least 5 memory write" in e for e in errs)
    assert any("forbidden effect(s): memory_write" in e for e in errs)
    assert any("Parameter ordinal 1 has no def-use" in e for e in errs)


def test_semantic_rule_integration() -> None:
    entry = HookEntry(
        class_path="CTrain",
        fn_name="ProcessControl",
        address="0x6f86a0",
        reversed=True,
        locked=False,
        is_virtual=False,
    )
    vf = parse_value_flow(_sample_native_value_flow())
    rule = SemanticRule(
        id="RULE-VF-1",
        reason="Function must write state and not invoke direct calls",
        severity="red",
        addresses=["0x6f86a0"],
        value_flow_checks=[
            {"min_memory_writes": 1, "forbidden_effects": ["direct_call"]},
        ],
    )

    findings = apply_semantic_rules(entry, "{ m_val = 1; }", [rule], value_flow=vf)
    assert len(findings) == 0

    rule_fail = SemanticRule(
        id="RULE-VF-2",
        reason="Must have at least 3 memory writes",
        severity="red",
        addresses=["0x6f86a0"],
        value_flow_checks=[{"min_memory_writes": 3}],
    )
    findings_fail = apply_semantic_rules(entry, "{ m_val = 1; }", [rule_fail], value_flow=vf)
    assert len(findings_fail) == 1
    assert "Expected at least 3 memory write(s)" in findings_fail[0].reason


def test_engine_score_single_with_value_flow() -> None:
    vf = parse_value_flow(_sample_native_value_flow())
    ghidra = GhidraData(
        decompile_ok=True,
        asm_ok=True,
        asm_instruction_count=20,
        asm_call_count=0,
        callees=0,
        value_flow=vf,
    )
    # Stub source with no mutations -> triggers value flow memory write signal (RED)
    source = _make_source(
        body="{ return 0; }",
        body_no_comments="{ return 0; }",
        body_lines=3,
    )
    entry = HookEntry(
        class_path="CTest",
        fn_name="Func",
        address="0x10040",
        reversed=True,
        locked=False,
        is_virtual=False,
    )
    config = ParityConfig(enabled=True)
    status, findings = score_single(entry, source, ghidra, config)
    assert status == ParityStatus.RED
    assert any("memory write" in f.reason for f in findings)
