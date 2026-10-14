"""SSA Def-Use and Value Flow modeling, normalization, and parity verification.

Models Ghidra High-Pcode AST, SSA def-use chains, Varnodes, and semantic effects
derived from REA (Reverse Engineering Assistant) native value flow observations.
Provides structural value flow comparisons and static parity heuristic signals.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from reforge.core.models import Finding, GhidraData, SourceMatch

# ---------------------------------------------------------------------------
# High-Pcode Varnode & Operation Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Varnode:
    """A decompiler P-code Varnode location or literal value."""

    kind: str  # "constant", "address", "register", "unique", "other"
    size_bytes: int = 0
    location: str | None = None
    constant_hex: str | None = None

    @property
    def is_constant(self) -> bool:
        return self.kind == "constant"

    @property
    def is_register(self) -> bool:
        return self.kind == "register"

    @property
    def is_unique(self) -> bool:
        return self.kind == "unique"

    @property
    def is_address(self) -> bool:
        return self.kind == "address"

    @property
    def constant_value(self) -> int | None:
        if self.constant_hex is not None:
            try:
                return int(self.constant_hex, 16)
            except ValueError:
                return None
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "size_bytes": self.size_bytes,
            "location": self.location,
            "constant_hex": self.constant_hex,
        }


@dataclass
class PcodeOp:
    """One High-Pcode operation recovered for a single procedure."""

    id: str
    address: str
    sequence: int
    opcode: str
    is_dead: bool = False
    block_membership: str = "member"  # "member", "detached", "unavailable"
    inputs: list[Varnode] = field(default_factory=list)
    output: Varnode | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "address": self.address,
            "sequence": self.sequence,
            "opcode": self.opcode,
            "is_dead": self.is_dead,
            "block_membership": self.block_membership,
            "inputs": [inp.to_dict() for inp in self.inputs],
            "output": self.output.to_dict() if self.output else None,
        }


@dataclass(frozen=True)
class DefUseEdge:
    """A def-use relation between operations in one recovered HighFunction."""

    definition: str  # defining operation ID
    use: str  # consuming operation ID
    input_index: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "definition": self.definition,
            "use": self.use,
            "input_index": self.input_index,
        }


@dataclass(frozen=True)
class ParameterUse:
    """A def-use link from a formal parameter into a consuming operation."""

    ordinal: int
    use: str
    input_index: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "use": self.use,
            "input_index": self.input_index,
        }


@dataclass(frozen=True)
class PcodeEffect:
    """Memory and branch operations directly classified from Ghidra P-code."""

    operation: str
    kind: str  # "memory_read", "memory_write", "conditional_branch", "indirect_branch", "direct_call", "indirect_call"
    operand_input: int | None = None
    value_input: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "kind": self.kind,
            "operand_input": self.operand_input,
            "value_input": self.value_input,
        }


@dataclass(frozen=True)
class FunctionParameter:
    """Formal parameter metadata from HighFunction prototype."""

    ordinal: int
    name: str
    data_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "name": self.name,
            "data_type": self.data_type,
        }


# ---------------------------------------------------------------------------
# Value Flow Graph
# ---------------------------------------------------------------------------


@dataclass
class ValueFlowGraph:
    """Complete static value flow representation for a procedure."""

    available: bool = True
    provenance: str = "ghidra-high-pcode"
    operations: list[PcodeOp] = field(default_factory=list)
    def_use: list[DefUseEdge] = field(default_factory=list)
    parameter_uses: list[ParameterUse] = field(default_factory=list)
    effects: list[PcodeEffect] = field(default_factory=list)
    parameters: list[FunctionParameter] = field(default_factory=list)
    truncated: bool = False
    omitted_operations_lower_bound: int = 0
    known_omitted_inputs: int = 0
    known_omitted_edges: int = 0
    limitations: list[str] = field(default_factory=list)

    def get_op(self, op_id: str) -> PcodeOp | None:
        for op in self.operations:
            if op.id == op_id:
                return op
        return None

    def get_memory_writes(self) -> list[PcodeEffect]:
        return [e for e in self.effects if e.kind == "memory_write"]

    def get_memory_reads(self) -> list[PcodeEffect]:
        return [e for e in self.effects if e.kind == "memory_read"]

    def get_conditional_branches(self) -> list[PcodeEffect]:
        return [e for e in self.effects if e.kind == "conditional_branch"]

    def get_calls(self) -> list[PcodeEffect]:
        return [e for e in self.effects if e.kind in {"direct_call", "indirect_call"}]

    def get_memory_write_count(self) -> int:
        return len(self.get_memory_writes())

    def get_memory_read_count(self) -> int:
        return len(self.get_memory_reads())

    def get_conditional_branch_count(self) -> int:
        return len(self.get_conditional_branches())

    def get_call_count(self) -> int:
        return len(self.get_calls())

    def get_used_parameter_ordinals(self) -> set[int]:
        return {u.ordinal for u in self.parameter_uses}

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "provenance": self.provenance,
            "operations": [op.to_dict() for op in self.operations],
            "def_use": [edge.to_dict() for edge in self.def_use],
            "parameter_uses": [u.to_dict() for u in self.parameter_uses],
            "effects": [e.to_dict() for e in self.effects],
            "parameters": [p.to_dict() for p in self.parameters],
            "truncated": self.truncated,
            "omitted_operations_lower_bound": self.omitted_operations_lower_bound,
            "known_omitted_inputs": self.known_omitted_inputs,
            "known_omitted_edges": self.known_omitted_edges,
            "limitations": list(self.limitations),
        }


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _parse_varnode(raw: Any) -> Varnode:
    if not isinstance(raw, dict):
        return Varnode(kind="other")
    kind = str(raw.get("kind", "other"))
    raw_size = raw.get("size_bytes")
    if raw_size is None:
        raw_size = raw.get("size", 0)
    size = int(raw_size or 0)
    location = raw.get("location")
    constant_hex = raw.get("constant_hex")
    if constant_hex is None and raw.get("offset") is not None and kind == "constant":
        offset = raw["offset"]
        if isinstance(offset, int):
            constant_hex = hex(offset)[2:]
        elif isinstance(offset, str):
            constant_hex = offset.removeprefix("0x")
    return Varnode(
        kind=kind,
        size_bytes=size,
        location=str(location) if location is not None else None,
        constant_hex=str(constant_hex) if constant_hex is not None else None,
    )


def parse_value_flow(raw: Any) -> ValueFlowGraph | None:
    """Parse high-Pcode value flow from REA or Ghidra artifacts.

    Supports:
    - Direct `ValueFlowGraph` instance
    - JSON string or dict matching REA `nativeValueFlowSchema`
    - Nested responses from `trace_native_values` or MCP tool payloads
    - Flat P-code operation lists
    """
    if raw is None:
        return None
    if isinstance(raw, ValueFlowGraph):
        return raw

    data: Any = raw
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return None

    if not isinstance(data, (dict, list)):
        return None

    # Unwrap tool container if present (e.g. MCP structuredContent)
    if isinstance(data, dict):
        if "structuredContent" in data and isinstance(data["structuredContent"], dict):
            norm = data["structuredContent"].get("normalized_result", {})
            if isinstance(norm, dict) and "value_flow" in norm:
                data = norm["value_flow"]
            elif isinstance(norm, dict):
                data = norm
        elif "normalized_result" in data and isinstance(data["normalized_result"], dict):
            data = data["normalized_result"].get("value_flow", data["normalized_result"])
        elif "data" in data and isinstance(data["data"], (dict, list)):
            data = data["data"]

    # Flat list of P-code ops fallback
    if isinstance(data, list):
        ops: list[PcodeOp] = []
        flat_effects: list[PcodeEffect] = []
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                continue
            op_id = str(item.get("id", f"op_{i}"))
            addr = str(item.get("address", "0x0"))
            seq = int(item.get("sequence", i))
            opcode = str(item.get("opcode", "UNKNOWN")).upper()
            inputs = [_parse_varnode(inp) for inp in item.get("inputs", [])] if "inputs" in item else []
            out = _parse_varnode(item["output"]) if "output" in item and item["output"] else None
            ops.append(
                PcodeOp(
                    id=op_id,
                    address=addr,
                    sequence=seq,
                    opcode=opcode,
                    is_dead=bool(item.get("is_dead", False)),
                    inputs=inputs,
                    output=out,
                )
            )
            # Infer basic effect if opcode matches
            _infer_effect(flat_effects, opcode, op_id)
        return ValueFlowGraph(operations=ops, effects=flat_effects)

    if not isinstance(data, dict):
        return None

    # Check available flag
    if data.get("available") is False:
        lims = [str(lim) for lim in data.get("limitations", [])]
        reason = data.get("reason")
        if reason and isinstance(reason, str):
            lims.insert(0, reason)
        return ValueFlowGraph(available=False, limitations=lims)

    # REA trace_native_values format (nodes & edges)
    if "nodes" in data and "edges" in data:
        return _parse_trace_format(data)

    # Standard REA nativeValueFlow format
    ops = []
    for item in data.get("operations", []):
        if not isinstance(item, dict):
            continue
        op_id = str(item.get("id", ""))
        addr = str(item.get("address", ""))
        seq = int(item.get("sequence", 0))
        opcode = str(item.get("opcode", "")).upper()
        dead = bool(item.get("is_dead", False))
        block = str(item.get("block_membership", "member"))
        inputs = [_parse_varnode(inp) for inp in item.get("inputs", [])]
        out = _parse_varnode(item["output"]) if item.get("output") else None
        ops.append(
            PcodeOp(
                id=op_id,
                address=addr,
                sequence=seq,
                opcode=opcode,
                is_dead=dead,
                block_membership=block,
                inputs=inputs,
                output=out,
            )
        )

    def_use: list[DefUseEdge] = []
    for edge in data.get("def_use", []):
        if isinstance(edge, dict):
            def_use.append(
                DefUseEdge(
                    definition=str(edge.get("definition", "")),
                    use=str(edge.get("use", "")),
                    input_index=int(edge.get("input_index", 0)),
                )
            )

    param_uses: list[ParameterUse] = []
    for pu in data.get("parameter_uses", []):
        if isinstance(pu, dict):
            param_uses.append(
                ParameterUse(
                    ordinal=int(pu.get("ordinal", 0)),
                    use=str(pu.get("use", "")),
                    input_index=int(pu.get("input_index", 0)),
                )
            )

    effects: list[PcodeEffect] = []
    for eff in data.get("effects", []):
        if isinstance(eff, dict):
            op_ref = str(eff.get("operation", ""))
            kind = str(eff.get("kind", ""))
            op_inp = eff.get("operand_input")
            val_inp = eff.get("value_input")
            effects.append(
                PcodeEffect(
                    operation=op_ref,
                    kind=kind,
                    operand_input=int(op_inp) if op_inp is not None else None,
                    value_input=int(val_inp) if val_inp is not None else None,
                )
            )

    params: list[FunctionParameter] = []
    for p in data.get("parameters", []):
        if isinstance(p, dict):
            params.append(
                FunctionParameter(
                    ordinal=int(p.get("ordinal", 0)),
                    name=str(p.get("name", "")),
                    data_type=str(p.get("data_type", "")),
                )
            )

    return ValueFlowGraph(
        available=True,
        provenance=str(data.get("provenance", "ghidra-high-pcode")),
        operations=ops,
        def_use=def_use,
        parameter_uses=param_uses,
        effects=effects,
        parameters=params,
        truncated=bool(data.get("truncated", False)),
        omitted_operations_lower_bound=int(data.get("omitted_operations_lower_bound", 0)),
        known_omitted_inputs=int(data.get("known_omitted_inputs", 0)),
        known_omitted_edges=int(data.get("known_omitted_edges", 0)),
        limitations=[str(lim) for lim in data.get("limitations", [])],
    )


def _infer_effect(effects: list[PcodeEffect], opcode: str, op_id: str) -> None:
    if opcode == "LOAD":
        effects.append(PcodeEffect(operation=op_id, kind="memory_read", operand_input=1))
    elif opcode == "STORE":
        effects.append(PcodeEffect(operation=op_id, kind="memory_write", operand_input=1, value_input=2))
    elif opcode == "CBRANCH":
        effects.append(PcodeEffect(operation=op_id, kind="conditional_branch", value_input=1))
    elif opcode == "BRANCHIND":
        effects.append(PcodeEffect(operation=op_id, kind="indirect_branch", operand_input=0))
    elif opcode == "CALL":
        effects.append(PcodeEffect(operation=op_id, kind="direct_call", operand_input=0))
    elif opcode == "CALLIND":
        effects.append(PcodeEffect(operation=op_id, kind="indirect_call", operand_input=0))


def _parse_trace_format(data: dict[str, Any]) -> ValueFlowGraph:
    ops: list[PcodeOp] = []
    params: list[FunctionParameter] = []
    effects: list[PcodeEffect] = []
    def_use: list[DefUseEdge] = []
    param_uses: list[ParameterUse] = []

    for node in data.get("nodes", []):
        if not isinstance(node, dict):
            continue
        kind = node.get("kind")
        if kind == "operation" and isinstance(node.get("operation"), dict):
            op_data = node["operation"]
            op_id = str(op_data.get("id", node.get("id", "")))
            addr = str(op_data.get("address", ""))
            seq = int(op_data.get("sequence", 0))
            opcode = str(op_data.get("opcode", "")).upper()
            inputs = [_parse_varnode(inp) for inp in op_data.get("inputs", [])]
            out = _parse_varnode(op_data["output"]) if op_data.get("output") else None
            ops.append(
                PcodeOp(
                    id=op_id,
                    address=addr,
                    sequence=seq,
                    opcode=opcode,
                    is_dead=bool(op_data.get("is_dead", False)),
                    inputs=inputs,
                    output=out,
                )
            )
            _infer_effect(effects, opcode, op_id)
        elif kind == "parameter" and isinstance(node.get("parameter"), dict):
            p_data = node["parameter"]
            params.append(
                FunctionParameter(
                    ordinal=int(p_data.get("ordinal", len(params))),
                    name=str(p_data.get("name", "")),
                    data_type=str(p_data.get("data_type", "")),
                )
            )

    for edge in data.get("edges", []):
        if not isinstance(edge, dict):
            continue
        e_kind = edge.get("kind")
        src = str(edge.get("source", ""))
        tgt = str(edge.get("target", ""))
        inp_idx = int(edge.get("input_index", 0))
        if e_kind == "def-use":
            def_use.append(DefUseEdge(definition=src, use=tgt, input_index=inp_idx))
        elif e_kind == "parameter-use":
            # Match parameter ordinal if source node is param
            ord_val = 0
            for p in params:
                if p.name == src:
                    ord_val = p.ordinal
                    break
            param_uses.append(ParameterUse(ordinal=ord_val, use=tgt, input_index=inp_idx))

    return ValueFlowGraph(
        available=True,
        provenance="ghidra-high-pcode-trace",
        operations=ops,
        def_use=def_use,
        parameter_uses=param_uses,
        effects=effects,
        parameters=params,
        truncated=bool(data.get("truncated", False)),
        limitations=[str(lim) for lim in data.get("limitations", [])],
    )


# ---------------------------------------------------------------------------
# Normalization & Comparison
# ---------------------------------------------------------------------------


@dataclass
class NormalizedValueFlow:
    """Canonical, address-independent representation of an SSA value flow graph."""

    opcodes: list[str]
    indexed_edges: list[tuple[int, int, int]]  # (def_op_idx, use_op_idx, input_index)
    indexed_param_uses: list[tuple[int, int, int]]  # (ordinal, use_op_idx, input_index)
    indexed_effects: list[tuple[int, str]]  # (op_idx, kind)
    parameter_count: int


def normalize_value_flow(graph: ValueFlowGraph) -> NormalizedValueFlow | None:
    """Normalize a ValueFlowGraph by mapping operation IDs to local indices [0..N-1]."""
    if not graph.available:
        return None

    # Sort operations by address and sequence for stable ordering
    def _sort_key(op: PcodeOp) -> tuple[int, int]:
        addr_int = 0
        if op.address.startswith("0x") or op.address.startswith("0X"):
            try:
                addr_int = int(op.address, 16)
            except ValueError:
                addr_int = 0
        return (addr_int, op.sequence)

    sorted_ops = sorted(graph.operations, key=_sort_key)
    id_to_idx: dict[str, int] = {op.id: idx for idx, op in enumerate(sorted_ops)}

    opcodes = [op.opcode for op in sorted_ops]

    indexed_edges: list[tuple[int, int, int]] = []
    for edge in graph.def_use:
        def_idx = id_to_idx.get(edge.definition)
        use_idx = id_to_idx.get(edge.use)
        if def_idx is not None and use_idx is not None:
            indexed_edges.append((def_idx, use_idx, edge.input_index))
    indexed_edges.sort()

    indexed_param_uses: list[tuple[int, int, int]] = []
    for pu in graph.parameter_uses:
        use_idx = id_to_idx.get(pu.use)
        if use_idx is not None:
            indexed_param_uses.append((pu.ordinal, use_idx, pu.input_index))
    indexed_param_uses.sort()

    indexed_effects: list[tuple[int, str]] = []
    for eff in graph.effects:
        op_idx = id_to_idx.get(eff.operation)
        if op_idx is not None:
            indexed_effects.append((op_idx, eff.kind))
    indexed_effects.sort()

    return NormalizedValueFlow(
        opcodes=opcodes,
        indexed_edges=indexed_edges,
        indexed_param_uses=indexed_param_uses,
        indexed_effects=indexed_effects,
        parameter_count=len(graph.parameters),
    )


@dataclass
class ValueFlowComparison:
    """Result of structurally comparing two ValueFlowGraphs."""

    status: str  # "unchanged", "changed", "unresolved"
    differences: list[str] = field(default_factory=list)
    left_counts: dict[str, int] = field(default_factory=dict)
    right_counts: dict[str, int] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


def compare_value_flow(left: ValueFlowGraph, right: ValueFlowGraph) -> ValueFlowComparison:
    """Compare two ValueFlowGraphs structurally across opcodes, def-use edges, and side effects."""
    limitations: list[str] = []
    for lim in left.limitations:
        limitations.append(f"Left: {lim}")
    for lim in right.limitations:
        limitations.append(f"Right: {lim}")

    if not left.available or not right.available:
        return ValueFlowComparison(
            status="unresolved",
            differences=["At least one procedure has no available High-Pcode value flow"],
            limitations=limitations,
        )

    norm_left = normalize_value_flow(left)
    norm_right = normalize_value_flow(right)
    if norm_left is None or norm_right is None:
        return ValueFlowComparison(
            status="unresolved",
            differences=["Failed to normalize value flow into canonical index space"],
            limitations=limitations,
        )

    left_counts = {
        "operations": len(left.operations),
        "def_use_edges": len(left.def_use),
        "memory_writes": left.get_memory_write_count(),
        "memory_reads": left.get_memory_read_count(),
        "conditional_branches": left.get_conditional_branch_count(),
        "calls": left.get_call_count(),
    }
    right_counts = {
        "operations": len(right.operations),
        "def_use_edges": len(right.def_use),
        "memory_writes": right.get_memory_write_count(),
        "memory_reads": right.get_memory_read_count(),
        "conditional_branches": right.get_conditional_branch_count(),
        "calls": right.get_call_count(),
    }

    diffs: list[str] = []

    # Check effects differences
    if left_counts["memory_writes"] != right_counts["memory_writes"]:
        diffs.append(
            f"Memory writes mismatch: left has {left_counts['memory_writes']}, "
            f"right has {right_counts['memory_writes']}"
        )
    if left_counts["memory_reads"] != right_counts["memory_reads"]:
        diffs.append(
            f"Memory reads mismatch: left has {left_counts['memory_reads']}, right has {right_counts['memory_reads']}"
        )
    if left_counts["conditional_branches"] != right_counts["conditional_branches"]:
        diffs.append(
            f"Conditional branches mismatch: left has {left_counts['conditional_branches']}, "
            f"right has {right_counts['conditional_branches']}"
        )
    if left_counts["calls"] != right_counts["calls"]:
        diffs.append(f"Calls mismatch: left has {left_counts['calls']}, right has {right_counts['calls']}")

    # Opcode distribution comparison
    left_op_counter = Counter(norm_left.opcodes)
    right_op_counter = Counter(norm_right.opcodes)
    if left_op_counter != right_op_counter:
        diffs.append(
            f"Opcode frequency mismatch: left has {len(norm_left.opcodes)} ops, right has {len(norm_right.opcodes)} ops"
        )

    # Def-use topology comparison
    if norm_left.indexed_edges != norm_right.indexed_edges:
        diffs.append(
            f"Def-use graph topology mismatch: left has {len(norm_left.indexed_edges)} edges, "
            f"right has {len(norm_right.indexed_edges)} edges"
        )

    # Parameter uses comparison
    if norm_left.indexed_param_uses != norm_right.indexed_param_uses:
        diffs.append("Parameter use bindings mismatch between procedures")

    status = "unchanged" if not diffs else "changed"
    return ValueFlowComparison(
        status=status,
        differences=diffs,
        left_counts=left_counts,
        right_counts=right_counts,
        limitations=limitations,
    )


# ---------------------------------------------------------------------------
# Static Parity Signals
# ---------------------------------------------------------------------------


def _has_mutations(text: str) -> bool:
    """Check if C++ source text contains state mutations or assignments."""
    # Strip literal string and char contents
    clean = re.sub(r'"(\\.|[^"\\])*"', '""', text)
    clean = re.sub(r"'(\\.|[^'\\])*'", "''", clean)

    # Common memory/mutation functions
    if re.search(r"\b(memcpy|memset|memmove|strcpy|strncpy|operator\s*=)\b", clean):
        return True

    # Compound assignments and increment/decrement
    if re.search(r"(\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=|\+\+|--)", clean):
        return True

    # Standalone assignment '=' not preceded by ! < > & | = and not followed by =
    return bool(re.search(r"(?<![!=<>&|])=(?![=])", clean))


def check_value_flow_memory_writes(
    source: SourceMatch | None,
    ghidra: GhidraData | None = None,
    inline_skip: bool = False,
    **_kw: object,
) -> Finding | None:
    """Verify that memory writes observed in High-Pcode are reflected by mutations in source."""
    if source is None or ghidra is None or inline_skip:
        return None

    vf: ValueFlowGraph | None = getattr(ghidra, "value_flow", None)
    if vf is None or not vf.available:
        return None

    writes = vf.get_memory_write_count()
    if writes > 0 and not _has_mutations(source.body_no_comments):
        return Finding(
            level="red",
            reason=(
                f"High-Pcode value flow has {writes} memory write(s) (STORE), "
                "but source performs no assignments or state mutation"
            ),
        )
    return None


def check_value_flow_branch_conditions(
    source: SourceMatch | None,
    ghidra: GhidraData | None = None,
    inline_skip: bool = False,
    **_kw: object,
) -> Finding | None:
    """Verify that multiple conditional branches in P-code value flow are reflected in source control flow."""
    if source is None or ghidra is None or inline_skip:
        return None

    vf: ValueFlowGraph | None = getattr(ghidra, "value_flow", None)
    if vf is None or not vf.available:
        return None

    branches = vf.get_conditional_branch_count()
    if branches >= 2 and source.control_flow_count == 0:
        return Finding(
            level="yellow",
            reason=(
                f"High-Pcode value flow has {branches} conditional branch(es), "
                "but source contains no control flow constructs"
            ),
        )
    return None


def check_value_flow_parameter_usage(
    source: SourceMatch | None,
    ghidra: GhidraData | None = None,
    inline_skip: bool = False,
    **_kw: object,
) -> Finding | None:
    """Verify that function parameters active in High-Pcode def-use chains are utilized in source."""
    if source is None or ghidra is None or inline_skip:
        return None

    vf: ValueFlowGraph | None = getattr(ghidra, "value_flow", None)
    if vf is None or not vf.available or not vf.parameters or not vf.parameter_uses:
        return None

    # Check if parameters controlling writes or branches are missing from source
    critical_op_ids: set[str] = {e.operation for e in vf.effects if e.kind in {"memory_write", "conditional_branch"}}
    critical_params: set[int] = {pu.ordinal for pu in vf.parameter_uses if pu.use in critical_op_ids}

    body = source.body_no_comments
    for param in vf.parameters:
        if (
            param.ordinal in critical_params
            and param.name
            and not re.search(r"^(?:a\d+|param_\d+|unaff_.*)$", param.name, re.IGNORECASE)
            and not re.search(rf"\b{re.escape(param.name)}\b", body)
        ):
            return Finding(
                level="yellow",
                reason=(
                    f"Parameter '{param.name}' (arg {param.ordinal}) flows into "
                    "critical operations in value flow, but is not referenced in source"
                ),
            )
    return None


# ---------------------------------------------------------------------------
# Semantic Rules Integration
# ---------------------------------------------------------------------------


def evaluate_value_flow_checks(value_flow: Any, checks: list[dict[str, Any]]) -> list[str]:
    """Evaluate value flow assertions from semantic rules against a ValueFlowGraph."""
    vf = parse_value_flow(value_flow)
    if vf is None or not vf.available:
        return ["High-Pcode value flow data is unavailable to verify value_flow_checks"]

    errors: list[str] = []
    for check in checks:
        if not isinstance(check, dict):
            continue

        if "min_memory_writes" in check:
            min_w = int(check["min_memory_writes"])
            actual_w = vf.get_memory_write_count()
            if actual_w < min_w:
                errors.append(f"Expected at least {min_w} memory write(s), found {actual_w}")

        if "max_memory_writes" in check:
            max_w = int(check["max_memory_writes"])
            actual_w = vf.get_memory_write_count()
            if actual_w > max_w:
                errors.append(f"Expected at most {max_w} memory write(s), found {actual_w}")

        if "min_memory_reads" in check:
            min_r = int(check["min_memory_reads"])
            actual_r = vf.get_memory_read_count()
            if actual_r < min_r:
                errors.append(f"Expected at least {min_r} memory read(s), found {actual_r}")

        if "min_conditional_branches" in check:
            min_b = int(check["min_conditional_branches"])
            actual_b = vf.get_conditional_branch_count()
            if actual_b < min_b:
                errors.append(f"Expected at least {min_b} conditional branch(es), found {actual_b}")

        if "requires_effects" in check:
            req_effects = set(check["requires_effects"])
            actual_effects = {e.kind for e in vf.effects}
            missing = req_effects - actual_effects
            if missing:
                errors.append(f"Missing required effect(s): {', '.join(sorted(missing))}")

        if "forbidden_effects" in check:
            forb = set(check["forbidden_effects"])
            actual_effects = {e.kind for e in vf.effects}
            present = forb & actual_effects
            if present:
                errors.append(f"Present forbidden effect(s): {', '.join(sorted(present))}")

        if "requires_param_use" in check:
            used_ords = vf.get_used_parameter_ordinals()
            for ord_val in check["requires_param_use"]:
                if ord_val not in used_ords:
                    errors.append(f"Parameter ordinal {ord_val} has no def-use links in value flow")

    return errors
