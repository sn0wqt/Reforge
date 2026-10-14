"""Core data models for reforge."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Target identification
# ---------------------------------------------------------------------------


@dataclass
class FunctionTarget:
    """Identifies a single function to reverse."""

    address: str
    class_name: str
    function_name: str
    caller_count: int = 0


# ---------------------------------------------------------------------------
# Verdict / status enums
# ---------------------------------------------------------------------------


class Verdict(Enum):
    """Checker verdict for a reversal attempt."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ParityStatus(Enum):
    """Static parity triage status."""

    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


# ---------------------------------------------------------------------------
# Checker results
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single parity finding."""

    level: str  # "red", "yellow", or "info"
    reason: str


@dataclass
class CheckerVerdict:
    """Structured result from the checker agent."""

    verdict: Verdict
    summary: str
    issues: list[str] = field(default_factory=list)
    fix_instructions: list[str] = field(default_factory=list)


@dataclass
class ObjectiveVerdict:
    """Structured result from conservative non-LLM verification."""

    verdict: Verdict
    summary: str
    findings: list[str] = field(default_factory=list)


@dataclass
class ValidationVerdict:
    """Result of configured candidate build and test gates."""

    verdict: Verdict
    summary: str
    findings: list[str] = field(default_factory=list)
    overlay_file: str | None = None
    checks: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ReversalResult:
    """Complete result of reversing one function."""

    target: FunctionTarget
    code: str
    checker_verdict: CheckerVerdict | None = None
    objective_verdict: ObjectiveVerdict | None = None
    parity_status: ParityStatus | None = None
    parity_findings: list[Finding] = field(default_factory=list)
    rounds_used: int = 0
    success: bool = False
    validation_verdict: ValidationVerdict | None = None
    run_id: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize result to a dictionary representation matching session checkpoints."""
        from reforge.reports.formatter import _result_to_dict

        return _result_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReversalResult:
        """Reconstruct a ReversalResult from a dictionary representation."""
        address = str(data.get("address", ""))
        class_name = str(data.get("class_name", ""))
        function_name = str(data.get("function_name", ""))
        target = FunctionTarget(
            address=address,
            class_name=class_name,
            function_name=function_name,
            caller_count=int(data.get("caller_count", 0)),
        )
        code = str(data.get("code") or "")
        rounds_used = int(data.get("rounds_used", 0))
        success = bool(data.get("success", False))
        run_id = str(data.get("run_id", ""))
        error = data.get("error")
        if error is not None:
            error = str(error)

        checker_verdict: CheckerVerdict | None = None
        if data.get("verdict"):
            raw_v = data["verdict"]
            v = raw_v if isinstance(raw_v, Verdict) else Verdict(raw_v)
            checker_verdict = CheckerVerdict(
                verdict=v,
                summary=str(data.get("summary", "")),
                issues=list(data.get("issues", [])),
                fix_instructions=list(data.get("fix_instructions", [])),
            )

        objective_verdict: ObjectiveVerdict | None = None
        if data.get("objective_verdict"):
            raw_ov = data["objective_verdict"]
            ov = raw_ov if isinstance(raw_ov, Verdict) else Verdict(raw_ov)
            objective_verdict = ObjectiveVerdict(
                verdict=ov,
                summary=str(data.get("objective_summary", "")),
                findings=list(data.get("objective_findings", [])),
            )

        validation_verdict: ValidationVerdict | None = None
        if data.get("validation_verdict"):
            raw_vv = data["validation_verdict"]
            vv = raw_vv if isinstance(raw_vv, Verdict) else Verdict(raw_vv)
            validation_verdict = ValidationVerdict(
                verdict=vv,
                summary=str(data.get("validation_summary", "")),
                findings=list(data.get("validation_findings", [])),
                overlay_file=data.get("candidate_overlay"),
                checks=list(data.get("validation_checks", [])),
            )

        parity_status: ParityStatus | None = None
        if data.get("parity_status"):
            raw_ps = data["parity_status"]
            parity_status = raw_ps if isinstance(raw_ps, ParityStatus) else ParityStatus(raw_ps)

        parity_findings: list[Finding] = []
        for item in data.get("parity_findings", []):
            if isinstance(item, Finding):
                parity_findings.append(item)
            elif isinstance(item, dict):
                parity_findings.append(Finding(level=str(item.get("level", "")), reason=str(item.get("reason", ""))))

        return cls(
            target=target,
            code=code,
            checker_verdict=checker_verdict,
            objective_verdict=objective_verdict,
            parity_status=parity_status,
            parity_findings=parity_findings,
            rounds_used=rounds_used,
            success=success,
            validation_verdict=validation_verdict,
            run_id=run_id,
            error=error,
        )


# ---------------------------------------------------------------------------
# Ghidra / decompiler data
# ---------------------------------------------------------------------------


@dataclass
class DecompileResult:
    """Parsed output from a decompiler invocation."""

    address: str
    name: str
    signature: str
    decompiled: str
    raw_output: str
    callers: int | None = None
    callees: int | None = None


@dataclass
class XRef:
    """A single cross-reference entry."""

    address: str
    name: str
    ref_type: str


@dataclass
class FunctionEntry:
    """A function entry from the decompiler's function list."""

    address: str
    name: str
    class_name: str = ""
    caller_count: int = 0


@dataclass
class StructField:
    """A single field within a struct definition."""

    name: str
    offset: int
    type_str: str
    size: int


@dataclass
class StructDef:
    """A struct/class definition from the decompiler."""

    name: str
    size: int
    fields: list[StructField] = field(default_factory=list)


@dataclass
class EnumValue:
    """A single value within an enum definition."""

    name: str
    value: int


@dataclass
class EnumDef:
    """An enum definition from the decompiler."""

    name: str
    values: list[EnumValue] = field(default_factory=list)


@dataclass
class AsmResult:
    """Parsed assembly listing for a function."""

    address: str
    instructions: str
    instruction_count: int
    call_count: int
    has_fp_sensitive: bool


@dataclass
class AnalysisArtifact:
    """Machine-readable or textual evidence returned by an RE backend."""

    kind: str
    target: str
    content: str


# ---------------------------------------------------------------------------
# Source analysis data
# ---------------------------------------------------------------------------


@dataclass
class SourceMatch:
    """Parsed source function body with analysis metrics."""

    path: str
    line: int
    body: str
    body_no_comments: str
    body_lines: int
    call_count: int
    plugin_call_count: int
    non_plugin_call_count: int
    control_flow_count: int
    has_stub_marker: bool
    has_fp_token: bool
    is_inline_internal_forwarder: bool
    body_start: int = 0
    body_end: int = 0


@dataclass
class GhidraData:
    """Aggregated Ghidra analysis data for a function."""

    decompile_ok: bool = False
    decompile_error: str | None = None
    callers: int | None = None
    callees: int | None = None
    param_offsets: int = 0
    decompile_has_nan: bool = False
    asm_ok: bool = False
    asm_error: str | None = None
    asm_instruction_count: int = 0
    asm_call_count: int = 0
    asm_has_fp_sensitive: bool = False
    refs_call_count: int = 0
    refs_global_rw_count: int = 0
    used_containing_fallback: bool = False
    resolved_address: str | None = None
    value_flow: Any | None = None


# ---------------------------------------------------------------------------
# Hook registry
# ---------------------------------------------------------------------------


@dataclass
class HookEntry:
    """A single hook from the hooks CSV registry."""

    class_path: str
    fn_name: str
    address: str
    reversed: bool
    locked: bool
    is_virtual: bool

    @property
    def class_name(self) -> str:
        """Extract the class name from the class path."""
        return self.class_path.split("/")[-1]

    @property
    def symbol(self) -> str:
        """Return the fully-qualified symbol name."""
        return f"{self.class_name}::{self.fn_name}"


# ---------------------------------------------------------------------------
# Semantic parity rules
# ---------------------------------------------------------------------------


@dataclass
class SemanticRule:
    """A semantic parity rule loaded from a JSON rules file."""

    id: str
    reason: str
    severity: str  # "red", "yellow", or "info"
    addresses: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    source_all_of: list[str] = field(default_factory=list)
    source_any_of: list[str] = field(default_factory=list)
    source_none_of: list[str] = field(default_factory=list)
    value_flow_checks: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ManualCheckEntry:
    """A manually-verified parity check entry."""

    line: int
    note: str


@dataclass(frozen=True)
class EvidenceGap:
    """An observed limitation, not a guessed dependency or recovered fact."""

    function: str
    reason: str
    origin: str
    kind: str = "unavailable"
    site: str | None = None

    @classmethod
    def from_dict(cls, value: object) -> EvidenceGap:
        if not isinstance(value, dict):
            raise ValueError("Evidence gap must be an object")
        required = ("function", "reason", "origin", "kind")
        if any(not isinstance(value.get(key), str) or not value[key].strip() for key in required):
            raise ValueError("Evidence gap requires function, reason, origin, and kind strings")
        if value["kind"] not in {"unavailable", "unsupported", "query_failed", "unresolved_call", "limit"}:
            raise ValueError("Unknown evidence gap kind")
        from reforge.utils.address import checked_address

        return cls(
            checked_address(value["function"]),
            value["reason"],
            value["origin"],
            value["kind"],
            checked_address(value["site"]) if value.get("site") is not None else None,
        )
