"""Tests for core data models."""

from __future__ import annotations

from reforge.core.models import (
    CheckerVerdict,
    Finding,
    FunctionTarget,
    HookEntry,
    ObjectiveVerdict,
    ParityStatus,
    ReversalResult,
    Verdict,
)


def test_function_target() -> None:
    t = FunctionTarget(address="0x6F86A0", class_name="CTrain", function_name="ProcessControl")
    assert t.address == "0x6F86A0"
    assert t.caller_count == 0


def test_verdict_enum() -> None:
    assert Verdict.PASS.value == "PASS"
    assert Verdict.FAIL.value == "FAIL"
    assert Verdict.UNKNOWN.value == "UNKNOWN"


def test_parity_status_enum() -> None:
    assert ParityStatus.GREEN.value == "green"
    assert ParityStatus.YELLOW.value == "yellow"
    assert ParityStatus.RED.value == "red"


def test_finding() -> None:
    f = Finding(level="red", reason="Missing source body")
    assert f.level == "red"


def test_checker_verdict() -> None:
    v = CheckerVerdict(
        verdict=Verdict.PASS,
        summary="All checks passed",
        issues=[],
        fix_instructions=[],
    )
    assert v.verdict == Verdict.PASS


def test_objective_verdict() -> None:
    v = ObjectiveVerdict(
        verdict=Verdict.PASS,
        summary="Structural checks passed",
        findings=[],
    )
    assert v.verdict == Verdict.PASS


def test_hook_entry_properties() -> None:
    h = HookEntry(
        class_path="Vehicle/CTrain",
        fn_name="ProcessControl",
        address="0x6f86a0",
        reversed=True,
        locked=False,
        is_virtual=False,
    )
    assert h.class_name == "CTrain"
    assert h.symbol == "CTrain::ProcessControl"


def test_reversal_result() -> None:
    t = FunctionTarget(address="0x6F86A0", class_name="CTrain", function_name="ProcessControl")
    r = ReversalResult(
        target=t,
        code="void CTrain::ProcessControl() { }",
        checker_verdict=None,
        objective_verdict=None,
        parity_status=None,
        parity_findings=[],
        rounds_used=1,
        success=True,
    )
    assert r.success
    assert r.rounds_used == 1


def test_reversal_result_serialization_roundtrip() -> None:
    from reforge.core.models import ValidationVerdict

    t = FunctionTarget(address="0x6F86A0", class_name="CTrain", function_name="ProcessControl", caller_count=4)
    r = ReversalResult(
        target=t,
        code="void CTrain::ProcessControl() { do_work(); }",
        checker_verdict=CheckerVerdict(
            verdict=Verdict.PASS,
            summary="All good",
            issues=[],
            fix_instructions=["Do not change this pointer"],
        ),
        objective_verdict=ObjectiveVerdict(
            verdict=Verdict.PASS,
            summary="Objective checks passed",
            findings=["match 1"],
        ),
        parity_status=ParityStatus.GREEN,
        parity_findings=[Finding(level="info", reason="clean match")],
        rounds_used=2,
        success=True,
        validation_verdict=ValidationVerdict(
            verdict=Verdict.PASS,
            summary="Gates passed",
            findings=[],
            overlay_file="overlay.cpp",
            checks=[{"kind": "build", "verdict": "PASS", "detail": "ninja clean"}],
        ),
        run_id="run-101",
        error=None,
    )

    data = r.to_dict()
    assert data["address"] == "0x6F86A0"
    assert data["verdict"] == "PASS"
    assert data["fix_instructions"] == ["Do not change this pointer"]
    assert data["validation_verdict"] == "PASS"
    assert data["candidate_overlay"] == "overlay.cpp"
    assert len(data["validation_checks"]) == 1

    restored = ReversalResult.from_dict(data)
    assert restored.target.address == "0x6F86A0"
    assert restored.target.class_name == "CTrain"
    assert restored.target.function_name == "ProcessControl"
    assert restored.code == r.code
    assert restored.success is True
    assert restored.rounds_used == 2
    assert restored.run_id == "run-101"
    assert restored.checker_verdict is not None
    assert restored.checker_verdict.verdict == Verdict.PASS
    assert restored.checker_verdict.fix_instructions == ["Do not change this pointer"]
    assert restored.objective_verdict is not None
    assert restored.objective_verdict.findings == ["match 1"]
    assert restored.validation_verdict is not None
    assert restored.validation_verdict.overlay_file == "overlay.cpp"
    assert restored.validation_verdict.checks[0]["detail"] == "ninja clean"
    assert restored.parity_status == ParityStatus.GREEN
    assert len(restored.parity_findings) == 1
    assert restored.parity_findings[0].reason == "clean match"

