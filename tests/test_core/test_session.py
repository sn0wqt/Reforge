"""Tests for durable session persistence."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path

from reforge.core.models import FunctionTarget, ReversalResult
from reforge.core.session import Session


def _result(address: str, *, success: bool) -> ReversalResult:
    return ReversalResult(
        target=FunctionTarget(address, "Player", "Update"),
        code="void Player::Update() {}",
        rounds_used=1,
        success=success,
    )


def test_session_replaces_existing_file_atomically(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    session = Session(path)
    session.record_result(_result("0x100", success=False))
    session.record_result(_result("0x100", success=True))

    reloaded = Session(path)
    assert reloaded.is_completed("0x100")
    assert reloaded.attempt_count("0x100") == 2
    assert not list(tmp_path.glob("*.tmp"))


def test_session_recovers_from_invalid_schema(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    path.write_text(json.dumps({"functions": [], "runs": {}}), encoding="utf-8")

    session = Session(path)

    assert session.get_summary()["total_functions"] == 0
    assert not path.exists()
    assert list(tmp_path.glob("session.json.corrupt-*"))


def test_session_filters_invalid_nested_entries(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "functions": {"bad": "not-an-object", "0100": {"success": True}},
                "runs": ["bad", {"address": "0x100"}],
            }
        ),
        encoding="utf-8",
    )

    session = Session(path)

    assert session.get_summary()["total_functions"] == 1
    assert session.attempt_count("0x100") == 1


def test_session_load_acquires_cross_process_lock(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "session.json"
    session = Session(path)
    path.write_text(
        json.dumps({"schema_version": 1, "functions": {}, "runs": []}),
        encoding="utf-8",
    )
    events: list[str] = []

    @contextmanager
    def observed_lock():
        events.append("enter")
        yield
        events.append("exit")

    monkeypatch.setattr(session, "_file_lock", observed_lock)

    session.load()

    assert events == ["enter", "exit"]


def test_session_checkpoint_restoration_and_gate_roundtrips(tmp_path: Path) -> None:
    from reforge.core.models import (
        CheckerVerdict,
        Finding,
        ObjectiveVerdict,
        ParityStatus,
        ValidationVerdict,
        Verdict,
    )

    path = tmp_path / "session.json"
    session = Session(path)

    result = ReversalResult(
        target=FunctionTarget("0x100", "Player", "Update"),
        code="void Player::Update() { do_work(); }",
        checker_verdict=CheckerVerdict(
            verdict=Verdict.PASS,
            summary="Checker approved",
            issues=[],
            fix_instructions=["Keep ABI"],
        ),
        objective_verdict=ObjectiveVerdict(
            verdict=Verdict.PASS,
            summary="Structural parity ok",
            findings=[],
        ),
        parity_status=ParityStatus.GREEN,
        parity_findings=[Finding(level="info", reason="clean match")],
        rounds_used=2,
        success=True,
        validation_verdict=ValidationVerdict(
            verdict=Verdict.PASS,
            summary="All gates passed",
            findings=["clean build"],
            overlay_file="overlay.cpp",
            checks=[
                {"kind": "build", "verdict": "PASS", "detail": "ninja ok"},
                {"kind": "test", "verdict": "PASS", "detail": "ctest ok"},
            ],
        ),
        run_id="run-42",
    )

    session.record_checkpoint(result)
    session.record_result(result)

    # Previous feedback should contain structured JSON with fix instructions
    feedback = session.previous_feedback("0x100")
    assert feedback != ""
    parsed_feedback = json.loads(feedback)
    assert parsed_feedback["address"] == "0x100"
    assert parsed_feedback["fix_instructions"] == ["Keep ABI"]
    assert len(parsed_feedback["validation_checks"]) == 2

    # Checkpoint restoration as a typed ReversalResult
    restored = session.restore_checkpoint("0x100")
    assert restored is not None
    assert restored.target.address == "0x100"
    assert restored.code == "void Player::Update() { do_work(); }"
    assert restored.success is True
    assert restored.validation_verdict is not None
    assert restored.validation_verdict.verdict == Verdict.PASS
    assert restored.validation_verdict.overlay_file == "overlay.cpp"
    assert len(restored.validation_verdict.checks) == 2
    assert restored.validation_verdict.checks[0]["kind"] == "build"
    assert restored.parity_status == ParityStatus.GREEN

    # Session reloaded from disk also restores checkpoints
    reloaded = Session(path)
    reloaded_restored = reloaded.restore_checkpoint("0x100")
    assert reloaded_restored is not None
    assert reloaded_restored.validation_verdict is not None
    assert reloaded_restored.validation_verdict.checks[1]["detail"] == "ctest ok"

    # Recorded result in functions has full validation / gate data
    funcs = reloaded.get_all_functions()
    assert len(funcs) == 1
    assert funcs[0]["validation_summary"] == "All gates passed"
    assert funcs[0]["candidate_overlay"] == "overlay.cpp"
    assert len(funcs[0]["validation_checks"]) == 2


def test_session_bind_archives_history(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    session = Session(path)
    session.bind("identity-alpha")

    res = _result("0x100", success=True)
    session.record_result(res)
    session.record_checkpoint(res)

    assert session.is_completed("0x100")
    assert session.identity == "identity-alpha"

    # Rebiding to a new identity archives previous records
    session.bind("identity-beta")
    assert session.identity == "identity-beta"
    assert not session.is_completed("0x100")

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert len(raw.get("history", [])) == 1
    archived = raw["history"][0]
    assert archived["identity"] == "identity-alpha"
    assert "00000100" in archived["functions"]
