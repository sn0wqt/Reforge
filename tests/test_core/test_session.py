"""Tests for durable session persistence."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path

from re_agent.core.models import FunctionTarget, ReversalResult
from re_agent.core.session import Session


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
