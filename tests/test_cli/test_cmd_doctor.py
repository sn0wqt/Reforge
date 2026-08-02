"""Tests for the toolchain doctor CLI."""

from __future__ import annotations

import json
from pathlib import Path

from re_agent.cli.main import main


def test_doctor_json_reports_ready(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "re_agent.cli.cmd_doctor.collect_toolchain_status",
        lambda: [
            {
                "name": "required-tool",
                "required": True,
                "ok": True,
                "path": str(tmp_path / "tool.exe"),
                "version": "1.0",
                "detail": None,
            }
        ],
    )
    monkeypatch.setattr(
        "re_agent.cli.cmd_doctor.managed_tools_root",
        lambda: tmp_path,
    )

    assert main(["doctor", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is True
    assert payload["managed_tools_root"] == str(tmp_path)


def test_doctor_fails_when_required_tool_is_missing(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "re_agent.cli.cmd_doctor.collect_toolchain_status",
        lambda: [
            {
                "name": "missing-tool",
                "required": True,
                "ok": False,
                "path": None,
                "version": None,
                "detail": None,
            }
        ],
    )

    assert main(["doctor"]) == 2
    assert "Required tools are missing" in capsys.readouterr().out
