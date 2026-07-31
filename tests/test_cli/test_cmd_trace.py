"""Unit tests for re-agent trace CLI command."""

from __future__ import annotations

from pathlib import Path

from re_agent.cli.main import main


def test_cmd_trace_symbol(tmp_path: Path) -> None:
    out_file = tmp_path / "trace_Player.ts"
    args = ["trace", "--symbol", "UpdateHealth", "--output", out_file.as_posix()]
    out = main(args)
    assert out == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "findGlobalExportByName" in content
    assert "UpdateHealth" in content
    assert 'class("Player")' not in content


def test_cmd_trace_class(tmp_path: Path) -> None:
    out_file = tmp_path / "trace_Class.ts"
    args = ["trace", "--class", "PlayerScript", "--output", out_file.as_posix()]
    out = main(args)
    assert out == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "PlayerScript" in content


def test_cmd_trace_absolute_address_has_no_placeholder_module(tmp_path: Path) -> None:
    out_file = tmp_path / "trace_address.ts"
    result = main(
        [
            "trace",
            "--address",
            "0x1234",
            "--output",
            out_file.as_posix(),
        ]
    )

    assert result == 0
    content = out_file.read_text(encoding="utf-8")
    assert 'ptr("0x1234")' in content
    assert "FrameworkName" not in content
    assert "ExecutableName" not in content


def test_cmd_trace_requires_a_target() -> None:
    assert main(["trace"]) == 2
