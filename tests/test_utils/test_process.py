"""Tests for subprocess error normalization."""

from __future__ import annotations

from unittest.mock import patch

from re_agent.utils.process import (
    run_cmd,
    run_cmd_split,
    sanitized_cli_environment,
)


def test_run_cmd_handles_general_oserror() -> None:
    with patch("re_agent.utils.process.subprocess.run", side_effect=OSError("bad handle")):
        ok, output = run_cmd(["tool"])
    assert ok is False
    assert "bad handle" in output


def test_run_cmd_split_handles_general_oserror() -> None:
    with patch("re_agent.utils.process.subprocess.run", side_effect=OSError("bad handle")):
        returncode, stdout, stderr = run_cmd_split(["tool"])
    assert returncode == -1
    assert stdout == ""
    assert "bad handle" in stderr


def test_sanitized_cli_environment_excludes_provider_secrets(monkeypatch) -> None:
    monkeypatch.setenv("PATH", "trusted-path")
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-secret")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "credential-file")
    monkeypatch.setenv("CODEX_HOME", "codex-home")

    environment = sanitized_cli_environment()

    assert environment["PATH"] == "trusted-path"
    assert environment["CODEX_HOME"] == "codex-home"
    assert "GEMINI_API_KEY" not in environment
    assert "ANTHROPIC_API_KEY" not in environment
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in environment
