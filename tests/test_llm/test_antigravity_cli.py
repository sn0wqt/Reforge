"""Tests for the login-backed Antigravity CLI provider."""
from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from re_agent.llm.antigravity_cli import AntigravityCLIProvider
from re_agent.llm.protocol import Message


def test_antigravity_cli_uses_model_and_sanitized_environment(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-leak")
    provider = AntigravityCLIProvider(model="gemini-test", agy_bin="agy-test")
    completed = CompletedProcess(["agy-test"], 0, stdout="answer\n", stderr="")

    with patch(
        "re_agent.llm.antigravity_cli.subprocess.run",
        return_value=completed,
    ) as run:
        result = provider.send([Message(role="user", content="hello")])

    assert result == "answer"
    command = run.call_args.args[0]
    assert command[command.index("--model") + 1] == "gemini-test"
    assert "ANTHROPIC_API_KEY" not in run.call_args.kwargs["env"]
    assert run.call_count == 2


def test_antigravity_cli_fails_fast_when_not_authenticated() -> None:
    provider = AntigravityCLIProvider(model="gemini-test", agy_bin="agy-test")
    status = CompletedProcess(
        ["agy-test", "models"],
        1,
        stdout="",
        stderr="Please sign in to view available models",
    )

    with (
        patch("re_agent.llm.antigravity_cli.subprocess.run", return_value=status),
        pytest.raises(RuntimeError, match="not authenticated"),
    ):
        provider.send([Message(role="user", content="hello")])


def test_antigravity_large_prompt_uses_ephemeral_request_file() -> None:
    provider = AntigravityCLIProvider(model="gemini-test", agy_bin="agy-test")
    observed: dict[str, object] = {}

    def complete(command: list[str], **kwargs: object) -> CompletedProcess[str]:
        if command[1] == "models":
            return CompletedProcess(command, 0, stdout="gemini-test\n", stderr="")
        work_dir = Path(str(kwargs["cwd"]))
        request = work_dir / "re-agent-request.txt"
        observed["exists"] = request.is_file()
        observed["content_length"] = len(request.read_text(encoding="utf-8"))
        observed["prompt_argument"] = command[-1]
        return CompletedProcess(command, 0, stdout="answer\n", stderr="")

    with patch("re_agent.llm.antigravity_cli.subprocess.run", side_effect=complete):
        result = provider.send([Message(role="user", content="x" * 20_000)])

    assert result == "answer"
    assert observed["exists"] is True
    assert int(observed["content_length"]) > 20_000
    assert "re-agent-request.txt" in str(observed["prompt_argument"])
