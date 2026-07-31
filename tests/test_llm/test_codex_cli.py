"""Tests for the subscription-backed Codex CLI provider."""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from re_agent.llm.codex_cli import CodexCLIProvider
from re_agent.llm.protocol import Message


def test_codex_cli_uses_safe_noninteractive_mode_and_stdin(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "must-not-leak")
    provider = CodexCLIProvider(
        model="gpt-5.6-sol",
        codex_bin="codex-test",
        effort="high",
    )

    def complete(command: list[str], **kwargs: object) -> CompletedProcess[str]:
        output_index = command.index("--output-last-message") + 1
        Path(command[output_index]).write_text("generated code", encoding="utf-8")
        return CompletedProcess(command, 0, stdout="generated code\n", stderr="")

    with patch("re_agent.llm.codex_cli.subprocess.run", side_effect=complete) as run:
        result = provider.send(
            [
                Message(role="system", content="Follow the evidence."),
                Message(role="user", content="Reverse this function."),
            ]
        )

    assert result == "generated code"
    command = run.call_args.args[0]
    assert command[:2] == ["codex-test", "exec"]
    assert command[-1] == "-"
    assert command[command.index("--sandbox") + 1] == "read-only"
    assert "--ephemeral" in command
    assert "--skip-git-repo-check" in command
    assert command[command.index("--model") + 1] == "gpt-5.6-sol"
    assert 'model_reasoning_effort="high"' in command
    assert run.call_args.kwargs["input"] == ("[SYSTEM]\nFollow the evidence.\n\n[USER]\nReverse this function.")
    assert "GEMINI_API_KEY" not in run.call_args.kwargs["env"]


def test_codex_cli_replays_conversation_history() -> None:
    provider = CodexCLIProvider(codex_bin="codex-test")
    conversation_id = provider.new_conversation("Be precise.")
    prompts: list[str] = []

    def complete(command: list[str], **kwargs: object) -> CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        output_index = command.index("--output-last-message") + 1
        Path(command[output_index]).write_text("answer", encoding="utf-8")
        return CompletedProcess(command, 0, stdout="answer\n", stderr="")

    with patch("re_agent.llm.codex_cli.subprocess.run", side_effect=complete):
        provider.resume(conversation_id, "first")
        provider.resume(conversation_id, "second")

    assert "[SYSTEM]\nBe precise." in prompts[0]
    assert "[USER]\nfirst" in prompts[0]
    assert "[ASSISTANT]\nanswer" in prompts[1]
    assert prompts[1].endswith("[USER]\nsecond")


def test_codex_cli_surfaces_stderr_on_failure() -> None:
    completed = CompletedProcess(["codex-test"], 1, stdout="", stderr="Not logged in")
    provider = CodexCLIProvider(codex_bin="codex-test")
    with (
        patch("re_agent.llm.codex_cli.subprocess.run", return_value=completed),
        pytest.raises(RuntimeError, match="Not logged in"),
    ):
        provider.send([Message(role="user", content="hello")])
