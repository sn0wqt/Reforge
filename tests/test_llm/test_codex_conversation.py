"""Regression tests for Codex conversation recovery."""
from __future__ import annotations

from typing import Any

import pytest

from reforge.llm.codex_cli import CodexCLIProvider
from reforge.llm.protocol import Message


def test_failed_turn_does_not_duplicate_prompt_on_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = CodexCLIProvider()
    conversation = provider.new_conversation("system")
    requests: list[list[Message]] = []

    def send(messages: list[Message], **kwargs: Any) -> str:
        requests.append(messages)
        if len(requests) == 1:
            raise RuntimeError("CLI unavailable")
        return "answer"

    monkeypatch.setattr(provider, "send", send)
    with pytest.raises(RuntimeError, match="CLI unavailable"):
        provider.resume(conversation, "request")
    assert provider.resume(conversation, "request") == "answer"
    assert [message.content for message in requests[1]] == ["system", "request"]
    provider.resume(conversation, "next")
    assert [message.content for message in requests[2]] == ["system", "request", "answer", "next"]
