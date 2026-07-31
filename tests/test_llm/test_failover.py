"""Tests for explicit cross-provider failover and bounded conversations."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest

from re_agent.llm.base import BaseLLMProvider
from re_agent.llm.failover import (
    FailoverLLMProvider,
    FailureKind,
    LLMFailoverError,
    ProviderRoute,
    classify_provider_failure,
)
from re_agent.llm.protocol import Message


class _Provider(BaseLLMProvider):
    def __init__(self, results: Iterable[str | BaseException]) -> None:
        super().__init__()
        self.results = iter(results)
        self.calls = 0
        self.seen: list[list[Message]] = []
        self.kwargs_seen: list[dict[str, Any]] = []

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        self.calls += 1
        self.seen.append(list(messages))
        self.kwargs_seen.append(dict(kwargs))
        result = next(self.results)
        if isinstance(result, BaseException):
            raise result
        return result


def test_transient_failure_retries_primary_before_fallback() -> None:
    primary = _Provider([RuntimeError("429 RESOURCE_EXHAUSTED"), "primary answer"])
    fallback = _Provider(["fallback answer"])
    sleeps: list[float] = []
    provider = FailoverLLMProvider(
        [
            ProviderRoute("gemini", primary, max_retries=1, retry_base_delay_s=0.25),
            ProviderRoute("codex", fallback, max_retries=0),
        ],
        sleep=sleeps.append,
    )

    assert provider.send([Message(role="user", content="hello")]) == "primary answer"
    assert primary.calls == 2
    assert fallback.calls == 0
    assert sleeps == [0.25]
    assert provider.last_metadata["provider"] == "gemini"
    assert provider.last_metadata["failed_over"] is False


def test_context_limit_moves_immediately_to_fallback() -> None:
    primary = _Provider([RuntimeError("400 request exceeds input token limit")])
    fallback = _Provider(["codex answer"])
    provider = FailoverLLMProvider(
        [
            ProviderRoute("gemini", primary, max_retries=2),
            ProviderRoute("codex", fallback, max_retries=0),
        ],
        sleep=lambda _: None,
    )

    assert provider.send([Message(role="user", content="hello")]) == "codex answer"
    assert primary.calls == 1
    assert fallback.calls == 1
    assert provider.last_metadata["provider"] == "codex"
    assert provider.last_metadata["failed_over"] is True


def test_safety_block_never_routes_to_another_provider() -> None:
    primary = _Provider([RuntimeError("403 BLOCKED FOR SAFETY: content policy")])
    fallback = _Provider(["must not run"])
    provider = FailoverLLMProvider(
        [
            ProviderRoute("gemini", primary),
            ProviderRoute("codex", fallback),
        ],
        sleep=lambda _: None,
    )

    with pytest.raises(RuntimeError, match="BLOCKED FOR SAFETY"):
        provider.send([Message(role="user", content="hello")])
    assert fallback.calls == 0


def test_unavailable_routes_are_aggregated_without_prompt_text() -> None:
    first = _Provider([RuntimeError("Codex CLI not found")])
    second = _Provider([RuntimeError("Antigravity CLI is not logged in")])
    provider = FailoverLLMProvider(
        [
            ProviderRoute("codex", first, max_retries=0),
            ProviderRoute("antigravity", second, max_retries=0),
        ],
        sleep=lambda _: None,
    )

    with pytest.raises(LLMFailoverError, match="All configured") as raised:
        provider.send([Message(role="user", content="SECRET_PROMPT_MARKER")])
    assert "SECRET_PROMPT_MARKER" not in str(raised.value)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("429 RESOURCE_EXHAUSTED", FailureKind.RATE_LIMIT),
        ("503 service unavailable", FailureKind.TRANSIENT),
        ("request exceeds input token limit", FailureKind.CONTEXT_LIMIT),
        ("Codex CLI not found", FailureKind.UNAVAILABLE),
        (
            "The 'gpt-5.6-sol' model requires a newer version of Codex. "
            "Please upgrade to the latest app or CLI and try again.",
            FailureKind.UNAVAILABLE,
        ),
        ("BLOCKED FOR SAFETY", FailureKind.SAFETY),
        ("400 INVALID_ARGUMENT malformed request", FailureKind.INVALID_REQUEST),
        ("codex exec failed with exit code 2", FailureKind.UNKNOWN),
        ("unexpected parser bug", FailureKind.UNKNOWN),
    ],
)
def test_failure_classification(message: str, expected: FailureKind) -> None:
    assert classify_provider_failure(RuntimeError(message)) is expected


def test_conversation_history_drops_oldest_complete_turns_by_size() -> None:
    provider = _Provider(["answer-one", "answer-two"])
    provider._max_conversation_chars = 1_000
    conversation = provider.new_conversation("system")

    provider.resume(conversation, "A" * 700)
    provider.resume(conversation, "B" * 700)

    second_prompt = provider.seen[1]
    rendered = provider._render_messages(second_prompt)
    assert "[SYSTEM]\nsystem" in rendered
    assert "A" * 100 not in rendered
    assert "B" * 700 in rendered


def test_primary_runtime_model_override_never_leaks_to_fallback() -> None:
    primary = _Provider([RuntimeError("request exceeds input token limit")])
    fallback = _Provider(["fallback answer"])
    provider = FailoverLLMProvider(
        [
            ProviderRoute("gemini", primary, max_retries=0),
            ProviderRoute("codex", fallback, max_retries=0),
        ],
        sleep=lambda _: None,
    )

    assert provider.send(
        [Message(role="user", content="hello")],
        model="gemini-primary-model",
        temperature=0.0,
    ) == "fallback answer"
    assert primary.kwargs_seen == [
        {"model": "gemini-primary-model", "temperature": 0.0}
    ]
    assert fallback.kwargs_seen == [{"temperature": 0.0}]
