"""Tests for explicit external-provider policy."""
from __future__ import annotations

import pytest

from re_agent.config.policy import provider_is_allowed, require_provider_allowed
from re_agent.config.schema import DataHandlingConfig, LLMConfig


def test_provider_requires_both_global_consent_and_allowlist() -> None:
    provider = LLMConfig(provider="gemini")
    assert not provider_is_allowed(DataHandlingConfig(), provider)
    assert not provider_is_allowed(
        DataHandlingConfig(allow_external_llm=True),
        provider,
    )
    assert provider_is_allowed(
        DataHandlingConfig(
            allow_external_llm=True,
            allowed_providers=["GEMINI"],
        ),
        provider,
    )


def test_policy_error_names_role_and_provider() -> None:
    with pytest.raises(RuntimeError, match="checker provider 'codex'"):
        require_provider_allowed(
            DataHandlingConfig(),
            LLMConfig(provider="codex"),
            role="checker",
        )


def test_policy_requires_every_fallback_provider() -> None:
    config = LLMConfig(
        provider="gemini",
        fallbacks=[LLMConfig(provider="codex")],
    )
    policy = DataHandlingConfig(
        allow_external_llm=True,
        allowed_providers=["gemini"],
    )
    with pytest.raises(RuntimeError, match="reverser fallback #1 provider 'codex'"):
        require_provider_allowed(policy, config, role="reverser")


def test_policy_accepts_provider_aliases() -> None:
    policy = DataHandlingConfig(
        allow_external_llm=True,
        allowed_providers=["gemini", "antigravity"],
    )
    config = LLMConfig(
        provider="google-gemini",
        fallbacks=[LLMConfig(provider="gemini-cli")],
    )
    require_provider_allowed(policy, config, role="reverser")
