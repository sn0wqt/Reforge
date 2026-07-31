"""LLM provider factory registry."""
from __future__ import annotations

from dataclasses import replace

from re_agent.config.schema import LLMConfig
from re_agent.llm.protocol import LLMProvider


def create_provider(config: LLMConfig) -> LLMProvider:
    """Instantiate an LLM provider from a configuration object.

    Args:
        config: The LLM configuration specifying provider type, model,
            API key, and other parameters.

    Returns:
        An object satisfying the :class:`LLMProvider` protocol.

    Raises:
        ValueError: If ``config.provider`` is not a recognised provider name.
    """
    if not config.fallbacks:
        return _create_single_provider(config)

    from re_agent.llm.failover import (
        FailoverLLMProvider,
        ProviderRoute,
        UnavailableLLMProvider,
    )

    routes: list[ProviderRoute] = []
    for route_config in [replace(config, fallbacks=[]), *config.fallbacks]:
        try:
            provider = _create_single_provider(route_config)
        except Exception as exc:
            provider = UnavailableLLMProvider(route_config.provider, exc)
        routes.append(
            ProviderRoute(
                name=route_config.provider,
                provider=provider,
                max_retries=route_config.max_retries,
                retry_base_delay_s=route_config.retry_base_delay_s,
            )
        )
    return FailoverLLMProvider(routes)


def _create_single_provider(config: LLMConfig) -> LLMProvider:
    """Instantiate exactly one provider without applying a failover chain."""
    if config.provider == "claude":
        from re_agent.llm.claude import ClaudeProvider

        return ClaudeProvider(
            api_key=config.api_key,
            model=config.model or "claude-sonnet-4-5-20250929",
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            timeout_s=config.timeout_s,
        )

    if config.provider == "claude-cli":
        from re_agent.llm.claude_cli import ClaudeCLIProvider

        return ClaudeCLIProvider(
            model=config.model or "sonnet",
            timeout_s=config.timeout_s,
            claude_bin=config.cli_path or "claude",
            max_budget_usd=config.max_budget_usd,
            effort=config.effort,
        )

    if config.provider == "codex":
        from re_agent.llm.codex_cli import CodexCLIProvider

        return CodexCLIProvider(
            model=config.model,
            timeout_s=config.timeout_s,
            codex_bin=config.cli_path or "codex",
            effort=config.effort,
        )

    if config.provider in ("openai", "openai-compat"):
        from re_agent.llm.openai_compat import OpenAIProvider

        return OpenAIProvider(
            api_key=config.api_key,
            model=config.model or "gpt-4o",
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            base_url=config.base_url,
            timeout_s=config.timeout_s,
        )

    if config.provider in ("gemini", "google-gemini"):
        from re_agent.llm.gemini_api import GeminiProvider

        return GeminiProvider(
            api_key=config.api_key,
            model=config.model or "gemini-2.5-flash",
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            base_url=config.base_url,
            service_account_file=config.service_account_file,
            timeout_s=config.timeout_s,
            allow_provider_fallback=config.allow_provider_fallback,
        )

    if config.provider in ("antigravity", "antigravity-cli", "gemini-cli"):
        from re_agent.llm.antigravity_cli import AntigravityCLIProvider

        return AntigravityCLIProvider(
            model=config.model or "gemini-3.6-flash",
            timeout_s=config.timeout_s,
            agy_bin=config.cli_path or "agy",
        )

    raise ValueError(
        f"Unknown LLM provider: {config.provider!r}. "
        f"Supported providers: 'claude', 'claude-cli', 'gemini', 'google-gemini', "
        f"'antigravity', 'antigravity-cli', 'gemini-cli', 'openai', "
        f"'openai-compat', 'codex'."
    )
