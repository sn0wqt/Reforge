"""LLM provider factory registry."""

from __future__ import annotations

import os
import re
from dataclasses import replace
from pathlib import Path

from reforge.config.schema import LLMConfig
from reforge.llm.protocol import LLMProvider


def _resolve_cliproxy_api_key(explicit_key: str | None = None) -> str:
    """Resolve CLIProxy API key from explicit config, env, or local config files on macOS/Windows/Linux."""
    if explicit_key:
        return explicit_key

    env_key = os.environ.get("CLIPROXY_API_KEY")
    if env_key:
        return env_key

    candidate_paths: list[Path] = []
    custom_cfg = os.environ.get("CLIPROXY_CONFIG")
    if custom_cfg:
        candidate_paths.append(Path(custom_cfg).expanduser())

    candidate_paths.extend(
        [
            # macOS CPA-GUI (cli-proxy-api desktop app)
            Path.home() / "Library" / "Application Support" / "com.cpa.gui" / "cpa-core" / "config.yaml",
            # Windows / standalone default
            Path.home() / "CLIProxyAPI" / "config.yaml",
            # Standard XDG / Linux / macOS CLI locations
            Path.home() / ".config" / "cliproxy" / "config.yaml",
            Path.home() / ".cli-proxy-api" / "config.yaml",
        ]
    )

    for proxy_cfg in candidate_paths:
        if not proxy_cfg.is_file():
            continue
        try:
            content = proxy_cfg.read_text(encoding="utf-8")
        except OSError:
            continue

        # Try structured YAML parsing first
        try:
            import yaml  # type: ignore[import-untyped]

            data = yaml.safe_load(content)
            if isinstance(data, dict):
                access = data.get("access")
                if isinstance(access, dict):
                    keys = access.get("api-keys")
                    if isinstance(keys, list) and keys:
                        first = str(keys[0]).strip()
                        if first:
                            return first
                    elif isinstance(keys, str) and keys.strip():
                        return keys.strip()
                top_keys = data.get("api-keys")
                if isinstance(top_keys, list) and top_keys:
                    first = str(top_keys[0]).strip()
                    if first:
                        return first
                elif isinstance(top_keys, str) and top_keys.strip():
                    return top_keys.strip()
        except Exception:
            pass

        # Regex fallback for sk-local-* or access.api-keys
        match = re.search(r"sk-local-[a-f0-9]+", content)
        if match:
            return match.group(0)

        key_match = re.search(r"""(?:api-keys:|\bapi-key:)\s*\n\s*-\s*['"]?([^'"\s#]+)['"]?""", content)
        if key_match:
            return key_match.group(1)

    return "sk-local-cliproxy"


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

    from reforge.llm.failover import (
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
        from reforge.llm.claude import ClaudeProvider

        return ClaudeProvider(
            api_key=config.api_key,
            model=config.model or "claude-sonnet-4-5-20250929",
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            timeout_s=config.timeout_s,
        )

    if config.provider == "claude-cli":
        from reforge.llm.claude_cli import ClaudeCLIProvider

        return ClaudeCLIProvider(
            model=config.model or "sonnet",
            timeout_s=config.timeout_s,
            claude_bin=config.cli_path or "claude",
            max_budget_usd=config.max_budget_usd,
            effort=config.effort,
        )

    if config.provider == "codex":
        from reforge.llm.codex_cli import CodexCLIProvider

        return CodexCLIProvider(
            model=config.model or "gpt-6.1-sol",
            timeout_s=config.timeout_s,
            codex_bin=config.cli_path or "codex",
            effort=config.effort,
        )

    if config.provider in ("openai", "openai-compat"):
        from reforge.llm.openai_compat import OpenAIProvider

        return OpenAIProvider(
            api_key=config.api_key,
            model=config.model or "gpt-4o",
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            base_url=config.base_url,
            timeout_s=config.timeout_s,
        )

    if config.provider in ("cliproxy", "cli-proxy"):
        from reforge.llm.openai_compat import OpenAIProvider

        api_key = _resolve_cliproxy_api_key(config.api_key)
        base_url = config.base_url or os.environ.get("CLIPROXY_BASE_URL", "http://127.0.0.1:8317/v1")
        return OpenAIProvider(
            api_key=api_key,
            model=config.model or "gemini-3.8-flash-high",
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            base_url=base_url,
            timeout_s=config.timeout_s,
        )

    if config.provider in ("gemini", "google-gemini"):
        from reforge.llm.gemini_api import GeminiProvider

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
        from reforge.llm.antigravity_cli import AntigravityCLIProvider

        return AntigravityCLIProvider(
            model=config.model or "gemini-3.8-flash-high",
            timeout_s=config.timeout_s,
            agy_bin=config.cli_path or "agy",
        )

    raise ValueError(
        f"Unknown LLM provider: {config.provider!r}. "
        f"Supported providers: 'claude', 'claude-cli', 'gemini', 'google-gemini', "
        f"'antigravity', 'antigravity-cli', 'gemini-cli', 'cliproxy', 'cli-proxy', "
        f"'openai', 'openai-compat', 'codex'."
    )
