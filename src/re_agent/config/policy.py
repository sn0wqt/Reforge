"""Data-boundary policy checks shared by LLM-enabled commands."""
from __future__ import annotations

from re_agent.config.schema import DataHandlingConfig, LLMConfig


def canonical_provider_name(provider: str) -> str:
    """Return the data-boundary name shared by aliases of one provider."""
    normalized = provider.strip().casefold()
    aliases = {
        "google-gemini": "gemini",
        "antigravity-cli": "antigravity",
        "gemini-cli": "antigravity",
        "claude-cli": "claude",
        "codex-cli": "codex",
    }
    return aliases.get(normalized, normalized)


def provider_is_allowed(
    policy: DataHandlingConfig,
    provider_config: LLMConfig,
) -> bool:
    """Return whether an external LLM provider is explicitly authorized."""
    provider = canonical_provider_name(provider_config.provider)
    allowed = {canonical_provider_name(item) for item in policy.allowed_providers}
    return policy.allow_external_llm and provider in allowed


def require_provider_allowed(
    policy: DataHandlingConfig,
    provider_config: LLMConfig,
    *,
    role: str,
) -> None:
    """Require authorization for the primary and every configured fallback."""
    chain = [provider_config, *provider_config.fallbacks]
    for index, item in enumerate(chain):
        if provider_is_allowed(policy, item):
            continue
        provider = canonical_provider_name(item.provider) or "(empty)"
        chain_role = role if index == 0 else f"{role} fallback #{index}"
        raise RuntimeError(
            f"{chain_role} provider {provider!r} is not authorized by data_handling. "
            "Set data_handling.allow_external_llm=true and add the provider to "
            "data_handling.allowed_providers after reviewing the data boundary."
        )
