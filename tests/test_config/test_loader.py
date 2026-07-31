"""Tests for config loading."""
from __future__ import annotations

from pathlib import Path

import pytest

from re_agent.config.loader import load_config
from re_agent.config.schema import ReAgentConfig


def test_load_default_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = load_config(None)
    assert isinstance(config, ReAgentConfig)
    assert config.llm.provider == "claude"
    assert config.backend.type == "ghidra-bridge"
    assert config.backend.cli_path == "ghidra-bridge"
    assert config.orchestrator.max_review_rounds == 4
    assert config.orchestrator.objective_verifier_enabled is True


def test_load_from_yaml(sample_config_path: Path) -> None:
    config = load_config(sample_config_path)
    assert config.project_profile.stub_call_prefix == "plugin::Call"
    assert config.llm.model == "claude-sonnet-4-5-20250929"
    assert config.parity.call_count_warn_diff == 3


def test_role_specific_agent_configs(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        """\
llm:
  provider: claude
agents:
  reverser:
    provider: claude-cli
    model: sonnet
    max_budget_usd: 1.5
  checker:
    provider: codex
    model: gpt-5.4
""",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.agents.reverser is not None
    assert config.agents.reverser.provider == "claude-cli"
    assert config.agents.reverser.max_budget_usd == 1.5
    assert config.agents.checker is not None
    assert config.agents.checker.provider == "codex"


def test_cli_overrides() -> None:
    config = load_config(None, cli_overrides={"llm.provider": "openai", "orchestrator.max_review_rounds": "6"})
    assert config.llm.provider == "openai"
    assert config.orchestrator.max_review_rounds == 6


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RE_AGENT_LLM_PROVIDER", "openai")
    monkeypatch.setenv("RE_AGENT_LLM_MODEL", "gpt-4o")
    config = load_config(None)
    assert config.llm.provider == "openai"
    assert config.llm.model == "gpt-4o"


def test_unknown_top_level_section_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("mystery:\n  enabled: true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unknown top-level"):
        load_config(path)


def test_unknown_nested_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("validation:\n  trust_commands_typo: true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unknown config key"):
        load_config(path)


def test_invalid_boolean_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("validation:\n  enabled: perhaps\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a boolean"):
        load_config(path)


def test_same_provider_role_inherits_base_fields(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        """\
llm:
  provider: openai
  model: base-model
  base_url: https://example.invalid/v1
  timeout_s: 77
agents:
  checker:
    model: checker-model
""",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.agents.checker is not None
    assert config.agents.checker.provider == "openai"
    assert config.agents.checker.model == "checker-model"
    assert config.agents.checker.base_url == "https://example.invalid/v1"
    assert config.agents.checker.timeout_s == 77


def test_cross_provider_role_does_not_inherit_model_or_credentials(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        """\
llm:
  provider: gemini
  model: gemini-model
  service_account_file: credentials/key.json
agents:
  checker:
    provider: codex
""",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.agents.checker is not None
    assert config.agents.checker.model is None
    assert config.agents.checker.service_account_file is None


def test_ordered_llm_fallback_configs_are_typed(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        """\
llm:
  provider: gemini
  model: gemini-primary
  max_retries: 2
  retry_base_delay_s: 0.25
  fallbacks:
    - provider: codex
      model: gpt-test
      max_retries: 0
    - provider: antigravity
      cli_path: agy-test
""",
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.llm.max_retries == 2
    assert config.llm.retry_base_delay_s == 0.25
    assert [item.provider for item in config.llm.fallbacks] == [
        "codex",
        "antigravity",
    ]
    assert config.llm.fallbacks[0].model == "gpt-test"
    assert config.llm.fallbacks[1].cli_path == "agy-test"


def test_nested_llm_fallbacks_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        """\
llm:
  provider: gemini
  fallbacks:
    - provider: codex
      fallbacks:
        - provider: antigravity
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Nested LLM fallback"):
        load_config(path)


def test_llm_retry_count_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("llm:\n  provider: gemini\n  max_retries: 3\n", encoding="utf-8")
    with pytest.raises(ValueError, match="between 0 and 2"):
        load_config(path)
