"""Tests for config loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from reforge.config.defaults import DEFAULT_CONFIG_YAML
from reforge.config.loader import discover_config_path, load_config
from reforge.config.schema import ReforgeConfig


def test_load_default_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("reforge.config.loader.discover_config_path", lambda: None)
    config = load_config(None)
    assert isinstance(config, ReforgeConfig)
    assert config.llm.provider == "cliproxy"
    assert config.project_profile.name == "reforge"
    assert config.project_profile.source_root == "output"
    assert config.backend.type == "ghidra-bridge"
    assert config.backend.cli_path == "ghidra-bridge"
    assert config.orchestrator.max_review_rounds == 4
    assert config.orchestrator.objective_verifier_enabled is True


def test_init_template_matches_schema_except_validation_opt_in(tmp_path: Path) -> None:
    config_path = tmp_path / "reforge.yaml"
    config_path.write_text(DEFAULT_CONFIG_YAML, encoding="utf-8")

    config = load_config(config_path)
    schema = ReforgeConfig.create_default()

    # Direct ValidationConfig callers retain the historical enabled default.
    # A freshly initialized project opts out until it has meaningful commands.
    assert schema.validation.enabled is True
    schema.validation.enabled = False
    assert config == schema


def test_default_config_discovery_works_outside_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout_dir = tmp_path / "checkout"
    checkout_dir.mkdir()
    fake_loader = checkout_dir / "src" / "reforge" / "config" / "loader.py"
    fake_loader.parent.mkdir(parents=True)
    fake_loader.write_text("# dummy loader\n", encoding="utf-8")

    outside_dir = tmp_path / "workdir"
    outside_dir.mkdir()

    monkeypatch.chdir(outside_dir)
    monkeypatch.delenv("REFORGE_CONFIG", raising=False)
    monkeypatch.setattr("reforge.config.loader.__file__", str(fake_loader))

    # Case 1: No config in checkout or workdir -> None
    assert discover_config_path() is None

    # Case 2: reforge.yaml in checkout root -> discovered
    reforge_yaml = checkout_dir / "reforge.yaml"
    reforge_yaml.write_text("llm:\n  provider: codex\n", encoding="utf-8")
    assert discover_config_path() == reforge_yaml.resolve()

    # Case 3: When reforge.yaml is removed -> None
    reforge_yaml.unlink()
    assert discover_config_path() is None


def test_explicit_environment_config_wins_default_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "custom.yaml"
    config_path.write_text("llm:\n  provider: codex\n", encoding="utf-8")
    monkeypatch.setenv("REFORGE_CONFIG", str(config_path))

    assert discover_config_path() == config_path.resolve()


def test_yaml_provider_credentials_are_relative_to_config_file(tmp_path: Path) -> None:
    config_path = tmp_path / "config" / "reforge.yaml"
    config_path.parent.mkdir()
    config_path.write_text(
        """\
llm:
  provider: codex
  fallbacks:
    - provider: gemini
      service_account_file: credentials/primary.json
agents:
  reverser:
    provider: gemini
    service_account_file: credentials/reverser.json
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.llm.fallbacks[0].service_account_file == str(
        (config_path.parent / "credentials" / "primary.json").resolve()
    )
    assert config.agents.reverser is not None
    assert config.agents.reverser.service_account_file == str(
        (config_path.parent / "credentials" / "reverser.json").resolve()
    )


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
    monkeypatch.setenv("REFORGE_LLM_PROVIDER", "openai")
    monkeypatch.setenv("REFORGE_LLM_MODEL", "gpt-4o")
    config = load_config(None)
    assert config.llm.provider == "openai"
    assert config.llm.model == "gpt-4o"


def test_reforge_env_override_takes_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REFORGE_LLM_PROVIDER", "openai")
    monkeypatch.setenv("REFORGE_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("REFORGE_LLM_MODEL", "gpt-4o")
    monkeypatch.setenv("REFORGE_LLM_MODEL", "claude-3-7-sonnet")
    config = load_config(None)
    assert config.llm.provider == "anthropic"
    assert config.llm.model == "claude-3-7-sonnet"


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
    assert config.agents.checker.model == "gpt-6.1-sol"
    assert config.agents.checker.model != "gemini-model"
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
