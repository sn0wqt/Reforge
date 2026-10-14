"""Smoke tests for CLI."""

from __future__ import annotations

from pathlib import Path

from re_agent.cli.main import _resolve_default_config_argument, build_parser, main


def test_parser_builds() -> None:
    parser = build_parser()
    assert parser is not None


def test_estimate_parser_accepts_class() -> None:
    args = build_parser().parse_args(["estimate", "--class", "CTest", "--limit", "3"])
    assert args.command == "estimate"
    assert args.class_name == "CTest"
    assert args.limit == 3


def test_batch_parser_exposes_binary_and_semantic_limit() -> None:
    args = build_parser().parse_args(
        [
            "batch",
            "--binary",
            "game.apk",
            "--limit",
            "25",
        ]
    )
    assert args.binary == "game.apk"
    assert args.limit == 25


def test_no_command_returns_zero() -> None:
    assert main([]) == 0


def test_every_non_init_command_resolves_checkout_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "resolved.yaml"
    config_path.write_text("project_profile:\n  name: resolved\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "re_agent.config.loader.discover_config_path",
        lambda: config_path,
    )
    args = build_parser().parse_args(["status"])

    _resolve_default_config_argument(args)

    assert args.config == str(config_path)


def test_non_init_command_uses_schema_defaults_when_no_config_is_discovered(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "re_agent.config.loader.discover_config_path",
        lambda: None,
    )
    args = build_parser().parse_args(["status"])

    _resolve_default_config_argument(args)

    assert args.config is None


def test_init_keeps_current_directory_config_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "repository.yaml"
    config_path.write_text("project_profile: {}\n", encoding="utf-8")
    monkeypatch.setattr(
        "re_agent.config.loader.discover_config_path",
        lambda: config_path,
    )
    args = build_parser().parse_args(["init"])

    _resolve_default_config_argument(args)

    assert args.config in ("reforge.yaml", "re-agent.yaml")


def test_explicit_missing_config_fails_before_command_dispatch(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing.yaml"

    assert main(["--config", str(missing), "doctor"]) == 2
    assert f"Config file not found: {missing}" in capsys.readouterr().out


def test_version_flag(capsys) -> None:
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() in ("reforge 0.3.0", "re-agent 0.3.0")


def test_init_creates_config(tmp_path: Path) -> None:
    config_path = tmp_path / "re-agent.yaml"
    result = main(["--config", str(config_path), "init"])
    assert result == 0
    assert config_path.exists()


def test_init_fails_if_exists(tmp_path: Path) -> None:
    config_path = tmp_path / "re-agent.yaml"
    config_path.write_text("existing")
    result = main(["--config", str(config_path), "init"])
    assert result == 1


def test_status_no_session(tmp_path: Path) -> None:
    config_path = tmp_path / "re-agent.yaml"
    posix_tmp = tmp_path.as_posix()
    config_path.write_text(f'''
output:
  session_file: "{posix_tmp}/progress.json"
  report_dir: "{posix_tmp}/reports"
  log_dir: "{posix_tmp}/logs"
''')
    result = main(["--config", str(config_path), "status"])
    assert result == 0


def test_reverse_dry_run(tmp_path: Path) -> None:
    config_path = tmp_path / "re-agent.yaml"
    config_path.write_text("llm:\n  provider: claude\n")
    result = main(["--config", str(config_path), "reverse", "--address", "0x6F86A0", "--dry-run"])
    assert result == 0


def test_reverse_no_target(tmp_path: Path) -> None:
    config_path = tmp_path / "re-agent.yaml"
    config_path.write_text("llm:\n  provider: claude\n")
    result = main(["--config", str(config_path), "reverse"])
    assert result == 1


def test_reverse_rejects_impossible_validation_before_llm(tmp_path: Path) -> None:
    config_path = tmp_path / "re-agent.yaml"
    config_path.write_text(
        """\
llm:
  provider: codex
validation:
  enabled: true
  require_verified: true
  build_commands: []
  test_commands: []
  runtime_commands: []
""",
        encoding="utf-8",
    )

    result = main(["--config", str(config_path), "reverse", "--address", "0x100"])

    assert result == 2
