"""Smoke tests for CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from reforge.cli.main import _resolve_default_config_argument, build_parser, main


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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "resolved.yaml"
    config_path.write_text("project_profile:\n  name: resolved\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "reforge.config.loader.discover_config_path",
        lambda: config_path,
    )
    args = build_parser().parse_args(["status"])

    _resolve_default_config_argument(args)

    assert args.config == str(config_path)


def test_non_init_command_uses_schema_defaults_when_no_config_is_discovered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "reforge.config.loader.discover_config_path",
        lambda: None,
    )
    args = build_parser().parse_args(["status"])

    _resolve_default_config_argument(args)

    assert args.config is None


def test_init_keeps_current_directory_config_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "repository.yaml"
    config_path.write_text("project_profile: {}\n", encoding="utf-8")
    monkeypatch.setattr(
        "reforge.config.loader.discover_config_path",
        lambda: config_path,
    )
    args = build_parser().parse_args(["init"])

    _resolve_default_config_argument(args)

    assert args.config == "reforge.yaml"


def test_explicit_missing_config_fails_before_command_dispatch(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing.yaml"

    assert main(["--config", str(missing), "doctor"]) == 2
    assert f"Config file not found: {missing}" in capsys.readouterr().out


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == "reforge 0.3.0"


def test_init_creates_config(tmp_path: Path) -> None:
    config_path = tmp_path / "reforge.yaml"
    result = main(["--config", str(config_path), "init"])
    assert result == 0
    assert config_path.exists()


def test_init_fails_if_exists(tmp_path: Path) -> None:
    config_path = tmp_path / "reforge.yaml"
    config_path.write_text("existing")
    result = main(["--config", str(config_path), "init"])
    assert result == 1


def test_status_no_session(tmp_path: Path) -> None:
    config_path = tmp_path / "reforge.yaml"
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
    config_path = tmp_path / "reforge.yaml"
    config_path.write_text("llm:\n  provider: claude\n")
    result = main(["--config", str(config_path), "reverse", "--address", "0x6F86A0", "--dry-run"])
    assert result == 0


def test_reverse_no_target(tmp_path: Path) -> None:
    config_path = tmp_path / "reforge.yaml"
    config_path.write_text("llm:\n  provider: claude\n")
    result = main(["--config", str(config_path), "reverse"])
    assert result == 1


def test_reverse_rejects_impossible_validation_before_llm(tmp_path: Path) -> None:
    config_path = tmp_path / "reforge.yaml"
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


def test_plan_parser() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["plan", "--address", "0x100", "--match", "CPlayer*", "--output", "plan.json", "--max-depth", "2"]
    )
    assert args.command == "plan"
    assert args.address == ["0x100"]
    assert args.match == ["CPlayer*"]
    assert args.output == "plan.json"
    assert args.max_depth == 2


def test_evidence_parser() -> None:
    parser = build_parser()
    args = parser.parse_args(["evidence", "--manifest", "plan.json", "--output", "evidence_dir"])
    assert args.command == "evidence"
    assert args.manifest == "plan.json"
    assert args.output == "evidence_dir"


def test_benchmark_parser() -> None:
    parser = build_parser()
    args = parser.parse_args(["benchmark", "--manifest", "bench.json", "--output", "report.json"])
    assert args.command == "benchmark"
    assert args.manifest == "bench.json"
    assert args.output == "report.json"


def test_reverse_manifest_combining_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    from reforge.cli.main import _main

    assert main(["reverse", "--manifest", "plan.json", "--address", "0x100"]) == 2
    assert "cannot be combined" in capsys.readouterr().out

    import pytest

    with pytest.raises(ValueError, match="cannot be combined"):
        _main(["reverse", "--manifest", "plan.json", "--address", "0x100"])


def test_benchmark_command_executes(tmp_path: Path) -> None:
    manifest_path = tmp_path / "bench.json"
    manifest_path.write_text(
        json.dumps(
            [
                {
                    "name": "echo_test",
                    "reference": [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
                    "candidate": [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
                    "cases": [{"input": "hi", "expected_output": "hi"}],
                    "timeout_s": 10,
                }
            ]
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "report.json"
    result = main(["benchmark", "--manifest", str(manifest_path), "--output", str(output_path)])
    assert result == 0
    assert output_path.exists()
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["expectations_met"] == 1


def test_plan_command_executes(tmp_path: Path) -> None:
    from unittest.mock import patch

    from reforge.backend.stub import StubBackend

    config_path = tmp_path / "reforge.yaml"
    config_path.write_text("backend:\n  type: stub\n", encoding="utf-8")
    output_path = tmp_path / "plan.json"

    with patch("reforge.cli.cmd_plan.create_backend", return_value=StubBackend()):
        result = main(
            [
                "--config",
                str(config_path),
                "plan",
                "--address",
                "140001000",
                "--output",
                str(output_path),
            ]
        )
    assert result == 0
    assert output_path.exists()
