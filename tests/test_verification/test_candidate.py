"""Tests for candidate overlays and validation gates."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from re_agent.config.schema import ProjectProfile, ValidationConfig
from re_agent.core.models import FunctionTarget, Verdict
from re_agent.parity.source_indexer import SourceIndexer
from re_agent.verification.candidate import (
    cleanup_candidate_overlay,
    create_candidate_overlay,
    extract_candidate_body,
    validate_candidate,
    validation_preflight_error,
)


def test_candidate_overlay_replaces_only_function_body(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    source_file = source_root / "Train.cpp"
    source_file.write_text(
        "void CTrain::Go() { OldCall(); }\nvoid CTrain::Stop() { KeepMe(); }\n",
        encoding="utf-8",
    )
    indexer = SourceIndexer(source_root, ProjectProfile(source_root=str(source_root)))
    source = indexer.find("CTrain", "Go")
    assert source is not None

    candidate = create_candidate_overlay(
        FunctionTarget("0x100", "CTrain", "Go"),
        "void CTrain::Go() { NewCall(); }",
        source,
        source_root,
        tmp_path / "reports",
    )
    text = candidate.read_text(encoding="utf-8")
    assert "NewCall" in text
    assert "OldCall" not in text
    assert "KeepMe" in text
    assert source_file.read_text(encoding="utf-8").startswith("void CTrain::Go() { OldCall")


def test_candidate_overlay_sanitizes_qualified_class_name(tmp_path: Path) -> None:
    candidate = create_candidate_overlay(
        FunctionTarget("0x100", "app::ui::Widget", "Render"),
        "void Render() { NewCall(); }",
        None,
        tmp_path / "src",
        tmp_path / "reports",
    )
    assert candidate.exists()
    assert "::" not in candidate.name
    assert candidate.read_text(encoding="utf-8") == "void Render() { NewCall(); }\n"


def test_candidate_overlay_sanitizes_template_and_operator_names(tmp_path: Path) -> None:
    candidate = create_candidate_overlay(
        FunctionTarget("0x101", "std::vector<int, alloc>", "operator<"),
        "void operator<() {}",
        None,
        tmp_path / "src",
        tmp_path / "reports",
    )
    assert candidate.exists()
    illegal_chars = set(':<>,/\\*?"| ')
    assert not illegal_chars.intersection(candidate.name)


def test_extract_candidate_body_ignores_braces_in_strings_and_comments() -> None:
    code = r"""
void Player::Update() {
    const char* text = "{not a body}";
    // }
    if (ready) { Run(); }
}
"""

    body = extract_candidate_body(code)

    assert body.startswith("{")
    assert body.endswith("}")
    assert "Run();" in body


def test_extract_candidate_body_rejects_multiple_definitions() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        extract_candidate_body("void first() {} void second() {}")


def test_validation_gate_runs_configured_command(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("void f() {}", encoding="utf-8")
    verdict = validate_candidate(
        ValidationConfig(
            build_commands=["test -f '{candidate_file}'"],
            working_directory=str(tmp_path),
            allow_host_commands=True,
            trust_configured_commands=True,
        ),
        candidate,
        None,
    )
    assert verdict.verdict == Verdict.PASS


def test_required_build_without_command_fails(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("void f() {}", encoding="utf-8")
    verdict = validate_candidate(ValidationConfig(require_build=True), candidate, None)
    assert verdict.verdict == Verdict.FAIL


def test_host_commands_require_separate_execution_consent(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("void f() {}", encoding="utf-8")
    with patch("re_agent.verification.candidate.subprocess.run") as run:
        verdict = validate_candidate(
            ValidationConfig(
                build_commands=["test -f '{candidate_file}'"],
                trust_configured_commands=True,
            ),
            candidate,
            None,
        )
    assert verdict.verdict == Verdict.FAIL
    assert "host execution is disabled" in verdict.summary
    run.assert_not_called()


def test_nonisolated_command_must_consume_candidate(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("this is invalid C++", encoding="utf-8")
    verdict = validate_candidate(
        ValidationConfig(
            build_commands=["true"],
            working_directory=str(tmp_path),
            allow_host_commands=True,
        ),
        candidate,
        None,
    )
    assert verdict.verdict == Verdict.FAIL
    assert "explicitly consume" in verdict.summary


def test_untrusted_shell_gate_is_not_accepted_as_proof(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("invalid C++", encoding="utf-8")
    verdict = validate_candidate(
        ValidationConfig(
            build_commands=["true # $RE_AGENT_CANDIDATE_FILE"],
            working_directory=str(tmp_path),
            allow_host_commands=True,
        ),
        candidate,
        None,
    )
    assert verdict.verdict == Verdict.UNKNOWN
    assert "trust_configured_commands" in verdict.summary


def test_validation_normalizes_subprocess_oserror(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("void f() {}", encoding="utf-8")
    with patch(
        "re_agent.verification.candidate.subprocess.run",
        side_effect=OSError("bad handle"),
    ):
        verdict = validate_candidate(
            ValidationConfig(
                build_commands=["check '{candidate_file}'"],
                allow_host_commands=True,
                trust_configured_commands=True,
            ),
            candidate,
            None,
        )
    assert verdict.verdict == Verdict.FAIL
    assert "could not be started" in verdict.summary
    assert any("bad handle" in finding for finding in verdict.findings)


def test_validation_commands_do_not_inherit_interactive_stdin(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("void f() {}", encoding="utf-8")
    completed = subprocess.CompletedProcess([], 0, stdout="")
    with patch(
        "re_agent.verification.candidate.subprocess.run",
        return_value=completed,
    ) as run:
        verdict = validate_candidate(
            ValidationConfig(
                build_commands=["check '{candidate_file}'"],
                allow_host_commands=True,
                trust_configured_commands=True,
            ),
            candidate,
            None,
        )

    assert verdict.verdict == Verdict.PASS
    assert run.call_args.kwargs["stdin"] is subprocess.DEVNULL


def test_verified_validation_preflight_rejects_impossible_config() -> None:
    config = ValidationConfig(enabled=True, require_verified=True)
    assert "no build/test/runtime" in str(validation_preflight_error(config))

    config.build_commands = ['clang++ -fsyntax-only "{candidate_file}"']
    assert "allow_host_commands" in str(validation_preflight_error(config))

    config.allow_host_commands = True
    assert "trust_configured_commands" in str(validation_preflight_error(config))

    config.trust_configured_commands = True
    assert validation_preflight_error(config) is None


def test_failed_project_copy_creation_cleans_temporary_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.cpp"
    outside.write_text("void CTest::Foo() {}\n", encoding="utf-8")
    indexer = SourceIndexer(tmp_path, ProjectProfile(source_root=str(tmp_path)))
    source = indexer.find("CTest", "Foo")
    assert source is not None
    overlay = tmp_path / "forced-overlay"
    monkeypatch.setattr("re_agent.verification.candidate.tempfile.mkdtemp", lambda **_: str(overlay))

    with pytest.raises(ValueError, match="outside validation.project_root"):
        create_candidate_overlay(
            FunctionTarget("0x100", "CTest", "Foo"),
            "void CTest::Foo() {}",
            source,
            tmp_path,
            tmp_path / "reports",
            project_root=project,
            copy_project=True,
        )

    assert not overlay.exists()


def test_copy_project_builds_against_isolated_candidate(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project / "src"
    source_root.mkdir(parents=True)
    source_file = source_root / "Train.cpp"
    source_file.write_text("void CTrain::Go() { OldCall(); }\n", encoding="utf-8")
    indexer = SourceIndexer(source_root, ProjectProfile(source_root=str(source_root)))
    source = indexer.find("CTrain", "Go")
    assert source is not None

    candidate = create_candidate_overlay(
        FunctionTarget("0x100", "CTrain", "Go"),
        "void CTrain::Go() { NewCall(); }",
        source,
        source_root,
        tmp_path / "reports",
        project_root=project,
        copy_project=True,
    )
    verdict = validate_candidate(
        ValidationConfig(
            copy_project=True,
            project_root=str(project),
            build_commands=["grep -q NewCall src/Train.cpp"],
            allow_host_commands=True,
            trust_configured_commands=True,
        ),
        candidate,
        str(source_file),
    )
    assert verdict.verdict == Verdict.PASS
    assert "OldCall" in source_file.read_text(encoding="utf-8")
    overlay_root = candidate.parents[1]
    cleanup_candidate_overlay(candidate)
    assert not overlay_root.exists()


def test_copy_project_rejects_symlinks(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = project / "outside-link"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Symbolic links are unavailable in this test environment")

    with pytest.raises(ValueError, match="Symbolic links and junctions"):
        create_candidate_overlay(
            FunctionTarget("0x100", "CTest", "Foo"),
            "void CTest::Foo() {}",
            None,
            project,
            tmp_path / "reports",
            project_root=project,
            copy_project=True,
        )


def test_isolated_working_directory_cannot_escape_overlay(tmp_path: Path) -> None:
    overlay = tmp_path / "re-agent-overlay"
    overlay.mkdir()
    (overlay / ".re-agent-overlay").write_text("schema_version=1\n", encoding="utf-8")
    candidate = overlay / "candidate.cpp"
    candidate.write_text("void f() {}", encoding="utf-8")

    verdict = validate_candidate(
        ValidationConfig(
            copy_project=True,
            build_commands=["check"],
            working_directory=str(tmp_path),
            allow_host_commands=True,
        ),
        candidate,
        "candidate.cpp",
    )

    assert verdict.verdict == Verdict.FAIL
    assert "must stay inside" in verdict.summary
