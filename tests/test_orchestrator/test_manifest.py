from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from reforge.backend.stub import StubBackend
from reforge.cli.main import main
from reforge.config.schema import ReforgeConfig, ValidationConfig
from reforge.core.identity import project_fingerprint
from reforge.core.models import FunctionTarget, ReversalResult, XRef
from reforge.core.session import Session
from reforge.core.target_plan import TargetPlan
from reforge.orchestrator.batch_runner import reverse_manifest
from tests.test_agents.test_loop import MockLLM


def config_for(tmp_path: Path) -> ReforgeConfig:
    config = ReforgeConfig()
    config.project_profile.source_root = str(tmp_path / "src")
    Path(config.project_profile.source_root).mkdir(parents=True, exist_ok=True)
    config.output.report_dir = str(tmp_path / "reports")
    config.output.log_dir = str(tmp_path / "logs")
    config.output.session_file = str(tmp_path / "session.json")
    config.orchestrator.objective_verifier_enabled = False
    config.orchestrator.investigation_enabled = False
    config.parity.enabled = False
    return config


def test_manifest_orders_mixed_classes_and_resumes(tmp_path: Path) -> None:
    class Backend(StubBackend):
        def xrefs_from(self, target: str) -> list[XRef]:
            return [XRef("200", "B", "CALL"), XRef("999", "External", "CALL")] if target == "00000100" else []

    config = config_for(tmp_path)
    session = Session(config.output.session_file)
    plan = TargetPlan(
        "a" * 64,
        ["00000100"],
        [FunctionTarget("00000100", "A", "Caller"), FunctionTarget("00000200", "B", "Leaf")],
    )
    visited: list[str] = []

    def reverse(target: FunctionTarget, *args: object, **kwargs: object) -> ReversalResult:
        visited.append(target.address)
        result = ReversalResult(target, "int f() {}", success=True)
        session_obj = kwargs.get("session")
        if isinstance(session_obj, Session):
            session_obj.record_result(result)
        return result

    with patch("reforge.orchestrator.class_runner.reverse_single", side_effect=reverse):
        first = reverse_manifest(plan, config, Backend(), MockLLM([]), session, max_functions=1)
        second = reverse_manifest(plan, config, Backend(), MockLLM([]), session, max_functions=2)
    assert len(first) == len(second) == 1
    assert visited == ["00000200", "00000100"]
    assert not session.is_attempted("999")


def test_manifest_failed_attempt_limit_is_preserved(tmp_path: Path) -> None:
    config = config_for(tmp_path)
    config.orchestrator.max_attempts_per_function = 1
    session = Session(config.output.session_file)
    target = FunctionTarget("00000100", "", "f")
    session.record_result(ReversalResult(target, "", success=False))
    plan = TargetPlan("a" * 64, [target.address], [target])
    with patch("reforge.orchestrator.class_runner.reverse_single", side_effect=AssertionError("must not retry")):
        assert reverse_manifest(plan, config, StubBackend(), MockLLM([]), session) == []


def test_manifest_preflight_before_provider(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"backend": {"type": "stub"}, "validation": {"enabled": False}}))
    from reforge.config.loader import load_config

    plan = TargetPlan(
        project_fingerprint(load_config(config_path)),
        ["00000100"],
        [FunctionTarget("00000100", "", "f")],
    )
    path = tmp_path / "plan.json"
    plan.save(path)
    with patch("reforge.llm.registry.create_provider", side_effect=AssertionError("must not call")):
        assert main(["--config", str(config_path), "reverse", "--manifest", str(path), "--dry-run"]) == 0
        plan.identity = "a" * 64
        plan.save(path)
        assert main(["--config", str(config_path), "reverse", "--manifest", str(path)]) in (1, 2)


@pytest.mark.parametrize("flag", ["--address", "--class"])
def test_manifest_excludes_other_target_modes(flag: str) -> None:
    assert main(["reverse", "--manifest", "missing.json", flag, "100"]) in (1, 2)


def test_manifest_cumulative_resume_across_classes(tmp_path: Path) -> None:
    import shutil

    compiler = shutil.which("c++")
    if not compiler:
        pytest.skip("C++ compiler required")
    config = config_for(tmp_path)
    file = Path(config.project_profile.source_root) / "group.cpp"
    original = (
        "struct A { static int f(); }; struct B { static int g(); };\n"
        "int A::f() { return 0; }\nint B::g() { return 0; }\n"
        "int main() { return A::f()==7 && (B::g()==0 || B::g()==8) ? 0 : 1; }"
    )
    file.write_text(original, encoding="utf-8")
    config.validation = ValidationConfig(
        copy_project=True,
        project_root=str(tmp_path),
        trust_configured_commands=True,
        allow_host_commands=True,
        build_commands=[[compiler, "src/group.cpp", "-o", "program.exe"]],
        test_commands=[["{overlay_root}/program.exe"]],
    )
    plan = TargetPlan(
        "a" * 64,
        ["00000100"],
        [FunctionTarget("00000100", "A", "f"), FunctionTarget("00000200", "B", "g")],
    )
    session = Session(config.output.session_file)
    first = reverse_manifest(
        plan,
        config,
        StubBackend(),
        MockLLM(["```cpp\nint A::f() { return 7; }\n```"]),
        session,
        1,
        MockLLM(['{"verdict":"PASS","summary":"ok","issues":[],"fix_instructions":[]}']),
    )
    second = reverse_manifest(
        plan,
        config,
        StubBackend(),
        MockLLM(["```cpp\nint B::g() { return A::f()+1; }\n```"]),
        session,
        1,
        MockLLM(['{"verdict":"PASS","summary":"ok","issues":[],"fix_instructions":[]}']),
    )
    assert first[0].success and second[0].success
    assert file.read_text(encoding="utf-8") == original
