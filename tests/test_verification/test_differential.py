"""Tests for JSON harness differential validation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from reforge.config.schema import ValidationConfig
from reforge.core.models import Verdict
from reforge.verification.candidate import validate_candidate
from reforge.verification.differential import compare_commands


def test_differential_empty_inputs_fail(tmp_path: Path) -> None:
    result = compare_commands([], ["cmd"], [{"input": 1}], cwd=tmp_path)
    assert not result.passed
    assert "requires two harnesses" in result.findings[0]

    result2 = compare_commands(["cmd"], [], [{"input": 1}], cwd=tmp_path)
    assert not result2.passed

    result3 = compare_commands(["cmd"], ["cmd"], [], cwd=tmp_path)
    assert not result3.passed


def test_differential_matching_outputs_pass(tmp_path: Path) -> None:
    script = "import json, sys; data = json.load(sys.stdin); print(json.dumps({'out': data['val'] * 2}))"
    cmd = [sys.executable, "-c", script]
    cases = [{"val": 1}, {"val": 2}, {"val": 3}]
    result = compare_commands(cmd, cmd, cases, cwd=tmp_path)
    assert result.passed
    assert result.cases_run == 3
    assert "All 3 differential cases matched" in result.findings[0]


def test_differential_mismatching_outputs_fail(tmp_path: Path) -> None:
    ref_script = "import json, sys; json.load(sys.stdin); print(json.dumps({'out': 10}))"
    cand_script = "import json, sys; json.load(sys.stdin); print(json.dumps({'out': 20}))"
    ref_cmd = [sys.executable, "-c", ref_script]
    cand_cmd = [sys.executable, "-c", cand_script]
    cases = [{"case_id": 1}]
    result = compare_commands(ref_cmd, cand_cmd, cases, cwd=tmp_path)
    assert not result.passed
    assert result.cases_run == 1
    diff = json.loads(result.findings[0])
    assert diff["reference"] == {"out": 10}
    assert diff["candidate"] == {"out": 20}


def test_differential_harness_error_exit(tmp_path: Path) -> None:
    ref_cmd = [sys.executable, "-c", "import sys; sys.exit(42)"]
    cand_cmd = [sys.executable, "-c", "import json, sys; json.load(sys.stdin); print('{}')"]
    cases = [{"input": 1}]
    result = compare_commands(ref_cmd, cand_cmd, cases, cwd=tmp_path)
    assert not result.passed
    assert "reference harness exit 42" in result.findings[0]


def test_differential_rejects_non_standard_json_constants(tmp_path: Path) -> None:
    # NaN is non-standard JSON
    ref_cmd = [sys.executable, "-c", "print('{\"val\": NaN}')"]
    cand_cmd = [sys.executable, "-c", "print('{\"val\": 1}')"]
    cases = [{"input": 1}]
    result = compare_commands(ref_cmd, cand_cmd, cases, cwd=tmp_path)
    assert not result.passed
    assert "Non-standard JSON constant: NaN" in result.findings[0]


def test_differential_gate_integrated_in_validate_candidate(tmp_path: Path) -> None:
    cases_file = tmp_path / "cases.json"
    cases_file.write_text(json.dumps([{"x": 1}, {"x": 2}]), encoding="utf-8")

    script = "import json, sys; data = json.load(sys.stdin); print(json.dumps({'doubled': data['x'] * 2}))"
    harness = [sys.executable, "-c", script]

    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("void f() {}", encoding="utf-8")

    config = ValidationConfig(
        differential_reference=harness,
        differential_candidate=harness,
        differential_cases_file=str(cases_file),
        trust_configured_commands=True,
    )

    verdict = validate_candidate(config, candidate, None)
    assert verdict.verdict == Verdict.PASS
    assert any("All 2 differential cases matched" in f for f in verdict.findings)
    assert any(c.get("kind") == "differential" and c.get("verdict") == "PASS" for c in verdict.checks)
