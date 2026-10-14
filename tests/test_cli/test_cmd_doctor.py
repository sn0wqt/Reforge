"""Tests for the toolchain doctor CLI."""

from __future__ import annotations

import json
from pathlib import Path

from re_agent.cli.main import main


def test_doctor_json_reports_ready(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "re_agent.cli.cmd_doctor.collect_toolchain_status",
        lambda: [
            {
                "name": "required-tool",
                "required": True,
                "ok": True,
                "path": str(tmp_path / "tool.exe"),
                "version": "1.0",
                "detail": None,
            }
        ],
    )
    monkeypatch.setattr(
        "re_agent.cli.cmd_doctor.managed_tools_root",
        lambda: tmp_path,
    )

    assert main(["doctor", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is True
    assert payload["capabilities"]["analysis"]["ready"] is True
    assert payload["managed_tools_root"] == str(tmp_path)


def test_doctor_fails_when_required_tool_is_missing(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "re_agent.cli.cmd_doctor.collect_toolchain_status",
        lambda: [
            {
                "name": "missing-tool",
                "required": True,
                "ok": False,
                "path": None,
                "version": None,
                "detail": None,
            }
        ],
    )

    assert main(["doctor"]) == 2
    assert "Core analysis requirements are missing" in capsys.readouterr().out


def test_doctor_optional_android_workflows_do_not_block_analysis(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        "re_agent.cli.cmd_doctor.collect_toolchain_status",
        lambda: [
            {
                "name": "Python",
                "required": True,
                "required_for": ["analysis"],
                "ok": True,
                "path": "python",
                "version": "3.13",
                "detail": None,
            },
            {
                "name": "apktool",
                "required": False,
                "required_for": ["android_structural_repack", "gadget_non_root"],
                "ok": False,
                "path": None,
                "version": None,
                "detail": None,
            },
            {
                "name": "Java",
                "required": False,
                "required_for": [
                    "android_repack",
                    "android_structural_repack",
                    "gadget_non_root",
                ],
                "ok": True,
                "path": "java",
                "version": "21",
                "detail": None,
            },
            {
                "name": "uber-apk-signer",
                "required": False,
                "required_for": [
                    "android_repack",
                    "android_structural_repack",
                    "gadget_non_root",
                ],
                "ok": True,
                "path": "signer.jar",
                "version": "1.3.0",
                "detail": None,
            },
            {
                "name": "Frida Gadget",
                "required": False,
                "required_for": ["gadget_non_root"],
                "ok": False,
                "path": None,
                "version": None,
                "detail": None,
            },
            {
                "name": "ADB",
                "required": False,
                "required_for": [],
                "ok": False,
                "path": None,
                "version": None,
                "detail": None,
            },
        ],
    )

    assert main(["doctor", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is True
    assert payload["capabilities"]["analysis"]["ready"] is True
    assert payload["capabilities"]["android_repack"]["ready"] is True
    assert payload["capabilities"]["android_structural_repack"]["ready"] is False
    assert payload["capabilities"]["gadget_non_root"]["ready"] is False
    assert payload["full_android_toolchain_ready"] is False
