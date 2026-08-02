"""Tests for managed external-tool discovery."""

from __future__ import annotations

import os
from pathlib import Path

from re_agent.utils.toolchain import (
    managed_tools_root,
    resolve_adb,
    resolve_apk_signer,
    resolve_frida_gadget_path,
    resolve_il2cpp_dumper,
    resolve_jadx,
)


def test_managed_tool_resolvers_find_versioned_install(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("RE_AGENT_TOOLS_DIR", str(tmp_path))
    monkeypatch.delenv("RE_AGENT_APK_SIGNER_JAR", raising=False)
    monkeypatch.delenv("RE_AGENT_FRIDA_GADGET_DIR", raising=False)
    monkeypatch.delenv("RE_AGENT_IL2CPP_DUMPER", raising=False)
    monkeypatch.setattr("re_agent.utils.toolchain.shutil.which", lambda _name: None)

    signer = tmp_path / "uber-apk-signer" / "1.3.0" / "uber-apk-signer-1.3.0.jar"
    gadget = tmp_path / "frida-gadget" / "17.16.4"
    adb = tmp_path / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
    jadx = tmp_path / "jadx" / "1.5.6" / "bin" / "jadx.bat"
    dumper = tmp_path / "il2cpp-dumper" / "6.7.46" / "Il2CppDumper.exe"
    for file_path in (signer, adb, jadx, dumper):
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(b"tool")
    gadget.mkdir(parents=True)

    assert managed_tools_root() == tmp_path
    assert resolve_apk_signer() == signer.resolve()
    assert resolve_frida_gadget_path(version="17.16.4") == gadget.resolve()
    assert resolve_adb() == adb.resolve()
    assert resolve_jadx() == jadx.resolve()
    assert resolve_il2cpp_dumper() == dumper.resolve()


def test_explicit_invalid_tool_does_not_hide_managed_fallback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("RE_AGENT_TOOLS_DIR", str(tmp_path))
    monkeypatch.delenv("RE_AGENT_APK_SIGNER_JAR", raising=False)
    signer = tmp_path / "uber-apk-signer" / "1.3.0" / "uber-apk-signer-1.3.0.jar"
    signer.parent.mkdir(parents=True)
    signer.write_bytes(b"jar")

    assert resolve_apk_signer(tmp_path / "missing.jar") == signer.resolve()
