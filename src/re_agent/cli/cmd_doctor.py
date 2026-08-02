"""Environment diagnostics for re-agent analysis and Android deployment tools."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from re_agent.packaging.frida_gadget import (
    GadgetPackagingError,
    inspect_frida_gadget_sources,
)
from re_agent.utils.toolchain import (
    managed_tools_root,
    resolve_adb,
    resolve_apk_signer,
    resolve_frida_gadget_path,
    resolve_il2cpp_dumper,
    resolve_jadx,
)


def _version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return lines[0][:300] if lines else None


def _entry(
    name: str,
    path: Path | str | None,
    *,
    required: bool,
    version: str | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "required": required,
        "ok": path is not None,
        "path": str(path) if path is not None else None,
        "version": version,
        "detail": detail,
    }


def collect_toolchain_status() -> list[dict[str, Any]]:
    """Collect deterministic tool status without modifying the environment."""
    apktool = shutil.which("apktool") or shutil.which("apktool.bat")
    java = shutil.which("java")
    frida = shutil.which("frida")
    frida_version = _version([frida, "--version"]) if frida else None
    signer = resolve_apk_signer()
    signer_version = _version([java, "-jar", str(signer), "--version"]) if signer is not None and java else None
    gadget = resolve_frida_gadget_path(version=frida_version)
    gadget_detail: str | None = None
    gadget_ok: Path | None = gadget
    if gadget is not None:
        try:
            abis = inspect_frida_gadget_sources(gadget)
            gadget_detail = "ABIs: " + ", ".join(abis)
        except GadgetPackagingError as exc:
            gadget_ok = None
            gadget_detail = str(exc)

    adb = resolve_adb()
    jadx = resolve_jadx()
    dumper = resolve_il2cpp_dumper()
    node = shutil.which("node")
    ghidra_bridge = shutil.which("ghidra-bridge")
    ghidra = shutil.which("ghidraRun") or shutil.which("ghidraRun.bat") or shutil.which("analyzeHeadless")
    codex = shutil.which("codex") or shutil.which("codex.cmd")
    antigravity = shutil.which("agy") or shutil.which("agy.exe")
    hermes_available = importlib.util.find_spec("hermes_dec") is not None

    return [
        _entry("Python", Path(sys.executable), required=True, version=sys.version.split()[0]),
        _entry(
            "apktool",
            apktool,
            required=True,
            version=_version([apktool, "--version"]) if apktool else None,
        ),
        _entry(
            "Java",
            java,
            required=True,
            version=_version([java, "-version"]) if java else None,
        ),
        _entry(
            "uber-apk-signer",
            signer,
            required=True,
            version=signer_version,
        ),
        _entry("Frida CLI", frida, required=True, version=frida_version),
        _entry(
            "Frida Gadget",
            gadget_ok,
            required=True,
            version=frida_version,
            detail=gadget_detail,
        ),
        _entry(
            "ADB",
            adb,
            required=True,
            version=_version([str(adb), "version"]) if adb else None,
        ),
        _entry(
            "JADX",
            jadx,
            required=False,
            version=_version([str(jadx), "--version"]) if jadx else None,
            detail="Used for deeper Java/Kotlin decompilation.",
        ),
        _entry(
            "Il2CppDumper",
            dumper,
            required=False,
            version=dumper.parent.name if dumper is not None else None,
            detail="Required for automatic Unity IL2CPP sidecar extraction.",
        ),
        _entry(
            "Hermes decoder",
            "python:hermes_dec" if hermes_available else None,
            required=False,
        ),
        _entry("Node.js", node, required=False, version=_version([node, "--version"]) if node else None),
        _entry("ghidra-bridge", ghidra_bridge, required=False),
        _entry("Ghidra runtime", ghidra, required=False),
        _entry("Codex CLI", codex, required=False),
        _entry("AntiGravity CLI", antigravity, required=False),
    ]


def cmd_doctor(args: argparse.Namespace) -> int:
    """Print installed-tool status and fail when the Android deployment core is incomplete."""
    entries = collect_toolchain_status()
    ready = all(entry["ok"] for entry in entries if entry["required"])
    if bool(getattr(args, "json", False)):
        print(
            json.dumps(
                {
                    "ready": ready,
                    "managed_tools_root": str(managed_tools_root()),
                    "tools": entries,
                },
                indent=2,
            )
        )
        return 0 if ready else 2

    print("re-agent toolchain doctor")
    print(f"Managed tools: {managed_tools_root()}")
    for entry in entries:
        state = "OK" if entry["ok"] else ("MISSING" if entry["required"] else "OPTIONAL")
        requirement = "required" if entry["required"] else "optional"
        suffix = f" - {entry['path']}" if entry["path"] else ""
        if entry["version"]:
            suffix += f" ({entry['version']})"
        if entry["detail"]:
            suffix += f"; {entry['detail']}"
        print(f"[{state:8}] {entry['name']} [{requirement}]{suffix}")
    print()
    if ready:
        print("[+] Android analysis, repackaging, Gadget, and ADB deployment tools are ready.")
        return 0
    print("[!] Required tools are missing. Run scripts/setup_android_tools.ps1 in PowerShell.")
    return 2
