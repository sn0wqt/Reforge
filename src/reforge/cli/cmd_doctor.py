"""Environment diagnostics for Reforge analysis and Android deployment tools."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from reforge.packaging.frida_gadget import (
    GadgetPackagingError,
    inspect_frida_gadget_sources,
)
from reforge.utils.toolchain import (
    managed_tools_root,
    resolve_adb,
    resolve_apk_signer,
    resolve_apktool,
    resolve_frida_gadget_path,
    resolve_il2cpp_dumper,
    resolve_jadx,
    resolve_wakaru,
)

_CAPABILITY_LABELS = {
    "analysis": "Core analysis",
    "android_repack": "Android single-asset replacement/signing",
    "android_structural_repack": "Android manifest/native structural repackaging",
    "gadget_non_root": "Non-root Android Frida Gadget workflow",
}


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
    required_for: tuple[str, ...] = (),
    version: str | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        # Backward-compatible global field: only core-analysis requirements
        # are globally required. Optional workflows are reported separately.
        "required": "analysis" in required_for,
        "required_for": list(required_for),
        "ok": path is not None,
        "path": str(path) if path is not None else None,
        "version": version,
        "detail": detail,
    }


def _capability_status(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Summarize independent workflows instead of one all-or-nothing toolchain."""
    capabilities: dict[str, dict[str, Any]] = {}
    for capability, label in _CAPABILITY_LABELS.items():
        required_entries = [
            entry
            for entry in entries
            if capability in entry.get("required_for", ())
            or (capability == "analysis" and "required_for" not in entry and bool(entry.get("required")))
        ]
        missing = [str(entry["name"]) for entry in required_entries if not entry.get("ok")]
        capabilities[capability] = {
            "label": label,
            "ready": not missing,
            "missing": missing,
        }
    return capabilities


def collect_toolchain_status() -> list[dict[str, Any]]:
    """Collect deterministic tool status without modifying the environment."""
    apktool_path = resolve_apktool()
    apktool = str(apktool_path) if apktool_path is not None else None
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
    from reforge.utils.toolchain import resolve_ghidra

    ghidra = (
        resolve_ghidra()
        or shutil.which("ghidraRun")
        or shutil.which("ghidraRun.bat")
        or shutil.which("analyzeHeadless")
        or shutil.which("analyzeHeadless.bat")
    )
    codex = shutil.which("codex") or shutil.which("codex.cmd")
    antigravity = shutil.which("agy") or shutil.which("agy.exe")
    cliproxy_candidates = [
        shutil.which("cli-proxy"),
        shutil.which("cli-proxy.exe"),
        shutil.which("cpa-gui"),
        Path.home() / "Library" / "Application Support" / "com.cpa.gui" / "cpa-core" / "cli-proxy-api",
        Path.home() / ".local" / "share" / "cpa-core" / "cli-proxy-api",
        Path.home() / ".config" / "CLIProxyAPI" / "cli-proxy-api",
        Path.home() / "CLIProxyAPI" / "cli-proxy-api.exe",
    ]
    cliproxy = next((str(p) for p in cliproxy_candidates if p and (isinstance(p, str) or Path(p).is_file())), None)
    hermes_available = importlib.util.find_spec("hermes_dec") is not None
    frida_py_available = importlib.util.find_spec("frida") is not None
    wakaru = resolve_wakaru()
    rea_bridge = os.environ.get("REA_MCP_COMMAND") or shutil.which("rea") or shutil.which("rea.cmd")

    return [
        _entry(
            "Python",
            Path(sys.executable),
            required_for=("analysis",),
            version=sys.version.split()[0],
        ),
        _entry(
            "apktool",
            apktool,
            required_for=("android_structural_repack", "gadget_non_root"),
            version=_version([apktool, "--version"]) if apktool else None,
        ),
        _entry(
            "Java",
            java,
            required_for=(
                "android_repack",
                "android_structural_repack",
                "gadget_non_root",
            ),
            version=_version([java, "-version"]) if java else None,
        ),
        _entry(
            "uber-apk-signer",
            signer,
            required_for=(
                "android_repack",
                "android_structural_repack",
                "gadget_non_root",
            ),
            version=signer_version,
        ),
        _entry(
            "Frida CLI",
            frida,
            required_for=("gadget_non_root",),
            version=frida_version,
        ),
        _entry(
            "Frida Gadget",
            gadget_ok,
            required_for=("gadget_non_root",),
            version=frida_version,
            detail=gadget_detail,
        ),
        _entry(
            "ADB",
            adb,
            required_for=(),
            version=_version([str(adb), "version"]) if adb else None,
        ),
        _entry(
            "JADX",
            jadx,
            required_for=(),
            version=_version([str(jadx), "--version"]) if jadx else None,
            detail=(
                "Available for manual Java/Kotlin review; automatic discovery currently uses the bounded DEX parser."
            ),
        ),
        _entry(
            "Il2CppDumper",
            dumper,
            required_for=(),
            version=dumper.parent.name if dumper is not None else None,
            detail="Required for automatic Unity IL2CPP sidecar extraction.",
        ),
        _entry(
            "Hermes decoder",
            "python:hermes_dec" if hermes_available else None,
            required_for=(),
        ),
        _entry(
            "Wakaru decompiler",
            wakaru,
            required_for=(),
            version=_version([str(wakaru), "--version"]) if wakaru else None,
            detail="Used for Webpack bundle recovery and JS de-minification.",
        ),
        _entry(
            "Frida Python runtime",
            "python:frida" if frida_py_available else None,
            required_for=(),
            detail="Enables in-process Frida tracing with 16 MiB circular buffer and orphan prevention.",
        ),
        _entry(
            "REA MCP bridge",
            rea_bridge,
            required_for=(),
            detail="Enables multi-decompiler backend bridge (--backend rea) for IDA Pro, Hopper, Cutter, Rizin.",
        ),
        _entry("Node.js", node, version=_version([node, "--version"]) if node else None),
        _entry("ghidra-bridge", ghidra_bridge),
        _entry("Ghidra runtime", ghidra),
        _entry("Codex CLI", codex),
        _entry("AntiGravity CLI", antigravity),
        _entry("CLIProxyAPI", cliproxy, detail="Local OpenAI-compatible API gateway"),
    ]


def _cmd_doctor_config(args: argparse.Namespace) -> int:
    from reforge.backend.registry import create_backend
    from reforge.config.loader import load_config

    config = load_config(Path(args.config))
    checks: list[dict[str, object]] = []

    def add(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    add("source_root", Path(config.project_profile.source_root).is_dir(), config.project_profile.source_root)
    for role, model in (
        ("reverser", config.agents.reverser or config.llm),
        ("checker", config.agents.checker or config.llm),
    ):
        if model.provider in {"claude-cli", "codex"}:
            executable = model.cli_path or ("claude" if model.provider == "claude-cli" else "codex")
            add(role + " executable", shutil.which(executable) is not None, executable)
        elif model.provider in {"cliproxy", "cli-proxy"}:
            from reforge.llm.registry import _resolve_cliproxy_api_key

            key = _resolve_cliproxy_api_key(model.api_key)
            has_key = bool(key and key != "sk-local-cliproxy")
            detail = f"Key detected: {key[:3]}***" if has_key else "Default key fallback"
            add(role + " cliproxy key", has_key, detail)
    validation = config.validation
    commands = validation.build_commands + validation.test_commands + validation.runtime_commands
    if validation.enabled and any(isinstance(command, str) for command in commands):
        if os.name == "nt":
            comspec = os.environ.get("COMSPEC", "cmd.exe")
            shell_ok = shutil.which(comspec) is not None or shutil.which("cmd.exe") is not None
            detail = "cmd.exe available for Windows validation shell commands"
        else:
            sh_bin = os.environ.get("SHELL", "/bin/sh")
            shell_ok = shutil.which(sh_bin) is not None or shutil.which("/bin/sh") is not None
            detail = "POSIX shell available for validation shell commands"
        add(
            "validation shell",
            shell_ok,
            detail,
        )
    has_gates = bool(
        validation.build_commands
        or validation.test_commands
        or validation.runtime_commands
        or validation.differential_cases_file
    )
    add(
        "acceptance policy",
        not validation.enabled
        or not validation.require_verified
        or (has_gates and validation.trust_configured_commands),
        "Verified acceptance requires configured, explicitly trusted validation gates",
    )
    for required, gate_commands, name in [
        (validation.require_build, validation.build_commands, "build"),
        (validation.require_tests, validation.test_commands, "tests"),
        (validation.require_runtime, validation.runtime_commands, "runtime"),
    ]:
        add(name + " gate", not validation.enabled or not required or bool(gate_commands))
    try:
        backend = create_backend(config.backend)
        add("decompile capability", backend.capabilities.has_decompile)
        address = getattr(args, "address", None)
        if address:
            result = backend.decompile(address)
            add("target evidence", bool(result.decompiled.strip()), result.name)
    except (OSError, ValueError, RuntimeError) as exc:
        add("backend", False, str(exc))
    print(json.dumps({"checks": checks, "ready": all(c["passed"] for c in checks)}, indent=2))
    return 0 if all(c["passed"] for c in checks) else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    """Print independent analysis, packaging, and runtime capabilities."""
    if getattr(args, "config", None) is not None:
        return _cmd_doctor_config(args)

    entries = collect_toolchain_status()
    capabilities = _capability_status(entries)
    ready = bool(capabilities["analysis"]["ready"])
    android_repack_ready = bool(capabilities["android_repack"]["ready"])
    android_structural_repack_ready = bool(capabilities["android_structural_repack"]["ready"])
    gadget_ready = bool(capabilities["gadget_non_root"]["ready"])
    adb_ready = any(entry["name"] == "ADB" and entry["ok"] for entry in entries)
    if bool(getattr(args, "json", False)):
        print(
            json.dumps(
                {
                    "ready": ready,
                    "capabilities": capabilities,
                    "full_android_toolchain_ready": (
                        android_repack_ready and android_structural_repack_ready and gadget_ready and adb_ready
                    ),
                    "managed_tools_root": str(managed_tools_root()),
                    "tools": entries,
                },
                indent=2,
            )
        )
        return 0 if ready else 2

    print("reforge toolchain doctor")
    print(f"Managed tools: {managed_tools_root()}")
    for entry in entries:
        required_for = entry.get("required_for", ())
        state = "OK" if entry["ok"] else ("MISSING" if required_for else "OPTIONAL")
        requirement = ", ".join(required_for) if required_for else "optional"
        suffix = f" - {entry['path']}" if entry["path"] else ""
        if entry["version"]:
            suffix += f" ({entry['version']})"
        if entry["detail"]:
            suffix += f"; {entry['detail']}"
        print(f"[{state:8}] {entry['name']} [{requirement}]{suffix}")
    print()
    print("Capabilities:")
    for capability in capabilities.values():
        state = "READY" if capability["ready"] else "UNAVAILABLE"
        missing = f"; missing: {', '.join(capability['missing'])}" if capability["missing"] else ""
        print(f"[{state:11}] {capability['label']}{missing}")
    if not ready:
        print("[!] Core analysis requirements are missing.")
        return 2
    print("[+] Core analysis is ready. Optional workflow gaps do not block analysis.")
    return 0
