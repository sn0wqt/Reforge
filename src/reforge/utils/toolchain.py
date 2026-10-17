"""Resolve optional external tools from PATH, environment, or managed installs."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path


def managed_tools_root() -> Path:
    """Return the per-user directory used by the Android setup script."""
    configured = os.environ.get("REFORGE_TOOLS_DIR") or os.environ.get("RE_AGENT_TOOLS_DIR")
    if configured:
        return Path(configured).expanduser()
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        reforge_dir = Path(local_app_data) / "Reforge" / "tools"
        legacy_dir = Path(local_app_data) / "auto-re-agent" / "tools"
        if legacy_dir.is_dir() and not reforge_dir.is_dir():
            return legacy_dir
        return reforge_dir
    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        reforge_dir = Path(xdg_data).expanduser() / "Reforge" / "tools"
        legacy_dir = Path(xdg_data).expanduser() / "auto-re-agent" / "tools"
        if legacy_dir.is_dir() and not reforge_dir.is_dir():
            return legacy_dir
        return reforge_dir
    import sys

    if sys.platform == "darwin":
        mac_dir = Path.home() / "Library" / "Application Support" / "Reforge" / "tools"
        legacy_mac_dir = Path.home() / "Library" / "Application Support" / "auto-re-agent" / "tools"
        if legacy_mac_dir.is_dir() and not mac_dir.is_dir():
            return legacy_mac_dir
        return mac_dir

    reforge_home = Path.home() / ".local" / "share" / "Reforge" / "tools"
    legacy_home = Path.home() / ".local" / "share" / "auto-re-agent" / "tools"
    if legacy_home.is_dir() and not reforge_home.is_dir():
        return legacy_home
    return reforge_home


def _version_key(path: Path) -> tuple[tuple[int, ...], str]:
    numbers = tuple(int(value) for value in re.findall(r"\d+", path.name))
    return numbers, path.name.casefold()


def _version_directories(parent: Path) -> list[Path]:
    if not parent.is_dir():
        return []
    return sorted(
        (child for child in parent.iterdir() if child.is_dir() and not child.is_symlink()),
        key=_version_key,
        reverse=True,
    )


def resolve_apk_signer(explicit: str | Path | None = None) -> Path | None:
    """Resolve an explicitly trusted or managed uber-apk-signer JAR."""
    values = [
        explicit,
        os.environ.get("REFORGE_APK_SIGNER_JAR"),
        os.environ.get("RE_AGENT_APK_SIGNER_JAR"),
    ]
    for value in values:
        if not value:
            continue
        candidate = Path(value).expanduser()
        if candidate.is_file() and candidate.suffix.casefold() == ".jar":
            return candidate.resolve()

    parent = managed_tools_root() / "uber-apk-signer"
    for version_dir in _version_directories(parent):
        candidates = sorted(version_dir.glob("uber-apk-signer-*.jar"))
        if len(candidates) == 1 and candidates[0].is_file():
            return candidates[0].resolve()
    return None


def resolve_apktool(explicit: str | Path | None = None) -> Path | None:
    """Resolve an executable apktool launcher consistently across commands."""
    values = [
        explicit,
        os.environ.get("REFORGE_APKTOOL"),
        os.environ.get("RE_AGENT_APKTOOL"),
    ]
    for value in values:
        if not value:
            continue
        candidate = Path(value).expanduser()
        if candidate.is_file() and candidate.suffix.casefold() in {
            "",
            ".bat",
            ".cmd",
            ".exe",
        }:
            return candidate.resolve()

    parent = managed_tools_root() / "apktool"
    names = (
        ("apktool.bat", "apktool.cmd", "apktool.exe", "apktool")
        if os.name == "nt"
        else ("apktool", "apktool.jar", "apktool.sh", "apktool.bat")
    )
    for version_dir in _version_directories(parent):
        for name in names:
            candidate = version_dir / name
            if candidate.is_file():
                return candidate.resolve()
    resolved = (
        shutil.which("apktool")
        or (shutil.which("apktool.bat") if os.name == "nt" else None)
        or (shutil.which("apktool.cmd") if os.name == "nt" else None)
        or (shutil.which("apktool.exe") if os.name == "nt" else None)
        or shutil.which("apktool.bat")
    )
    return Path(resolved).resolve() if resolved else None


def resolve_frida_gadget_path(
    explicit: str | Path | None = None,
    *,
    version: str | None = None,
) -> Path | None:
    """Resolve a local Gadget file/directory without downloading anything."""
    values = [
        explicit,
        os.environ.get("REFORGE_FRIDA_GADGET_DIR"),
        os.environ.get("RE_AGENT_FRIDA_GADGET_DIR"),
    ]
    for value in values:
        if not value:
            continue
        candidate = Path(value).expanduser()
        if candidate.is_file() or candidate.is_dir():
            return candidate.resolve()

    parent = managed_tools_root() / "frida-gadget"
    if version:
        candidate = parent / version
        if candidate.is_dir():
            return candidate.resolve()
        return None
    directories = _version_directories(parent)
    return directories[0].resolve() if directories else None


def resolve_il2cpp_dumper(explicit: str | Path | None = None) -> Path | None:
    """Resolve Il2CppDumper from an explicit path, environment, PATH, or managed install."""
    values = [
        explicit,
        os.environ.get("REFORGE_IL2CPP_DUMPER"),
        os.environ.get("RE_AGENT_IL2CPP_DUMPER"),
    ]
    for value in values:
        if not value:
            continue
        candidate = Path(value).expanduser()
        if candidate.is_file():
            return candidate.resolve()

    parent = managed_tools_root() / "il2cpp-dumper"
    dumper_names = (
        ("Il2CppDumper.exe", "Il2CppDumper")
        if os.name == "nt"
        else ("Il2CppDumper", "il2dump", "Il2CppDumper.exe")
    )
    for version_dir in _version_directories(parent):
        for name in dumper_names:
            candidate = version_dir / name
            if candidate.is_file():
                return candidate.resolve()
    for name in (
        "Il2CppDumper",
        "Il2CppDumper.exe",
        "il2cpp-dumper",
        "il2cpp-dumper.exe",
        "il2cpp_dumper",
        "il2cpp_dumper.exe",
        "il2dump",
        "il2dump.exe",
    ):
        resolved = shutil.which(name)
        if resolved:
            return Path(resolved).resolve()

    cargo_candidates = [
        Path.home() / ".cargo" / "bin" / name
        for name in ("il2cpp_dumper", "il2cpp_dumper.exe", "il2cpp-dumper", "Il2CppDumper", "il2dump", "il2dump.exe")
    ]
    for candidate in cargo_candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def resolve_adb() -> Path | None:
    """Resolve Android Debug Bridge."""
    name = "adb.exe" if os.name == "nt" else "adb"
    candidate = managed_tools_root() / "platform-tools" / name
    if candidate.is_file():
        return candidate.resolve()
    resolved = shutil.which("adb") or shutil.which("adb.exe")
    return Path(resolved).resolve() if resolved else None


def resolve_jadx() -> Path | None:
    """Resolve the JADX command-line launcher."""
    parent = managed_tools_root() / "jadx"
    names = ("jadx.bat", "jadx") if os.name == "nt" else ("jadx", "jadx.bat")
    for version_dir in _version_directories(parent):
        for name in names:
            candidate = version_dir / "bin" / name
            if candidate.is_file():
                return candidate.resolve()
    resolved = shutil.which("jadx") or shutil.which("jadx.bat")
    return Path(resolved).resolve() if resolved else None


def resolve_wakaru(explicit: str | Path | None = None) -> Path | None:
    """Resolve Wakaru JS decompiler and unbundler CLI."""
    values = [
        explicit,
        os.environ.get("REFORGE_WAKARU_COMMAND"),
        os.environ.get("REA_WAKARU_COMMAND"),
        os.environ.get("WAKARU_COMMAND"),
    ]
    for value in values:
        if not value:
            continue
        candidate = Path(value).expanduser()
        if candidate.is_file():
            return candidate.resolve()

    parent = managed_tools_root() / "wakaru"
    names = ("wakaru.exe", "wakaru.cmd", "wakaru.bat", "wakaru") if os.name == "nt" else ("wakaru", "wakaru.cmd")
    for version_dir in _version_directories(parent):
        for name in names:
            candidate = version_dir / name
            if candidate.is_file():
                return candidate.resolve()
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return Path(resolved).resolve()
    return None


def resolve_ghidra(explicit: str | Path | None = None) -> Path | None:
    """Resolve Ghidra launcher or headless analysis script across platforms."""
    import sys

    values = [
        explicit,
        os.environ.get("REFORGE_GHIDRA"),
        os.environ.get("GHIDRA_INSTALL_DIR"),
        os.environ.get("GHIDRA_HOME"),
    ]
    for value in values:
        if not value:
            continue
        candidate = Path(value).expanduser()
        if candidate.is_file():
            return candidate.resolve()
        if candidate.is_dir():
            names = (
                ("ghidraRun.bat", "analyzeHeadless.bat", "ghidraRun", "analyzeHeadless")
                if os.name == "nt"
                else ("ghidraRun", "analyzeHeadless", "support/analyzeHeadless")
            )
            for name in names:
                launcher = candidate / name
                if launcher.is_file():
                    return launcher.resolve()

    system_dirs: list[Path] = []
    if sys.platform == "darwin":
        system_dirs.extend(
            [
                Path("/Applications"),
                Path.home() / "Applications",
                Path("/opt/homebrew/bin"),
                Path("/usr/local/bin"),
            ]
        )
    elif os.name != "nt":
        system_dirs.extend(
            [
                Path("/opt"),
                Path("/usr/local"),
                Path("/usr/share"),
            ]
        )
    else:
        for drive in ("C:", "D:"):
            system_dirs.extend(
                [
                    Path(f"{drive}\\Program Files"),
                    Path(f"{drive}\\ghidra"),
                ]
            )

    for sys_dir in system_dirs:
        if not sys_dir.is_dir():
            continue
        try:
            for child in sys_dir.glob("ghidra*"):
                if child.is_dir():
                    ghidra_launchers: tuple[str, ...] = (
                        ("ghidraRun.bat", "analyzeHeadless.bat")
                        if os.name == "nt"
                        else ("ghidraRun", "support/analyzeHeadless", "analyzeHeadless")
                    )
                    for launcher_name in ghidra_launchers:
                        launcher = child / launcher_name
                        if launcher.is_file():
                            return launcher.resolve()
        except OSError:
            pass

    names_to_which: tuple[str, ...] = (
        ("ghidraRun.bat", "analyzeHeadless.bat", "ghidraRun", "analyzeHeadless")
        if os.name == "nt"
        else ("ghidraRun", "analyzeHeadless", "ghidra-bridge")
    )
    for name in names_to_which:
        resolved = shutil.which(name)
        if resolved:
            return Path(resolved).resolve()
    return None
