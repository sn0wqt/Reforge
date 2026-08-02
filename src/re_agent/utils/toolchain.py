"""Resolve optional external tools from PATH, environment, or managed installs."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path


def managed_tools_root() -> Path:
    """Return the per-user directory used by the Android setup script."""
    configured = os.environ.get("RE_AGENT_TOOLS_DIR")
    if configured:
        return Path(configured).expanduser()
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "auto-re-agent" / "tools"
    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        return Path(xdg_data).expanduser() / "auto-re-agent" / "tools"
    return Path.home() / ".local" / "share" / "auto-re-agent" / "tools"


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
    values = [explicit, os.environ.get("RE_AGENT_APK_SIGNER_JAR")]
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


def resolve_frida_gadget_path(
    explicit: str | Path | None = None,
    *,
    version: str | None = None,
) -> Path | None:
    """Resolve a local Gadget file/directory without downloading anything."""
    values = [explicit, os.environ.get("RE_AGENT_FRIDA_GADGET_DIR")]
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
    values = [explicit, os.environ.get("RE_AGENT_IL2CPP_DUMPER")]
    for value in values:
        if not value:
            continue
        candidate = Path(value).expanduser()
        if candidate.is_file():
            return candidate.resolve()

    parent = managed_tools_root() / "il2cpp-dumper"
    for version_dir in _version_directories(parent):
        for name in ("Il2CppDumper.exe", "Il2CppDumper"):
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
    ):
        resolved = shutil.which(name)
        if resolved:
            return Path(resolved).resolve()
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
