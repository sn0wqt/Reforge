"""Safe discovery and deployment artifacts for Android split-APK sets."""

from __future__ import annotations

import os
import re
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path

from re_agent.core.app_identity import detect_application_identifier
from re_agent.utils.archives import (
    ArchiveSafetyError,
    extract_member_bounded,
    inspect_archive,
)

MAX_SPLIT_APKS = 256
_PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+\Z")


class SplitApkError(ValueError):
    """Raised when a split package cannot be handled without guessing."""


@dataclass(frozen=True)
class AndroidPackageSet:
    """One Android base APK and the splits that must be installed with it."""

    source: Path
    base_apk: Path
    split_apks: tuple[Path, ...]
    source_kind: str

    @property
    def all_apks(self) -> tuple[Path, ...]:
        return (self.base_apk, *self.split_apks)


def _iter_directory_apks(root: Path) -> tuple[Path, ...]:
    pending = [root]
    discovered: list[Path] = []
    visited = 0
    while pending:
        current = pending.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda entry: entry.name.casefold())
        except OSError as exc:
            raise SplitApkError(f"Cannot inspect split-APK directory {current}: {exc}") from exc
        for entry in entries:
            visited += 1
            if visited > 100_000:
                raise SplitApkError("Split-APK directory contains too many entries.")
            try:
                path = Path(entry.path)
                junction_check = getattr(path, "is_junction", None)
                if entry.is_symlink() or (callable(junction_check) and junction_check()):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False) and path.suffix.casefold() == ".apk":
                    discovered.append(path.resolve())
                    if len(discovered) > MAX_SPLIT_APKS:
                        raise SplitApkError(
                            f"Split package exceeds the {MAX_SPLIT_APKS}-APK safety limit."
                        )
            except OSError:
                continue
    return tuple(sorted(discovered, key=lambda path: path.as_posix().casefold()))


def _extract_archive_apks(source: Path, destination: Path) -> tuple[Path, ...]:
    try:
        with zipfile.ZipFile(source, "r") as archive:
            infos = inspect_archive(archive)
            apk_infos = [
                info
                for info in infos
                if not info.is_dir() and info.filename.casefold().endswith(".apk")
            ]
            if not apk_infos:
                return ()
            if len(apk_infos) > MAX_SPLIT_APKS:
                raise SplitApkError(
                    f"Split archive exceeds the {MAX_SPLIT_APKS}-APK safety limit."
                )
            destination.mkdir(parents=True, exist_ok=True)
            extracted: list[Path] = []
            for index, info in enumerate(apk_infos, start=1):
                # The numeric prefix makes duplicate basenames harmless while retaining
                # a recognizable name for diagnostics and final deployment artifacts.
                target = destination / f"{index:03d}-{Path(info.filename).name}"
                extract_member_bounded(
                    archive,
                    info.filename,
                    target,
                    destination_root=destination,
                )
                extracted.append(target)
            return tuple(extracted)
    except (ArchiveSafetyError, OSError, zipfile.BadZipFile) as exc:
        raise SplitApkError(f"Cannot safely extract split-APK archive: {exc}") from exc


def _apk_inventory(path: Path) -> tuple[set[str], bool]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = inspect_archive(archive)
            names = {info.filename.replace("\\", "/").casefold() for info in infos}
    except (ArchiveSafetyError, OSError, zipfile.BadZipFile) as exc:
        raise SplitApkError(f"Invalid APK member {path.name}: {exc}") from exc
    if "androidmanifest.xml" not in names:
        raise SplitApkError(f"Nested file is not an Android APK: {path.name}")
    has_executable_dex = any(
        re.fullmatch(r"classes(?:\d+)?\.dex", name.rsplit("/", 1)[-1])
        for name in names
    )
    return names, has_executable_dex


def _base_score(path: Path, names: set[str], has_dex: bool) -> int:
    basename = re.sub(r"^\d{3}-", "", path.name.casefold())
    stem = Path(basename).stem
    score = 0
    if basename == "base.apk":
        score += 1_000
    if stem in {"base-master", "base_master", "master"}:
        score += 800
    if has_dex:
        score += 100
    if "resources.arsc" in names:
        score += 20
    if any(name.startswith("assets/") for name in names):
        score += 10
    if stem.startswith(("split_config", "config.")) or ".config." in stem:
        score -= 500
    return score


def resolve_android_package_set(
    source: Path,
    extraction_root: Path,
) -> AndroidPackageSet | None:
    """Resolve a directory or outer ZIP/XAPK/APKS archive into a package set.

    A normal APK returns ``None`` so existing single-APK behavior remains
    untouched. Selection fails closed when two possible base APKs are equally
    plausible or package identifiers disagree.
    """

    source = source.expanduser().resolve()
    if source.is_file() and source.suffix.casefold() == ".apk":
        return None
    if source.is_dir():
        apks = _iter_directory_apks(source)
        source_kind = "directory"
    elif source.is_file() and zipfile.is_zipfile(source):
        apks = _extract_archive_apks(source, extraction_root)
        source_kind = "archive"
    else:
        return None
    if not apks:
        return None

    inventories: dict[Path, tuple[set[str], bool]] = {
        apk: _apk_inventory(apk) for apk in apks
    }
    ranked = sorted(
        (
            (_base_score(apk, names, has_dex), apk)
            for apk, (names, has_dex) in inventories.items()
        ),
        key=lambda item: (item[0], item[1].name.casefold()),
        reverse=True,
    )
    if len(ranked) > 1 and ranked[0][0] == ranked[1][0]:
        raise SplitApkError(
            "Split archive has multiple equally plausible base APKs: "
            f"{ranked[0][1].name}, {ranked[1][1].name}."
        )
    base = ranked[0][1]
    splits = tuple(apk for apk in apks if apk != base)

    base_identifier = detect_application_identifier(base)
    if not base_identifier:
        raise SplitApkError("Could not recover the Android package identifier from the base APK.")
    mismatches = [
        (split.name, detect_application_identifier(split))
        for split in splits
        if detect_application_identifier(split) != base_identifier
    ]
    if mismatches:
        detail = ", ".join(f"{name}={identifier or 'unknown'}" for name, identifier in mismatches[:5])
        raise SplitApkError(
            f"Split APK package identifiers do not match {base_identifier}: {detail}"
        )

    executable_splits = [split.name for split in splits if inventories[split][1]]
    if executable_splits:
        names = ", ".join(executable_splits[:5])
        raise SplitApkError(
            "Dynamic-feature APKs containing executable DEX require cross-split analysis, "
            f"which is not yet safe to approximate: {names}"
        )
    return AndroidPackageSet(source, base, splits, source_kind)


def validate_installer_package(value: str | None) -> str | None:
    """Validate an optional installer package used only in deployment notes."""

    if value is None:
        return None
    normalized = value.strip()
    if not normalized or not _PACKAGE_NAME.fullmatch(normalized):
        raise SplitApkError(f"Invalid Android installer package name: {value!r}")
    return normalized


def write_split_deployment_artifacts(
    output_dir: Path,
    signed_apks: tuple[Path, ...],
    *,
    base_apk: Path,
    installer_package: str | None,
) -> tuple[Path, Path]:
    """Write truthful ADB/Shizuku instructions and a portable ZIP container."""

    if base_apk not in signed_apks:
        raise SplitApkError("Signed split output does not identify its base APK.")
    install_dir = base_apk.parent
    ordered = (base_apk, *(path for path in signed_apks if path != base_apk))
    quoted_names = " ".join(f'"{path.name}"' for path in ordered)
    installer_arg = f' -i "{installer_package}"' if installer_package else ""
    adb_command = f"adb install-multiple -r{installer_arg} {quoted_names}"

    notes = install_dir / "INSTALL_SPLIT_APKS.txt"
    notes.write_text(
        "\n".join(
            [
                "re-agent Android split-APK deployment",
                "=====================================",
                "",
                f"APK count: {len(ordered)}",
                f"Installer metadata override: {installer_package or '(none)'}",
                "",
                "ADB (run from this directory):",
                adb_command,
                "",
                "Shizuku / InstallWithOptions:",
                "1. Start Shizuku using Android Wireless Debugging.",
                "2. Grant InstallWithOptions permission in Shizuku.",
                "3. Choose its split/multiple-APK install mode.",
                "4. Select every APK in this directory in one install session.",
                *(
                    [f"5. Set installer package metadata to {installer_package} if authorized."]
                    if installer_package
                    else []
                ),
                "",
                "All APKs in this set were re-signed together. They cannot update an",
                "installed copy signed by a different certificate; uninstall that copy first.",
                "Setting installer metadata does not reproduce store licensing, originating",
                "package state, purchase state, or integrity verdicts. Android 14+ retains",
                "additional shell/origin information even when an installer name is supplied.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    archive_path = output_dir / "modded_split_apks.zip"
    temporary = archive_path.with_suffix(".zip.tmp")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for apk in ordered:
            archive.write(apk, apk.name)
        archive.write(notes, notes.name)
    os.replace(temporary, archive_path)
    return notes, archive_path


def copy_unique_apks(apks: tuple[Path, ...], destination: Path) -> tuple[Path, ...]:
    """Copy APKs with deterministic unique names suitable for batch signing."""

    destination.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    used: set[str] = set()
    for index, apk in enumerate(apks):
        original = re.sub(r"^\d{3}-", "", apk.name)
        name = original if original.casefold() not in used else f"split-{index:03d}-{original}"
        used.add(name.casefold())
        target = destination / name
        shutil.copy2(apk, target)
        copied.append(target)
    return tuple(copied)
