"""Fail-closed Android Frida Gadget embedding for decoded APK projects.

This module never downloads Gadget. The caller must explicitly supply trusted
local ELF shared objects, and the resulting APK still has to be rebuilt and
signed by the pipeline's existing trusted-tool boundary.
"""

# ruff: noqa: E501 -- embedded smali method descriptors are indivisible lines.

from __future__ import annotations

import hashlib
import json
import lzma
import os
import re
import struct
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO
from xml.etree import ElementTree

from re_agent.utils.archives import inspect_archive, read_member_bounded
from re_agent.utils.toolchain import resolve_adb

ANDROID_NS = "http://schemas.android.com/apk/res/android"
GADGET_LIBRARY_NAME = "libreagent-gadget.so"
GADGET_CONFIG_NAME = "libreagent-gadget.config.so"
GADGET_LOADER_CLASS = "re.agent.GadgetInitProvider"
GADGET_LOADER_DESCRIPTOR = b"Lre/agent/GadgetInitProvider;"
_MAX_GADGET_BYTES = 256 * 1024 * 1024
_MAX_DIRECTORY_ENTRIES = 512
_MAX_DIRECTORY_DEPTH = 4
_SUPPORTED_ABIS = frozenset({"arm64-v8a", "armeabi-v7a", "x86", "x86_64"})
_ELF_MACHINE_TO_ABI = {
    3: "x86",
    40: "armeabi-v7a",
    62: "x86_64",
    183: "arm64-v8a",
}


class GadgetPackagingError(RuntimeError):
    """Raised when Gadget cannot be embedded without guessing."""


@dataclass(frozen=True)
class EmbeddedGadget:
    """One ABI-specific Gadget artifact copied into the decoded APK."""

    abi: str
    source_name: str
    source_sha256: str
    embedded_sha256: str
    embedded_size: int


@dataclass(frozen=True)
class GadgetEmbedding:
    """Evidence required to verify Gadget survived rebuilding and signing."""

    package_name: str
    provider_authority: str
    on_load: str
    port: int
    declared_version: str | None
    extract_native_libs_changed: bool
    artifacts: tuple[EmbeddedGadget, ...]
    expected_member_hashes: tuple[tuple[str, str], ...]

    @property
    def abis(self) -> tuple[str, ...]:
        return tuple(artifact.abi for artifact in self.artifacts)


def inspect_frida_gadget_sources(gadget_path: Path) -> tuple[str, ...]:
    """Validate local Gadget inputs and return their Android ABI coverage."""
    artifacts = _resolve_gadget_sources(
        gadget_path.expanduser().resolve(),
        expected_sha256=None,
    )
    return tuple(sorted(artifacts))


def embed_frida_gadget(
    decoded_apk: Path,
    gadget_path: Path,
    *,
    expected_sha256: str | None = None,
    on_load: str = "resume",
    port: int = 27042,
    declared_version: str | None = None,
) -> GadgetEmbedding:
    """Embed trusted local Gadget ELF files and a startup ContentProvider."""
    decoded = decoded_apk.resolve()
    if not decoded.is_dir():
        raise GadgetPackagingError(f"decoded APK directory does not exist: {decoded}")
    if on_load not in {"resume", "wait"}:
        raise GadgetPackagingError("Gadget on-load mode must be 'resume' or 'wait'")
    if not 1 <= port <= 65535:
        raise GadgetPackagingError("Gadget port must be between 1 and 65535")

    source = gadget_path.expanduser().resolve()
    artifacts = _resolve_gadget_sources(source, expected_sha256=expected_sha256)
    apk_abis = _decoded_apk_abis(decoded)
    if apk_abis:
        missing = apk_abis - artifacts.keys()
        if missing:
            raise GadgetPackagingError("Gadget input does not cover every APK ABI: " + ", ".join(sorted(missing)))
        selected_abis = sorted(apk_abis)
    else:
        selected_abis = sorted(artifacts)
    if not selected_abis:
        raise GadgetPackagingError("no supported Gadget ELF artifacts were supplied")

    package_name, provider_authority, extract_changed = _patch_manifest(decoded)
    _write_loader_smali(decoded)

    config_bytes = (
        json.dumps(
            {
                "interaction": {
                    "type": "listen",
                    "address": "127.0.0.1",
                    "port": port,
                    "on_port_conflict": "fail",
                    "on_load": on_load,
                }
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    embedded: list[EmbeddedGadget] = []
    expected_members: list[tuple[str, str]] = []
    for abi in selected_abis:
        artifact = artifacts[abi]
        lib_dir = decoded / "lib" / abi
        lib_dir.mkdir(parents=True, exist_ok=True)
        library_target = lib_dir / GADGET_LIBRARY_NAME
        _copy_gadget_payload(artifact.path, library_target)
        embedded_hash = _sha256_file(library_target)
        embedded_size = library_target.stat().st_size
        if embedded_size <= 0 or embedded_size > _MAX_GADGET_BYTES:
            raise GadgetPackagingError(f"embedded Gadget size is invalid for {abi}: {embedded_size}")
        embedded_abi = _elf_abi(library_target)
        if embedded_abi != abi:
            raise GadgetPackagingError(f"embedded Gadget ABI mismatch: expected {abi}, found {embedded_abi}")
        config_target = lib_dir / GADGET_CONFIG_NAME
        config_target.write_bytes(config_bytes)
        config_hash = hashlib.sha256(config_bytes).hexdigest()
        embedded.append(
            EmbeddedGadget(
                abi=abi,
                source_name=artifact.path.name,
                source_sha256=artifact.source_sha256,
                embedded_sha256=embedded_hash,
                embedded_size=embedded_size,
            )
        )
        expected_members.extend(
            [
                (f"lib/{abi}/{GADGET_LIBRARY_NAME}", embedded_hash),
                (f"lib/{abi}/{GADGET_CONFIG_NAME}", config_hash),
            ]
        )

    provisional = GadgetEmbedding(
        package_name=package_name,
        provider_authority=provider_authority,
        on_load=on_load,
        port=port,
        declared_version=declared_version,
        extract_native_libs_changed=extract_changed,
        artifacts=tuple(embedded),
        expected_member_hashes=tuple(expected_members),
    )
    evidence_path = decoded / "assets" / "re-agent" / "frida-gadget-manifest.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_bytes = (json.dumps(asdict(provisional), indent=2, sort_keys=True) + "\n").encode("utf-8")
    evidence_path.write_bytes(evidence_bytes)
    expected_members.append(
        (
            "assets/re-agent/frida-gadget-manifest.json",
            hashlib.sha256(evidence_bytes).hexdigest(),
        )
    )
    return GadgetEmbedding(
        package_name=provisional.package_name,
        provider_authority=provisional.provider_authority,
        on_load=provisional.on_load,
        port=provisional.port,
        declared_version=provisional.declared_version,
        extract_native_libs_changed=provisional.extract_native_libs_changed,
        artifacts=provisional.artifacts,
        expected_member_hashes=tuple(expected_members),
    )


def verify_gadget_archive(apk_path: Path, embedding: GadgetEmbedding) -> None:
    """Verify every injected payload and loader class in a rebuilt APK."""
    with zipfile.ZipFile(apk_path, "r") as archive:
        infos = inspect_archive(archive)
        by_name = {info.filename.replace("\\", "/"): info for info in infos}
        for member, expected_hash in embedding.expected_member_hashes:
            info = by_name.get(member)
            if info is None:
                raise GadgetPackagingError(f"signed APK is missing Gadget member: {member}")
            data = read_member_bounded(
                archive,
                info,
                max_bytes=_MAX_GADGET_BYTES,
            )
            actual_hash = hashlib.sha256(data).hexdigest()
            if actual_hash != expected_hash:
                raise GadgetPackagingError(f"signed APK Gadget member changed unexpectedly: {member}")

        dex_infos = [info for info in infos if re.fullmatch(r"classes(?:\d+)?\.dex", info.filename.replace("\\", "/"))]
        if not dex_infos:
            raise GadgetPackagingError("signed APK has no DEX containing the Gadget loader")
        loader_found = False
        for info in dex_infos:
            dex = read_member_bounded(archive, info, max_bytes=_MAX_GADGET_BYTES)
            if GADGET_LOADER_DESCRIPTOR in dex:
                loader_found = True
                break
        if not loader_found:
            raise GadgetPackagingError("signed APK is missing the Gadget startup loader class")


def write_gadget_deployment_notes(output_dir: Path, embedding: GadgetEmbedding) -> Path:
    """Write accurate non-root deployment and integrity caveats."""
    notes = output_dir / "FRIDA_GADGET_NOTES.txt"
    version_line = embedding.declared_version or "not declared; verify it matches the host Frida tools"
    adb_path = resolve_adb()
    adb_command = f'"{adb_path}"' if adb_path is not None else "adb"
    notes.write_text(
        "Frida Gadget was embedded explicitly into this rebuilt Android APK.\n\n"
        f"Package: {embedding.package_name}\n"
        f"ABIs: {', '.join(embedding.abis)}\n"
        f"Declared Gadget version: {version_line}\n"
        f"Interaction: listen on 127.0.0.1:{embedding.port}, on_load={embedding.on_load}\n\n"
        "The APK has a new signing certificate. The original installed app normally must be\n"
        "uninstalled first. Signature pinning, anti-tamper checks, or Play Integrity may reject\n"
        "the rebuilt package; re-agent cannot bypass or claim compatibility with those controls.\n\n"
        "Typical local connection:\n"
        f"  {adb_command} forward tcp:{embedding.port} tcp:{embedding.port}\n"
        f"  frida -H 127.0.0.1:{embedding.port} -n Gadget -l Hook_Frida.js\n\n"
        "If on_load=wait, the app intentionally pauses until a controller connects.\n",
        encoding="utf-8",
    )
    return notes


@dataclass(frozen=True)
class _GadgetSource:
    path: Path
    source_sha256: str


def _resolve_gadget_sources(
    source: Path,
    *,
    expected_sha256: str | None,
) -> dict[str, _GadgetSource]:
    if source.is_file():
        candidates = [source]
    elif source.is_dir():
        if expected_sha256:
            raise GadgetPackagingError("--frida-gadget-sha256 is valid only for a single input file")
        candidates = _bounded_gadget_files(source)
    else:
        raise GadgetPackagingError(f"Frida Gadget path does not exist: {source}")
    if not candidates:
        raise GadgetPackagingError("no Gadget .so or .so.xz files were found")

    normalized_expected = _normalize_sha256(expected_sha256) if expected_sha256 else None
    resolved: dict[str, _GadgetSource] = {}
    for candidate in candidates:
        if candidate.is_symlink():
            raise GadgetPackagingError(f"Gadget symlinks are not accepted: {candidate}")
        source_hash = _sha256_file(candidate)
        if normalized_expected and source_hash != normalized_expected:
            raise GadgetPackagingError(
                f"Frida Gadget SHA-256 mismatch for {candidate.name}: expected {normalized_expected}, got {source_hash}"
            )
        abi = _elf_abi(candidate)
        if abi in resolved:
            raise GadgetPackagingError(f"multiple Gadget files resolve to ABI {abi}")
        resolved[abi] = _GadgetSource(path=candidate, source_sha256=source_hash)
    return resolved


def _bounded_gadget_files(root: Path) -> list[Path]:
    root_depth = len(root.parts)
    seen = 0
    candidates: list[Path] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        depth = len(current_path.parts) - root_depth
        if depth >= _MAX_DIRECTORY_DEPTH:
            directories[:] = []
        directories[:] = sorted(name for name in directories if not (current_path / name).is_symlink())
        for name in sorted(files):
            seen += 1
            if seen > _MAX_DIRECTORY_ENTRIES:
                raise GadgetPackagingError("Gadget directory contains too many files")
            lowered = name.casefold()
            if "gadget" not in lowered or not lowered.endswith((".so", ".so.xz")):
                continue
            candidate = current_path / name
            if candidate.is_file():
                candidates.append(candidate)
    if len(candidates) > len(_SUPPORTED_ABIS):
        raise GadgetPackagingError("Gadget directory contains more than one candidate per supported ABI")
    return candidates


def _decoded_apk_abis(decoded: Path) -> set[str]:
    lib_root = decoded / "lib"
    if not lib_root.exists():
        return set()
    abis = {child.name for child in lib_root.iterdir() if child.is_dir()}
    unsupported = abis - _SUPPORTED_ABIS
    if unsupported:
        raise GadgetPackagingError("APK contains unsupported native ABI directories: " + ", ".join(sorted(unsupported)))
    return abis


def _patch_manifest(decoded: Path) -> tuple[str, str, bool]:
    manifest = decoded / "AndroidManifest.xml"
    if not manifest.is_file():
        raise GadgetPackagingError("apktool output is missing AndroidManifest.xml")
    try:
        tree = ElementTree.parse(manifest)
    except ElementTree.ParseError as exc:
        raise GadgetPackagingError(f"decoded AndroidManifest.xml is invalid: {exc}") from exc
    root = tree.getroot()
    if root.tag != "manifest":
        raise GadgetPackagingError("decoded manifest root is not <manifest>")
    android_config_for_split = f"{{{ANDROID_NS}}}configForSplit"
    android_split_required = f"{{{ANDROID_NS}}}isSplitRequired"
    if (
        root.get("split")
        or root.get("configForSplit")
        or root.get(android_config_for_split)
        or root.get(android_split_required) == "true"
    ):
        raise GadgetPackagingError("split APK Gadget injection is not supported")
    package_name = (root.get("package") or "").strip()
    if not package_name:
        raise GadgetPackagingError("decoded manifest has no package name")
    application = root.find("application")
    if application is None:
        raise GadgetPackagingError("decoded manifest has no <application> element")
    if application.get(android_split_required) == "true":
        raise GadgetPackagingError("split-required APK Gadget injection is not supported")

    android_name = f"{{{ANDROID_NS}}}name"
    android_authorities = f"{{{ANDROID_NS}}}authorities"
    for provider in application.findall("provider"):
        if provider.get(android_name) == GADGET_LOADER_CLASS:
            raise GadgetPackagingError("APK already contains the re-agent Gadget loader")
    provider_authority = f"{package_name}.reagent.gadget"
    if any(provider.get(android_authorities) == provider_authority for provider in application.findall("provider")):
        raise GadgetPackagingError(f"provider authority already exists: {provider_authority}")

    provider = ElementTree.SubElement(application, "provider")
    provider.set(android_name, GADGET_LOADER_CLASS)
    provider.set(android_authorities, provider_authority)
    provider.set(f"{{{ANDROID_NS}}}exported", "false")
    provider.set(f"{{{ANDROID_NS}}}initOrder", "2147483647")

    extract_key = f"{{{ANDROID_NS}}}extractNativeLibs"
    extract_changed = application.get(extract_key) != "true"
    application.set(extract_key, "true")
    if application.get(f"{{{ANDROID_NS}}}hasCode") == "false":
        application.set(f"{{{ANDROID_NS}}}hasCode", "true")

    ElementTree.register_namespace("android", ANDROID_NS)
    tree.write(manifest, encoding="utf-8", xml_declaration=True)
    return package_name, provider_authority, extract_changed


def _write_loader_smali(decoded: Path) -> None:
    target = decoded / "smali" / "re" / "agent" / "GadgetInitProvider.smali"
    if target.exists():
        raise GadgetPackagingError(f"Gadget loader path already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_LOADER_SMALI, encoding="utf-8", newline="\n")


def _copy_gadget_payload(source: Path, destination: Path) -> None:
    if source.stat().st_size <= 0 or source.stat().st_size > _MAX_GADGET_BYTES:
        raise GadgetPackagingError(f"Gadget input size is invalid: {source}")
    opener = lzma.open if source.name.casefold().endswith(".xz") else open
    total = 0
    with opener(source, "rb") as src, destination.open("wb") as dst:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_GADGET_BYTES:
                raise GadgetPackagingError("decompressed Gadget exceeds the size limit")
            dst.write(chunk)
    if total == 0:
        raise GadgetPackagingError("Gadget payload is empty")


def _elf_abi(path: Path) -> str:
    with _open_payload(path) as stream:
        header = stream.read(64)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise GadgetPackagingError(f"Gadget input is not an ELF shared object: {path.name}")
    data_encoding = header[5]
    if data_encoding == 1:
        endian = "<"
    elif data_encoding == 2:
        endian = ">"
    else:
        raise GadgetPackagingError(f"Gadget ELF has an unsupported byte order: {path.name}")
    elf_type = struct.unpack_from(f"{endian}H", header, 16)[0]
    machine = struct.unpack_from(f"{endian}H", header, 18)[0]
    if elf_type != 3:
        raise GadgetPackagingError(f"Gadget ELF is not a shared object (ET_DYN): {path.name}")
    abi = _ELF_MACHINE_TO_ABI.get(machine)
    if abi is None:
        raise GadgetPackagingError(f"Gadget ELF machine {machine} is not a supported Android ABI")
    return abi


def _open_payload(path: Path) -> BinaryIO | lzma.LZMAFile:
    if path.name.casefold().endswith(".xz"):
        return lzma.open(path, "rb")
    return path.open("rb")


def _normalize_sha256(value: str) -> str:
    normalized = value.strip().casefold()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise GadgetPackagingError("expected Gadget SHA-256 must contain exactly 64 hexadecimal characters")
    return normalized


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_GADGET_BYTES:
                raise GadgetPackagingError(f"Gadget file exceeds the size limit: {path}")
            digest.update(chunk)
    return digest.hexdigest()


_LOADER_SMALI = r""".class public Lre/agent/GadgetInitProvider;
.super Landroid/content/ContentProvider;
.source "GadgetInitProvider.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/content/ContentProvider;-><init>()V
    return-void
.end method

.method public onCreate()Z
    .locals 3
    :try_start_0
    const-string v0, "reagent-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    move-exception v0
    const-string v1, "re-agent"
    const-string v2, "Frida Gadget load failed"
    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    const/4 v0, 0x0
    return v0
.end method

.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public getType(Landroid/net/Uri;)Ljava/lang/String;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
"""
