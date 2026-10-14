"""Platform and engine detection for the eight supported binary pathways."""

from __future__ import annotations

import os
import posixpath
import re
import zipfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from reforge.core.scanners.dotnet_scanner import DotNetScanner
from reforge.core.scanners.electron_scanner import ElectronScanner
from reforge.core.scanners.flutter_scanner import FlutterScanner
from reforge.core.scanners.go_scanner import GoScanner
from reforge.core.scanners.mitigation_scanner import MitigationScanner
from reforge.core.scanners.pe_resource_scanner import PeResourceScanner
from reforge.core.scanners.plist_scanner import PlistScanner
from reforge.core.scanners.rust_scanner import RustScanner
from reforge.core.scanners.wasm_scanner import WasmScanner
from reforge.utils.archives import (
    ArchiveSafetyError,
    inspect_archive,
    read_member_bounded,
)
from reforge.utils.binary_magic import get_magic_bytes, is_mach_o

ANDROID_HERMES_BUNDLES: Final[tuple[str, ...]] = ("index.android.bundle",)
IOS_HERMES_BUNDLES: Final[tuple[str, ...]] = ("main.jsbundle", "index.ios.bundle")
MAX_DIRECTORY_ENTRIES: Final[int] = 100_000
IL2CPP_DUMP_MARKERS: Final[tuple[str, ...]] = (
    "script.json",
    "dump.cs",
    "il2cpp.h",
    "static_metadata.json",
)
PLATFORM_HINTS: Final[dict[str, str]] = {
    "android": "android",
    "android-arm64": "android",
    "ios": "ios",
    "ios-arm64": "ios",
    "linux": "linux",
    "linux-x64": "linux",
    "windows": "windows",
    "windows-x64": "windows",
}
MAX_PLATFORM_EVIDENCE_BYTES: Final[int] = 2 * 1024 * 1024
ANDROID_WEB_INDEX_MEMBERS: Final[tuple[str, ...]] = (
    "assets/public/index.html",
    "assets/www/index.html",
)
_HTML_SCRIPT_SRC = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+\.js(?:\?[^'\"]*)?)['\"]",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ArchitectureDetection:
    """Detailed platform route while retaining a legacy engine identifier."""

    pathway_id: int
    pathway: str
    platform: str
    engine_type: str
    display_name: str
    bundle_member: str | None = None
    package_type: str = "binary"
    detected_components: tuple[str, ...] = ()
    detection_notes: tuple[str, ...] = ()

    @property
    def is_android(self) -> bool:
        return self.platform == "android"

    @property
    def is_ios(self) -> bool:
        return self.platform == "ios"

    @property
    def is_windows(self) -> bool:
        return self.platform == "windows"

    @property
    def uses_frida_javascript(self) -> bool:
        return self.pathway_id in {1, 2, 3, 4, 6, 7, 8}

    @property
    def uses_cpp_hook(self) -> bool:
        return self.pathway_id in {3, 4, 5, 7}


def _detection(
    pathway_id: int,
    pathway: str,
    platform: str,
    engine_type: str,
    display_name: str,
    *,
    bundle_member: str | None = None,
    package_type: str = "binary",
    detected_components: tuple[str, ...] = (),
    detection_notes: tuple[str, ...] = (),
) -> ArchitectureDetection:
    return ArchitectureDetection(
        pathway_id=pathway_id,
        pathway=pathway,
        platform=platform,
        engine_type=engine_type,
        display_name=display_name,
        bundle_member=bundle_member,
        package_type=package_type,
        detected_components=detected_components,
        detection_notes=detection_notes,
    )


def normalize_platform_hint(platform_hint: str | None) -> str | None:
    """Normalize a user-facing platform/profile name to a platform identifier."""
    if platform_hint is None:
        return None
    normalized = platform_hint.strip().casefold()
    if not normalized:
        return None
    try:
        return PLATFORM_HINTS[normalized]
    except KeyError as exc:
        supported = ", ".join(sorted(PLATFORM_HINTS))
        raise ValueError(f"Unsupported platform hint '{platform_hint}'. Expected one of: {supported}.") from exc


def _read_prefix_text(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            return stream.read(MAX_PLATFORM_EVIDENCE_BYTES).decode(
                "utf-8",
                errors="ignore",
            )
    except OSError:
        return ""


def _il2cpp_dump_markers(path: Path) -> tuple[str, ...]:
    """Return root-level Il2CppDumper artifacts without inspecting DummyDll."""
    if not path.is_dir():
        return ()
    return tuple(marker for marker in IL2CPP_DUMP_MARKERS if (path / marker).is_file())


def _infer_il2cpp_dump_platform(path: Path) -> tuple[str, tuple[str, ...]]:
    """Infer a dump's target platform only from platform-specific evidence.

    Il2CppDumper's ``DummyDll`` and generated ``cpp_project`` directories are
    host-side analysis artifacts. Their PE files and Visual Studio scaffolding
    do not establish that the dumped game itself targets Windows.
    """
    root_names = {child.name.casefold() for child in path.iterdir() if child.is_file()}
    if "gameassembly.dll" in root_names:
        return "windows", ("root-level GameAssembly.dll",)
    if "libil2cpp.so" in root_names:
        return "android", ("root-level libil2cpp.so",)
    if "unityframework" in root_names:
        return "ios", ("root-level UnityFramework",)

    dump_prefix = _read_prefix_text(path / "dump.cs")
    weighted_markers = {
        "ios": {
            "Unity.Notifications.iOS.dll": 10,
            "UnityEngine.iOSModule.dll": 6,
            "UnityEngine.Apple.dll": 4,
        },
        "android": {
            "Unity.Notifications.Android.dll": 10,
            "UnityEngine.AndroidModule.dll": 6,
            # This compatibility assembly is sometimes retained in non-Android
            # Unity dumps, so it is supporting evidence only.
            "UnityEngine.AndroidJNIModule.dll": 1,
        },
        "windows": {
            "UnityEngine.WindowsStandaloneModule.dll": 10,
            "UnityEngine.WindowsGamingInputModule.dll": 4,
        },
    }
    platform_evidence = {
        platform: tuple(marker for marker in marker_weights if marker in dump_prefix)
        for platform, marker_weights in weighted_markers.items()
    }
    scores = {
        platform: sum(marker_weights[marker] for marker in platform_evidence[platform])
        for platform, marker_weights in weighted_markers.items()
    }
    ranked_scores = sorted(
        scores.items(),
        key=lambda item: item[1],
        reverse=True,
    )
    best_platform, best_score = ranked_scores[0]
    runner_up_score = ranked_scores[1][1]
    if best_score >= 4 and best_score - runner_up_score >= 3:
        return best_platform, tuple(f"dump.cs image: {marker}" for marker in platform_evidence[best_platform])
    return "unknown", ()


def _il2cpp_detection(
    platform: str,
    *,
    package_type: str,
    detection_notes: tuple[str, ...] = (),
) -> ArchitectureDetection:
    route = {
        "android": (
            3,
            "unity-il2cpp-android",
            "Unity IL2CPP (Android)",
        ),
        "ios": (
            4,
            "unity-il2cpp-ios",
            "Unity IL2CPP (iOS)",
        ),
        "windows": (
            5,
            "unity-il2cpp-windows",
            "Unity IL2CPP (Windows)",
        ),
        "linux": (
            7,
            "unity-il2cpp-linux",
            "Unity IL2CPP (Linux)",
        ),
    }.get(platform)
    if route is None:
        return _detection(
            0,
            "unity-il2cpp-unresolved",
            "unknown",
            "unity-il2cpp",
            "Unity IL2CPP (platform unresolved)",
            package_type=package_type,
            detected_components=("unity-il2cpp",),
            detection_notes=detection_notes,
        )
    pathway_id, pathway, display_name = route
    return _detection(
        pathway_id,
        pathway,
        platform,
        "unity-il2cpp",
        display_name,
        package_type=package_type,
        detected_components=("unity-il2cpp",),
        detection_notes=detection_notes,
    )


def _find_member(names: list[str], basenames: tuple[str, ...]) -> str | None:
    for name in names:
        normalized = name.replace("\\", "/").lower()
        if any(normalized == base or normalized.endswith(f"/{base}") for base in basenames):
            return name
    return None


def _resolve_web_entry_bundle(
    archive: zipfile.ZipFile,
    infos: Sequence[zipfile.ZipInfo],
) -> tuple[str | None, str | None]:
    """Return ``(index_html, entry_javascript)`` for packaged web apps."""
    by_normalized = {info.filename.replace("\\", "/").casefold(): info for info in infos}
    index_info = next(
        (by_normalized[name] for name in ANDROID_WEB_INDEX_MEMBERS if name in by_normalized),
        None,
    )
    if index_info is None:
        return None, None
    try:
        html = read_member_bounded(
            archive,
            index_info,
            max_bytes=MAX_PLATFORM_EVIDENCE_BYTES,
        ).decode("utf-8", errors="ignore")
    except (ArchiveSafetyError, OSError, UnicodeError, ValueError):
        return index_info.filename, None
    index_normalized = index_info.filename.replace("\\", "/")
    index_dir = posixpath.dirname(index_normalized)
    for match in _HTML_SCRIPT_SRC.finditer(html):
        source = match.group(1).split("?", 1)[0]
        if source.startswith(("http://", "https://", "//")):
            continue
        resolved = posixpath.normpath(posixpath.join(index_dir, source.lstrip("/")))
        info = by_normalized.get(resolved.casefold())
        if info is not None:
            return index_info.filename, info.filename
    return index_info.filename, None


def iter_directory_files_bounded(
    root: Path,
    *,
    max_entries: int = MAX_DIRECTORY_ENTRIES,
) -> Iterator[Path]:
    """Yield contained regular files without following links or walking forever."""
    pending = [root]
    seen_entries = 0
    while pending and seen_entries < max_entries:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                ordered = sorted(entries, key=lambda entry: entry.name.casefold())
        except OSError:
            continue
        for entry in ordered:
            seen_entries += 1
            if seen_entries > max_entries:
                return
            try:
                entry_path = Path(entry.path)
                junction_check = getattr(entry_path, "is_junction", None)
                if entry.is_symlink() or (callable(junction_check) and bool(junction_check())):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(entry_path)
                elif entry.is_file(follow_symlinks=False):
                    yield entry_path
            except OSError:
                continue


def resolve_hermes_bundle_member(target_path: str | Path) -> str | None:
    """Resolve the platform-specific Hermes bundle member in a package or directory."""
    return detect_architecture_from_path(target_path).bundle_member


def _detect_archive(path: Path) -> ArchitectureDetection:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = inspect_archive(archive)
            names = [info.filename for info in infos]
            web_index_member, web_bundle_member = _resolve_web_entry_bundle(
                archive,
                infos,
            )
    except (ArchiveSafetyError, OSError, zipfile.BadZipFile):
        return _detection(7, "native-cpp-unreal-flutter", "unknown", "native-cpp", "Native C/C++")

    normalized = [name.replace("\\", "/").lower() for name in names]
    is_ios = path.suffix.lower() == ".ipa" or any(name.startswith("payload/") for name in normalized)
    is_android = path.suffix.lower() == ".apk" or any(name.endswith("androidmanifest.xml") for name in normalized)
    has_game_assembly = any(name.endswith("gameassembly.dll") for name in normalized)
    if has_game_assembly and not is_ios and not is_android:
        return _detection(
            5,
            "unity-il2cpp-windows",
            "windows",
            "unity-il2cpp",
            "Unity IL2CPP (Windows)",
            package_type="zip",
        )
    platform = "ios" if is_ios else "android" if is_android else "unknown"
    package_type = "ipa" if is_ios else "apk" if is_android else "zip"
    components: list[str] = []
    if _find_member(names, IOS_HERMES_BUNDLES if is_ios else ANDROID_HERMES_BUNDLES):
        components.append("react-native-hermes")
    if any(
        "libil2cpp.so" in name
        or "global-metadata.dat" in name
        or "unityframework" in name
        or name.endswith("gameassembly.dll")
        for name in normalized
    ):
        components.append("unity-il2cpp")
    if any(name.endswith(".dex") for name in normalized):
        components.append("android-dex")
    if web_index_member is not None and web_bundle_member is not None:
        components.append("webview-javascript")
    if any("libapp.so" in name for name in normalized):
        components.append("flutter")
    if any("libunreal.so" in name or "libue4.so" in name for name in normalized):
        components.append("unreal-engine")
    if any(name.endswith((".so", ".dll", ".dylib")) for name in normalized):
        components.append("native-library")
    component_tuple = tuple(dict.fromkeys(components))

    bundle_names = IOS_HERMES_BUNDLES if is_ios else ANDROID_HERMES_BUNDLES
    bundle_member = _find_member(names, bundle_names)
    if bundle_member:
        pathway_id = 2 if is_ios else 1
        return _detection(
            pathway_id,
            "react-native-hermes-ios" if is_ios else "react-native-hermes-android",
            platform,
            "react-native-hermes",
            f"React Native Hermes ({'iOS' if is_ios else 'Android'})",
            bundle_member=bundle_member,
            package_type=package_type,
            detected_components=component_tuple,
        )

    has_unity = any(
        "libil2cpp.so" in name or "global-metadata.dat" in name or "unityframework" in name for name in normalized
    )
    if has_unity:
        pathway_id = 4 if is_ios else 3
        return _detection(
            pathway_id,
            "unity-il2cpp-ios" if is_ios else "unity-il2cpp-android",
            platform,
            "unity-il2cpp",
            f"Unity IL2CPP ({'iOS' if is_ios else 'Android'})",
            package_type=package_type,
            detected_components=component_tuple,
        )

    if is_android and web_index_member is not None and web_bundle_member is not None:
        return _detection(
            6,
            "android-webview-javascript",
            "android",
            "android-webview-js",
            "Android WebView / Capacitor JavaScript",
            bundle_member=web_bundle_member,
            package_type="apk",
            detected_components=component_tuple,
            detection_notes=(
                f"packaged web index: {web_index_member}",
                *((f"deployed JavaScript entry: {web_bundle_member}",) if web_bundle_member else ()),
            ),
        )

    if is_ios:
        apple_info = PlistScanner.scan_ipa_file(path)
        apple_notes = tuple(apple_info.notes) if apple_info is not None else ()
        display_label = (
            f"Apple iOS App ({apple_info.bundle_name or apple_info.bundle_id})"
            if apple_info and (apple_info.bundle_name or apple_info.bundle_id)
            else "Native iOS Swift / Objective-C"
        )
        return _detection(
            8,
            "native-ios-swift-objc",
            "ios",
            "ios-swift-objc",
            display_label,
            package_type="ipa",
            detected_components=component_tuple,
            detection_notes=apple_notes,
        )

    if any("libapp.so" in name for name in normalized):
        flutter_info = FlutterScanner.probe_apk(path)
        flutter_notes = flutter_info.notes if flutter_info is not None else ()
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "android",
            "flutter",
            "Flutter / Native Android",
            package_type="apk",
            detected_components=component_tuple,
            detection_notes=flutter_notes,
        )
    if any("libunreal.so" in name or "libue4.so" in name for name in normalized):
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "android",
            "unreal-engine",
            "Unreal Engine / Native Android",
            package_type="apk",
            detected_components=component_tuple,
        )
    if any(name.endswith(".dex") for name in normalized):
        return _detection(
            6,
            "android-java-kotlin-dex",
            "android",
            "android-java-dex",
            "Android Java / Kotlin DEX",
            package_type="apk",
            detected_components=component_tuple,
        )
    if any(name.endswith(".so") for name in normalized):
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "android",
            "native-elf",
            "Native C/C++ Android",
            package_type="apk",
            detected_components=component_tuple,
        )
    return _detection(
        7,
        "native-cpp-unreal-flutter",
        platform,
        "native-cpp",
        "Native Android" if platform == "android" else "Unknown ZIP package",
        package_type=package_type,
        detected_components=component_tuple,
    )


def _detect_file(path: Path) -> ArchitectureDetection:
    if path.name.lower() in IOS_HERMES_BUNDLES:
        return _detection(
            2,
            "react-native-hermes-ios",
            "ios",
            "react-native-hermes",
            "React Native Hermes (iOS)",
            bundle_member=path.name,
        )
    if path.name.lower() in ANDROID_HERMES_BUNDLES:
        return _detection(
            1,
            "react-native-hermes-android",
            "android",
            "react-native-hermes",
            "React Native Hermes (Android)",
            bundle_member=path.name,
        )

    magic = get_magic_bytes(path)

    if magic.startswith(b"dex\n") or path.suffix.lower() == ".dex":
        return _detection(
            6,
            "android-java-kotlin-dex",
            "android",
            "android-java-dex",
            "Android Java / Kotlin DEX",
        )
    if path.name.lower() == "gameassembly.dll":
        return _detection(
            5,
            "unity-il2cpp-windows",
            "windows",
            "unity-il2cpp",
            "Unity IL2CPP (Windows)",
        )
    if path.name.lower() == "libil2cpp.so":
        return _detection(
            3,
            "unity-il2cpp-android",
            "android",
            "unity-il2cpp",
            "Unity IL2CPP (Android)",
        )
    if path.name.lower() == "unityframework":
        return _detection(
            4,
            "unity-il2cpp-ios",
            "ios",
            "unity-il2cpp",
            "Unity IL2CPP (iOS)",
        )
    if magic.startswith(b"\x00asm") or path.suffix.lower() == ".wasm":
        wasm_info = WasmScanner.scan_file(path)
        if wasm_info is not None:
            return _detection(
                7,
                f"wasm-{wasm_info.runtime}",
                "wasm",
                "wasm",
                f"WebAssembly ({wasm_info.runtime})",
                detection_notes=tuple(wasm_info.notes),
            )

    if path.suffix.lower() == ".asar":
        return _detection(
            6,
            "electron-asar",
            "desktop",
            "electron-asar",
            "Electron ASAR Container",
            package_type="asar",
        )

    if magic.startswith(b"MZ") or path.suffix.lower() in {".exe", ".dll"}:
        mit_report = MitigationScanner.scan_file(path)
        mit_notes = tuple(mit_report.notes) if mit_report is not None else ()
        pe_res = PeResourceScanner.scan_file(path)
        pe_notes = tuple(pe_res.notes) if pe_res is not None else ()
        combined_aux_notes = (*pe_notes, *mit_notes)

        dotnet_info = DotNetScanner.probe_file(path)
        if dotnet_info is not None:
            if dotnet_info.is_unity:
                return _detection(
                    5,
                    "unity-il2cpp-windows",
                    "windows",
                    "unity-dotnet",
                    "Unity .NET / Mono (Windows)",
                    detection_notes=(*dotnet_info.notes, *combined_aux_notes),
                )
            return _detection(
                7,
                "dotnet-managed",
                "windows",
                "dotnet",
                f".NET Assembly ({dotnet_info.clr_version})",
                detection_notes=(*dotnet_info.notes, *combined_aux_notes),
            )
        go_info = GoScanner.probe_file(path)
        if go_info is not None:
            return _detection(
                7,
                "native-go",
                "windows",
                "go",
                f"Go Binary ({go_info.version})",
                detection_notes=(*go_info.notes, *combined_aux_notes),
            )
        rust_info = RustScanner.probe_file(path)
        if rust_info is not None:
            return _detection(
                7,
                "native-rust",
                "windows",
                "rust",
                f"Rust Binary ({len(rust_info.crates)} crates)",
                detection_notes=(*rust_info.notes, *combined_aux_notes),
            )
        electron_info = ElectronScanner.probe_file(path)
        if electron_info is not None and electron_info.is_electron:
            return _detection(
                7,
                "native-cpp-unreal-flutter",
                "windows",
                "electron",
                "Electron Desktop (Windows)",
                detection_notes=(*electron_info.notes, *combined_aux_notes),
            )
        display_pe_name = "Native C/C++ Windows"
        if pe_res and (pe_res.product_name or pe_res.company_name):
            name_part = pe_res.product_name or "Windows App"
            display_pe_name = f"{name_part} (PE Binary)"
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "windows",
            "native-pe",
            display_pe_name,
            detection_notes=combined_aux_notes,
        )
    if magic.startswith(b"\x7fELF") or path.suffix.lower() == ".so":
        mit_report = MitigationScanner.scan_file(path)
        mit_notes = tuple(mit_report.notes) if mit_report is not None else ()

        if path.name.lower() in ("libapp.so", "libflutter.so"):
            flutter_info = FlutterScanner.probe_file(path)
            if flutter_info is not None:
                return _detection(
                    7,
                    "native-cpp-unreal-flutter",
                    "android",
                    "flutter",
                    "Flutter AOT Library",
                    detection_notes=(*flutter_info.notes, *mit_notes),
                )
        go_info = GoScanner.probe_file(path)
        if go_info is not None:
            return _detection(
                7,
                "native-go",
                "unknown",
                "go",
                f"Go ELF Binary ({go_info.version})",
                detection_notes=(*go_info.notes, *mit_notes),
            )
        rust_info = RustScanner.probe_file(path)
        if rust_info is not None:
            return _detection(
                7,
                "native-rust",
                "unknown",
                "rust",
                f"Rust ELF Binary ({len(rust_info.crates)} crates)",
                detection_notes=(*rust_info.notes, *mit_notes),
            )
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "unknown",
            "native-elf",
            "Native ELF (platform unresolved)",
            detection_notes=mit_notes,
        )
    if is_mach_o(path):
        mit_report = MitigationScanner.scan_file(path)
        mit_notes = tuple(mit_report.notes) if mit_report is not None else ()
        return _detection(
            8,
            "native-ios-swift-objc",
            "ios",
            "ios-macho",
            "Native iOS Swift / Objective-C",
            detection_notes=mit_notes,
        )
    return _detection(
        7,
        "native-cpp-unreal-flutter",
        "unknown",
        "native-cpp",
        "Native C/C++",
    )


def detect_architecture_from_path(
    target_path: str | Path,
    *,
    platform_hint: str | None = None,
) -> ArchitectureDetection:
    """Resolve one of the eight supported platform pathways."""
    path = Path(target_path)
    normalized_hint = normalize_platform_hint(platform_hint)
    if not path.exists():
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "unknown",
            "native-cpp",
            "Native C/C++",
        )

    if path.is_file() and zipfile.is_zipfile(path):
        return _detect_archive(path)
    if path.is_file():
        detected = _detect_file(path)
        if normalized_hint is not None and detected.platform == "unknown":
            return _detection(
                detected.pathway_id,
                detected.pathway,
                normalized_hint,
                detected.engine_type,
                f"{detected.display_name} ({normalized_hint.title()})",
                package_type=detected.package_type,
                detected_components=detected.detected_components,
                detection_notes=(*detected.detection_notes, f"explicit --platform {platform_hint}"),
            )
        return detected

    dump_markers = _il2cpp_dump_markers(path)
    if dump_markers:
        inferred_platform, platform_evidence = _infer_il2cpp_dump_platform(path)
        if normalized_hint is not None:
            inferred_platform = normalized_hint
            platform_evidence = (f"explicit --platform {platform_hint}",)
        notes = (
            f"Il2CppDumper artifacts: {', '.join(dump_markers)}",
            *platform_evidence,
        )
        return _il2cpp_detection(
            inferred_platform,
            package_type="metadata-directory",
            detection_notes=notes,
        )

    names = [str(candidate.relative_to(path)).replace("\\", "/") for candidate in iter_directory_files_bounded(path)]
    normalized = [name.lower() for name in names]
    bundle_member = _find_member(names, IOS_HERMES_BUNDLES + ANDROID_HERMES_BUNDLES)
    if bundle_member:
        is_ios = Path(bundle_member).name.lower() in IOS_HERMES_BUNDLES or any(
            name.startswith("payload/") for name in normalized
        )
        return _detection(
            2 if is_ios else 1,
            "react-native-hermes-ios" if is_ios else "react-native-hermes-android",
            "ios" if is_ios else "android",
            "react-native-hermes",
            f"React Native Hermes ({'iOS' if is_ios else 'Android'})",
            bundle_member=bundle_member,
            package_type="directory",
        )
    if any("gameassembly.dll" in name for name in normalized):
        return _detection(
            5,
            "unity-il2cpp-windows",
            "windows",
            "unity-il2cpp",
            "Unity IL2CPP (Windows)",
            package_type="directory",
        )
    if any("global-metadata.dat" in name or "libil2cpp.so" in name for name in normalized):
        is_ios = any("unityframework" in name or name.startswith("payload/") for name in normalized)
        return _detection(
            4 if is_ios else 3,
            "unity-il2cpp-ios" if is_ios else "unity-il2cpp-android",
            "ios" if is_ios else "android",
            "unity-il2cpp",
            f"Unity IL2CPP ({'iOS' if is_ios else 'Android'})",
            package_type="directory",
        )
    if any(name.endswith("libapp.so") for name in normalized):
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "android",
            "flutter",
            "Flutter / Native Android",
            package_type="directory",
        )
    if any(name.endswith(("libunreal.so", "libue4.so")) for name in normalized):
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "android",
            "unreal-engine",
            "Unreal Engine / Native Android",
            package_type="directory",
        )
    if any(name.endswith("classes.dex") for name in normalized):
        return _detection(
            6,
            "android-java-kotlin-dex",
            "android",
            "android-java-dex",
            "Android Java / Kotlin DEX",
            package_type="directory",
        )
    if any(name.startswith("payload/") or name.endswith("info.plist") for name in normalized):
        apple_info = PlistScanner.scan_file(path)
        apple_notes = tuple(apple_info.notes) if apple_info is not None else ()
        display_label = (
            f"Apple iOS App ({apple_info.bundle_name or apple_info.bundle_id})"
            if apple_info and (apple_info.bundle_name or apple_info.bundle_id)
            else "Native iOS Swift / Objective-C"
        )
        return _detection(
            8,
            "native-ios-swift-objc",
            "ios",
            "ios-swift-objc",
            display_label,
            package_type="directory",
            detection_notes=apple_notes,
        )
    if any(name.endswith(".wasm") for name in normalized):
        wasm_files = [path / n for n in names if n.endswith(".wasm")]
        wasm_notes: list[str] = []
        if wasm_files:
            winfo = WasmScanner.scan_file(wasm_files[0])
            if winfo:
                wasm_notes = list(winfo.notes)
        return _detection(
            7,
            "wasm-generic",
            "wasm",
            "wasm",
            "WebAssembly Directory",
            package_type="directory",
            detection_notes=tuple(wasm_notes),
        )
    if any(name.endswith(".asar") for name in normalized):
        return _detection(
            6,
            "electron-asar",
            "desktop",
            "electron-asar",
            "Electron Desktop Application",
            package_type="directory",
        )
    if any(name.endswith(".so") for name in normalized):
        elf_platform = normalized_hint or "android"
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            elf_platform,
            "native-elf",
            f"Native C/C++ {elf_platform.title()}",
            package_type="directory",
            detection_notes=(f"explicit --platform {platform_hint}",) if normalized_hint else (),
        )

    if any(name.endswith((".exe", ".dll")) for name in normalized):
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "windows",
            "native-pe",
            "Native C/C++ Windows",
            package_type="directory",
        )
    unresolved_platform = normalized_hint or "unknown"
    return _detection(
        7,
        "native-cpp-unreal-flutter",
        unresolved_platform,
        "native-cpp",
        (f"Native C/C++ ({unresolved_platform.title()})" if normalized_hint else "Native C/C++ / Unreal / Flutter"),
        package_type="directory",
        detection_notes=(f"explicit --platform {platform_hint}",) if normalized_hint else (),
    )


def detect_engine_type_from_path(target_path: str | Path) -> str:
    """Return the legacy engine identifier for compatibility."""
    return detect_architecture_from_path(target_path).engine_type


def detect_engine_type(
    symbols: list[dict[str, Any]] | list[str],
    strings: list[str] | None = None,
) -> str:
    """Detect binary framework type from Ghidra symbol and string evidence."""
    symbols_text = " ".join(symbol if isinstance(symbol, str) else symbol.get("name", "") for symbol in symbols).lower()
    strings_text = " ".join(strings or []).lower()
    combined = f"{symbols_text} {strings_text}"

    if any(
        keyword in combined
        for keyword in {
            "gamevardef",
            "il2cpp",
            "il2cpp-metadata",
            "il2cpp_domain_get",
            "il2cpp_init",
        }
    ):
        return "unity-il2cpp"
    if any(
        keyword in combined
        for keyword in {
            "hermes",
            "index.android.bundle",
            "index.ios.bundle",
            "main.jsbundle",
            "reactnative",
        }
    ):
        return "react-native-hermes"
    if any(keyword in combined for keyword in {"fname::tostring", "fstring", "gengine", "gobjects", "uobject"}):
        return "unreal-engine"
    if any(keyword in combined for keyword in {"java_", "jni_onload", "jninativeinterface"}):
        return "android-jni"
    if any(keyword in combined for keyword in {"_objc_msgsend", "_swift_", "nslog", "unityappcontroller"}):
        return "ios-objc"
    return "native-cpp"
