"""Platform and engine detection for the eight supported binary pathways."""

from __future__ import annotations

import os
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from re_agent.utils.archives import ArchiveSafetyError, inspect_archive
from re_agent.utils.binary_magic import get_magic_bytes, is_mach_o

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
    "windows": "windows",
    "windows-x64": "windows",
}
MAX_PLATFORM_EVIDENCE_BYTES: Final[int] = 2 * 1024 * 1024


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
            names = [info.filename for info in inspect_archive(archive)]
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

    if is_ios:
        return _detection(
            8,
            "native-ios-swift-objc",
            "ios",
            "ios-swift-objc",
            "Native iOS Swift / Objective-C",
            package_type="ipa",
            detected_components=component_tuple,
        )

    if any("libapp.so" in name for name in normalized):
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "android",
            "flutter",
            "Flutter / Native Android",
            package_type="apk",
            detected_components=component_tuple,
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
    if magic.startswith(b"MZ") or path.suffix.lower() in {".exe", ".dll"}:
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "windows",
            "native-pe",
            "Native C/C++ Windows",
        )
    if magic.startswith(b"\x7fELF") or path.suffix.lower() == ".so":
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "unknown",
            "native-elf",
            "Native ELF (platform unresolved)",
        )
    if is_mach_o(path):
        return _detection(
            8,
            "native-ios-swift-objc",
            "ios",
            "ios-macho",
            "Native iOS Swift / Objective-C",
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
        return _detect_file(path)

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
    if any(name.startswith("payload/") for name in normalized):
        return _detection(
            8,
            "native-ios-swift-objc",
            "ios",
            "ios-swift-objc",
            "Native iOS Swift / Objective-C",
            package_type="directory",
        )
    if any(name.endswith(".so") for name in normalized):
        return _detection(
            7,
            "native-cpp-unreal-flutter",
            "android",
            "native-elf",
            "Native C/C++ Android",
            package_type="directory",
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
    return _detection(
        7,
        "native-cpp-unreal-flutter",
        "unknown",
        "native-cpp",
        "Native C/C++ / Unreal / Flutter",
        package_type="directory",
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
