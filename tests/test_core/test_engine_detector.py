"""Unit tests for engine detection module (Unity, React Native, Flutter, Java DEX, iOS IPA, Native C++)."""

from __future__ import annotations

import zipfile
from pathlib import Path

from re_agent.core.engine_detector import (
    detect_architecture_from_path,
    detect_engine_type,
    detect_engine_type_from_path,
    resolve_hermes_bundle_member,
)


def test_detect_unity_il2cpp_symbols() -> None:
    symbols = [{"name": "il2cpp_init"}, {"name": "il2cpp_domain_get"}]
    engine = detect_engine_type(symbols, ["il2cpp-metadata"])
    assert engine == "unity-il2cpp"


def test_detect_unreal_engine_symbols() -> None:
    symbols = [{"name": "UObject::ProcessEvent"}, {"name": "FName::ToString"}]
    engine = detect_engine_type(symbols, ["GEngine"])
    assert engine == "unreal-engine"


def test_detect_android_jni_symbols() -> None:
    symbols = [{"name": "Java_com_example_Game_init"}, {"name": "JNI_OnLoad"}]
    engine = detect_engine_type(symbols)
    assert engine == "android-jni"


def test_detect_ios_objc_symbols() -> None:
    symbols = [{"name": "_objc_msgSend"}, {"name": "UnityAppController"}]
    engine = detect_engine_type(symbols)
    assert engine == "ios-objc"


def test_detect_native_cpp_symbols() -> None:
    symbols = [{"name": "main"}, {"name": "std::vector<int>::push_back"}]
    engine = detect_engine_type(symbols)
    assert engine == "native-cpp"


# --- Framework Detection Tests directly from APK / ZIP / Directory Paths ---


def test_detect_react_native_hermes_from_apk(tmp_path: Path) -> None:
    apk_path = tmp_path / "app_hermes.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("assets/index.android.bundle", b"\x1e\x04\x00\x00hermes_bytecode")
        z.writestr("classes.dex", b"dex_bytes")

    engine = detect_engine_type_from_path(apk_path)
    assert engine == "react-native-hermes"


def test_detect_unity_il2cpp_from_apk(tmp_path: Path) -> None:
    apk_path = tmp_path / "game_unity.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", b"elf_bytes")
        z.writestr("assets/bin/Data/Managed/metadata/global-metadata.dat", b"meta_bytes")

    engine = detect_engine_type_from_path(apk_path)
    assert engine == "unity-il2cpp"


def test_detect_flutter_from_apk(tmp_path: Path) -> None:
    apk_path = tmp_path / "app_flutter.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("lib/arm64-v8a/libapp.so", b"flutter_bytes")
        z.writestr("classes.dex", b"dex_bytes")

    engine = detect_engine_type_from_path(apk_path)
    assert engine == "flutter"


def test_detect_android_java_dex_from_apk(tmp_path: Path) -> None:
    apk_path = tmp_path / "app_kotlin.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("classes.dex", b"dex_bytes")
        z.writestr("classes2.dex", b"dex2_bytes")

    engine = detect_engine_type_from_path(apk_path)
    assert engine == "android-java-dex"


def test_detect_ios_swift_objc_from_ipa(tmp_path: Path) -> None:
    ipa_path = tmp_path / "app_ios.ipa"
    with zipfile.ZipFile(ipa_path, "w") as z:
        z.writestr("Payload/TargetApp.app/TargetApp", b"macho_bytes")

    engine = detect_engine_type_from_path(ipa_path)
    assert engine == "ios-swift-objc"


def test_detect_react_native_hermes_from_ios_ipa(tmp_path: Path) -> None:
    ipa_path = tmp_path / "react_ios.ipa"
    with zipfile.ZipFile(ipa_path, "w") as archive:
        archive.writestr(
            "Payload/Target.app/main.jsbundle",
            b"var state = {'coins': 1};",
        )

    detection = detect_architecture_from_path(ipa_path)
    assert detection.pathway_id == 2
    assert detection.pathway == "react-native-hermes-ios"
    assert detection.bundle_member == "Payload/Target.app/main.jsbundle"
    assert resolve_hermes_bundle_member(ipa_path) == detection.bundle_member


def test_resolve_ios_bundle_in_lowercase_payload_zip(tmp_path: Path) -> None:
    archive_path = tmp_path / "renamed-package.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload/Target.app/main.jsbundle", b"const value = 1;")

    assert (
        resolve_hermes_bundle_member(archive_path)
        == "payload/Target.app/main.jsbundle"
    )


def test_detect_unity_il2cpp_windows(tmp_path: Path) -> None:
    game_assembly = tmp_path / "GameAssembly.dll"
    game_assembly.write_bytes(b"MZ\x00\x00")

    detection = detect_architecture_from_path(game_assembly)
    assert detection.pathway_id == 5
    assert detection.platform == "windows"
    assert detection.engine_type == "unity-il2cpp"


def test_detect_unity_il2cpp_windows_from_zip(tmp_path: Path) -> None:
    archive_path = tmp_path / "windows-build.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("Game/GameAssembly.dll", b"MZ\x00\x00")
        archive.writestr("Game/Game_Data/globalgamemanagers", b"unity")

    detection = detect_architecture_from_path(archive_path)

    assert detection.pathway_id == 5
    assert detection.platform == "windows"
    assert detection.engine_type == "unity-il2cpp"
    assert detection.package_type == "zip"


def test_detect_direct_libil2cpp_as_unity_android(tmp_path: Path) -> None:
    binary = tmp_path / "libil2cpp.so"
    binary.write_bytes(b"\x7fELF" + b"\0" * 32)

    detection = detect_architecture_from_path(binary)

    assert detection.pathway_id == 3
    assert detection.platform == "android"
    assert detection.engine_type == "unity-il2cpp"


def test_detect_unity_il2cpp_ios(tmp_path: Path) -> None:
    ipa_path = tmp_path / "unity_ios.ipa"
    with zipfile.ZipFile(ipa_path, "w") as archive:
        archive.writestr("Payload/Game.app/Frameworks/UnityFramework.framework/UnityFramework", b"macho")
        archive.writestr("Payload/Game.app/Data/Managed/Metadata/global-metadata.dat", b"meta")

    detection = detect_architecture_from_path(ipa_path)
    assert detection.pathway_id == 4
    assert detection.platform == "ios"


def test_detect_flutter_from_extracted_directory(tmp_path: Path) -> None:
    library = tmp_path / "lib" / "arm64-v8a" / "libapp.so"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"\x7fELF")

    detection = detect_architecture_from_path(tmp_path)

    assert detection.pathway_id == 7
    assert detection.platform == "android"
    assert detection.engine_type == "flutter"


def test_detect_unreal_from_extracted_directory(tmp_path: Path) -> None:
    library = tmp_path / "lib" / "arm64-v8a" / "libUnreal.so"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"\x7fELF")

    detection = detect_architecture_from_path(tmp_path)

    assert detection.pathway_id == 7
    assert detection.platform == "android"
    assert detection.engine_type == "unreal-engine"


def test_detect_native_elf_from_extracted_directory(tmp_path: Path) -> None:
    library = tmp_path / "lib" / "arm64-v8a" / "libmain.so"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"\x7fELF")

    detection = detect_architecture_from_path(tmp_path)

    assert detection.pathway_id == 7
    assert detection.platform == "android"
    assert detection.engine_type == "native-elf"


def test_detect_native_pe_from_extracted_directory(tmp_path: Path) -> None:
    binary = tmp_path / "bin" / "helper.dll"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"MZ\x00\x00")

    detection = detect_architecture_from_path(tmp_path)

    assert detection.pathway_id == 7
    assert detection.platform == "windows"
    assert detection.engine_type == "native-pe"


def test_detect_native_android_shared_object_pathway(tmp_path: Path) -> None:
    apk_path = tmp_path / "native.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("lib/arm64-v8a/libmain.so", b"\x7fELF")

    detection = detect_architecture_from_path(apk_path)
    assert detection.pathway_id == 7
    assert detection.engine_type == "native-elf"


def test_detect_fat_macho_magic(tmp_path: Path) -> None:
    binary = tmp_path / "RenamedBinary"
    binary.write_bytes(b"\xca\xfe\xba\xbe" + b"\0" * 32)

    detection = detect_architecture_from_path(binary)

    assert detection.pathway_id == 8
    assert detection.platform == "ios"


def test_hostile_bundle_member_does_not_select_hermes(tmp_path: Path) -> None:
    apk = tmp_path / "hostile.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("../assets/index.android.bundle", b"var coins = 1")

    detection = detect_architecture_from_path(apk)

    assert detection.engine_type != "react-native-hermes"


def test_hybrid_package_retains_all_detected_components(tmp_path: Path) -> None:
    apk = tmp_path / "hybrid.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/index.android.bundle", b"var coins = 1")
        archive.writestr("classes.dex", b"dex")
        archive.writestr("lib/arm64-v8a/libil2cpp.so", b"\x7fELF")
        archive.writestr("assets/bin/Data/Managed/metadata/global-metadata.dat", b"meta")

    detection = detect_architecture_from_path(apk)

    assert detection.pathway_id == 1
    assert set(detection.detected_components) >= {
        "react-native-hermes",
        "unity-il2cpp",
        "android-dex",
        "native-library",
    }
