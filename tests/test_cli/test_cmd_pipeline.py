"""Unit tests for 1-click automated pipeline CLI command."""

from __future__ import annotations

import io
import json
import struct
import zipfile
from pathlib import Path

from reforge.cli.cmd_pipeline import (
    _discover_hermes_candidates,
    _patch_textual_bundle,
    _repackage_android,
    _scan_js_primitive_properties,
    _write_hermes_candidate_evidence,
)
from reforge.cli.main import main
from reforge.core.engine_detector import detect_architecture_from_path
from reforge.llm.analyzed_target import AnalyzedTarget
from reforge.packaging.frida_gadget import GADGET_LOADER_DESCRIPTOR


def test_cmd_pipeline_generic_binary(tmp_path: Path) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text(f"""
project_profile:
  name: "generic-cpp"
  source_root: "{tmp_path.as_posix()}/src"
""")

    dummy_binary = tmp_path / "GenericBinary.exe"
    dummy_binary.write_text("binary-content")

    out_dir = (tmp_path / "src").as_posix()
    args = [
        "--config",
        config_file.as_posix(),
        "pipeline",
        "--binary",
        dummy_binary.as_posix(),
        "--output-dir",
        out_dir,
    ]

    out = main(args)
    assert out == 3
    assert not (tmp_path / "src" / "ReconstructedModule.h").exists()
    assert not (tmp_path / "src" / "ReconstructedModule.cpp").exists()


def test_gadget_tuning_option_requires_explicit_embedding(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"dex\n035\x00")

    assert (
        main(
            [
                "pipeline",
                "--binary",
                apk.as_posix(),
                "--frida-gadget-port",
                "28042",
                "--no-repack",
            ]
        )
        == 2
    )


def test_managed_gadget_install_is_used_without_path_flags(
    tmp_path: Path,
    monkeypatch,
) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"dex\n035\x00")
    gadget_dir = tmp_path / "frida-gadget" / "17.16.4"
    gadget_dir.mkdir(parents=True)
    observed: dict[str, object] = {}
    target = AnalyzedTarget(
        class_name="com.example.Wallet",
        target="getCoins",
        hook_type="return_override",
        confidence=90,
        reason="test candidate",
    )
    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline.resolve_frida_gadget_path",
        lambda _explicit=None, *, version=None: gadget_dir,
    )
    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline._local_frida_version",
        lambda: "17.16.4",
    )
    monkeypatch.setattr(
        "reforge.cli.cmd_batch.cmd_batch",
        lambda _args: (0, [], [target]),
    )

    def fake_repackage(
        _binary,
        output_dir,
        _architecture,
        _generated_files,
        _modified_bundle,
        **kwargs,
    ):
        observed.update(kwargs)
        signed = output_dir / "modded_app-aligned-signed.apk"
        signed.write_bytes(b"signed")
        return True, str(signed)

    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline._repackage_android",
        fake_repackage,
    )

    result = main(
        [
            "pipeline",
            "--binary",
            apk.as_posix(),
            "--goal",
            "give infinite coins",
            "--embed-frida-gadget",
            "--output-dir",
            (tmp_path / "output").as_posix(),
        ]
    )

    assert result == 0
    assert observed["gadget_path"] == gadget_dir
    assert observed["gadget_version"] == "17.16.4"


def test_cmd_pipeline_uses_desktop_app_output_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text('project_profile:\n  name: "react-native"\n')
    apk_path = tmp_path / "base.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            b'<manifest package="com.example.runner"><application /></manifest>',
        )
        archive.writestr(
            "assets/index.android.bundle",
            b'const state = {"diamonds": 1};',
        )

    output_dir = tmp_path / "Desktop" / "runner_output"
    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline.default_pipeline_output_dir",
        lambda _path: output_dir,
    )
    monkeypatch.setattr(
        "reforge.cli.cmd_batch.cmd_batch",
        lambda _args: (0, [], []),
    )

    result = main(
        [
            "--config",
            config_file.as_posix(),
            "pipeline",
            "--binary",
            apk_path.as_posix(),
            "--goal",
            "grant unlimited diamonds",
            "--no-repack",
        ]
    )

    assert result == 0
    assert (output_dir / "Hook_Frida.js").is_file()
    assert (output_dir / "pipeline_manifest.json").is_file()


def test_cmd_pipeline_react_native_hermes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text("""
project_profile:
  name: "react-native"
""")

    apk_path = tmp_path / "react_app.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("assets/index.android.bundle", b'var state = {"subscription": false};')
        z.writestr("classes.dex", b"fake_dex_bytes")

    monkeypatch.setattr(
        "reforge.cli.cmd_batch.cmd_batch",
        lambda _args: (0, [], []),
    )

    out_dir = tmp_path / "output_rn"
    args = [
        "--config",
        config_file.as_posix(),
        "pipeline",
        "--binary",
        apk_path.as_posix(),
        "--goal",
        "unlock pro subscription and bypass quota limits",
        "--output-dir",
        out_dir.as_posix(),
    ]

    out = main(args)
    assert out == 0
    assert (out_dir / "index.android.bundle").exists()
    assert (out_dir / "Hook_Frida.js").exists()
    assert (out_dir / "patch_diff_summary.txt").exists()
    manifest = json.loads((out_dir / "pipeline_manifest.json").read_text(encoding="utf-8"))
    assert manifest["capabilities"]["analysis_complete"] is True
    assert manifest["capabilities"]["runtime_hook_installed"] is False
    assert manifest["capabilities"]["runtime_behavior_verified"] is False
    assert {stage["status"] for stage in manifest["stages"]} <= {
        "SUCCEEDED",
        "FAILED",
        "SKIPPED",
    }


def test_pipeline_stops_before_packaging_when_all_candidates_are_review_only(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text('project_profile:\n  name: "react-native"\n')
    apk_path = tmp_path / "review-only.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "assets/index.android.bundle",
            b'const state = {"balance": 1};',
        )
    monkeypatch.setattr(
        "reforge.cli.cmd_batch.cmd_batch",
        lambda _args: (0, [], []),
    )

    def fail_if_prompted(*_args, **_kwargs):
        raise AssertionError("review-only analysis must not offer packaging")

    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline._repack_choice",
        fail_if_prompted,
    )
    output_dir = tmp_path / "review-output"

    result = main(
        [
            "--config",
            config_file.as_posix(),
            "pipeline",
            "--binary",
            apk_path.as_posix(),
            "--goal",
            "grant unlimited diamonds",
            "--output-dir",
            output_dir.as_posix(),
        ]
    )

    terminal = capsys.readouterr().out
    manifest = json.loads((output_dir / "pipeline_manifest.json").read_text(encoding="utf-8"))
    discovery = next(stage for stage in manifest["stages"] if stage["name"] == "candidate_discovery")
    packaging = next(stage for stage in manifest["stages"] if stage["name"] == "packaging")

    assert result == 3
    assert "INSUFFICIENT_EVIDENCE" in terminal
    assert "Step 5/5: Packaging decision" not in terminal
    assert discovery["status"] == "PARTIAL"
    assert packaging["status"] == "SKIPPED"
    assert manifest["capabilities"]["analysis_complete"] is False
    assert manifest["capabilities"]["package_artifact"] is None


def test_interactive_android_repack_applies_textual_patch_before_packaging(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text('project_profile:\n  name: "react-native"\n')
    apk_path = tmp_path / "patchable.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "assets/index.android.bundle",
            b'const state = {"coins": 1};',
        )
    monkeypatch.setattr(
        "reforge.cli.cmd_batch.cmd_batch",
        lambda _args: (0, [], []),
    )
    observed: dict[str, object] = {}

    def choose_repack(_args, _architecture, **kwargs):
        observed["choice_kwargs"] = kwargs
        return True

    def fake_repackage(
        _binary,
        output_dir,
        _architecture,
        _generated_files,
        modified_bundle,
        **_kwargs,
    ):
        observed["modified_bytes"] = modified_bundle.read_bytes()
        signed = output_dir / "modded_app-aligned-signed.apk"
        signed.write_bytes(b"signed")
        return True, str(signed)

    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline._repack_choice",
        choose_repack,
    )
    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline._repackage_android",
        fake_repackage,
    )
    output_dir = tmp_path / "patch-output"

    result = main(
        [
            "--config",
            config_file.as_posix(),
            "pipeline",
            "--binary",
            apk_path.as_posix(),
            "--goal",
            "grant unlimited coins",
            "--output-dir",
            output_dir.as_posix(),
        ]
    )

    assert result == 0
    assert observed["choice_kwargs"] == {
        "android_repackage_available": True,
        "unavailable_reason": None,
    }
    assert observed["modified_bytes"] == b'const state = {"coins": 999999999};'
    manifest = json.loads((output_dir / "pipeline_manifest.json").read_text(encoding="utf-8"))
    assert manifest["capabilities"]["static_patch_created"] is True
    assert manifest["capabilities"]["package_artifact"].endswith("modded_app-aligned-signed.apk")


def test_cmd_pipeline_ios_hermes_bundle_and_deployment_notes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text('project_profile:\n  name: "ios-arm64"\n')
    ipa_path = tmp_path / "react_ios.ipa"
    with zipfile.ZipFile(ipa_path, "w") as archive:
        archive.writestr(
            "Payload/Target.app/main.jsbundle",
            b'var state = {"diamonds": 10, "balance": 1};',
        )

    monkeypatch.setattr(
        "reforge.cli.cmd_batch.cmd_batch",
        lambda _args: (0, [], []),
    )
    output_dir = tmp_path / "ios-output"
    result = main(
        [
            "--config",
            config_file.as_posix(),
            "pipeline",
            "--binary",
            ipa_path.as_posix(),
            "--goal",
            "grant unlimited diamonds",
            "--patch-bundle",
            "--no-repack",
            "--output-dir",
            output_dir.as_posix(),
        ]
    )

    assert result == 0
    assert (output_dir / "main.jsbundle").exists()
    assert (output_dir / "modified_main.jsbundle").exists()
    assert (output_dir / "Hook_Frida.js").exists()
    assert (output_dir / "IOS_DEPLOYMENT_NOTES.txt").exists()
    summary = (output_dir / "patch_diff_summary.txt").read_text(encoding="utf-8")
    assert "Pathway 2: React Native Hermes (iOS)" in summary
    assert "[95%] HermesBundle::diamonds" in summary


def test_cmd_pipeline_webview_uses_source_maps_instead_of_shell_dex(
    tmp_path: Path,
    capsys,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text('project_profile:\n  name: "generic-cpp"\n')
    apk_path = tmp_path / "capacitor.apk"
    source_map = json.dumps(
        {
            "version": 3,
            "file": "app.js",
            "sources": [
                "../../src/features/spark/api.ts",
                "../../src/features/spark/useSparkBalance.ts",
            ],
            "sourcesContent": [
                "const url = 'spark/wallet';\nPrivateApi.get(url).json();",
                "function set(newBalance: number) {\n  cache.set({ wallet: { balance: newBalance } });\n}\n",
            ],
            "names": [],
            "mappings": "",
        }
    )
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "assets/public/index.html",
            '<script type="module" src="./assets/app.js"></script>',
        )
        archive.writestr("assets/public/assets/app.js", "export const app = true;\n")
        archive.writestr("assets/public/assets/app.js.map", source_map)
        archive.writestr("assets/capacitor.config.json", "{}")
        archive.writestr("classes.dex", b"dex\n035\x00")

    output_dir = tmp_path / "web-output"
    result = main(
        [
            "--config",
            config_file.as_posix(),
            "pipeline",
            "--binary",
            apk_path.as_posix(),
            "--goal",
            "grant unlimited sparks",
            "--patch-bundle",
            "--no-repack",
            "--output-dir",
            output_dir.as_posix(),
        ]
    )

    assert result == 0
    terminal = capsys.readouterr().out
    assert "Android WebView / Capacitor JavaScript" in terminal
    assert "Parsing declared executable methods from Android DEX" not in terminal
    hook = (output_dir / "Hook_Web.js").read_text(encoding="utf-8")
    modified = (output_dir / "modified_app.js").read_text(encoding="utf-8")
    assert '"endpoint":"spark/wallet"' in hook
    assert '"path":["wallet","balance"]' in hook
    assert "9007199254740991" in hook
    assert hook in modified
    assert not (output_dir / "Hook_Frida.js").exists()
    manifest = json.loads((output_dir / "pipeline_manifest.json").read_text(encoding="utf-8"))
    assert manifest["pathway"]["engine_type"] == "android-webview-js"
    assert manifest["capabilities"]["static_patch_created"] is True


def test_pipeline_fails_when_requested_static_patch_is_ambiguous(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text('project_profile:\n  name: "react-native"\n')
    apk_path = tmp_path / "duplicate.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "assets/index.android.bundle",
            b'const a = {"coins": 1}; const b = {"coins": 2};',
        )
    monkeypatch.setattr(
        "reforge.cli.cmd_batch.cmd_batch",
        lambda _args: (0, [], []),
    )
    output_dir = tmp_path / "output"

    result = main(
        [
            "--config",
            config_file.as_posix(),
            "pipeline",
            "--binary",
            apk_path.as_posix(),
            "--goal",
            "grant unlimited coins",
            "--patch-bundle",
            "--no-repack",
            "--output-dir",
            output_dir.as_posix(),
        ]
    )

    assert result == 4
    manifest = json.loads((output_dir / "pipeline_manifest.json").read_text(encoding="utf-8"))
    assert manifest["exit_code"] == 4
    assert manifest["capabilities"]["static_patch_created"] is False
    patch_stage = next(stage for stage in manifest["stages"] if stage["name"] == "static_patch")
    assert patch_stage["status"] == "FAILED"


def test_cmd_pipeline_android_apk_extracts_il2cpp_so(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text('project_profile:\n  name: "android-arm64"\n')
    apk_path = tmp_path / "unity.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("lib/armeabi-v7a/libil2cpp.so", b"32-bit")
        archive.writestr("lib/arm64-v8a/libil2cpp.so", b"64-bit")
        archive.writestr(
            "assets/bin/Data/Managed/Metadata/global-metadata.dat",
            b"metadata",
        )

    dumper_path = tmp_path / "Il2CppDumper.exe"
    dumper_path.write_bytes(b"trusted test executable")
    observed: dict[str, object] = {}

    def fake_dumper(binary, metadata, output, *, dumper_path=None):
        observed["binary_bytes"] = Path(binary).read_bytes()
        observed["metadata_bytes"] = Path(metadata).read_bytes()
        observed["dumper_path"] = dumper_path
        Path(output, "dump.cs").write_text("// evidence", encoding="utf-8")
        return {"success": True, "output_dir": str(output)}

    def fake_batch(args):
        observed["metadata_dir"] = args.metadata_dir
        assert Path(args.metadata_dir, "dump.cs").is_file()
        target = AnalyzedTarget(
            class_name="Wallet",
            target="get_Coins",
            hook_type="return_override",
            return_value="999999",
            return_type="int32_t",
            confidence=90,
            reason="Test dumper evidence",
        )
        return 0, [], [target]

    monkeypatch.setattr(
        "reforge.core.il2cpp_parser.run_il2cpp_dumper_cli",
        fake_dumper,
    )
    monkeypatch.setattr("reforge.cli.cmd_batch.cmd_batch", fake_batch)

    output_dir = tmp_path / "unity-output"
    result = main(
        [
            "--config",
            config_file.as_posix(),
            "pipeline",
            "--binary",
            apk_path.as_posix(),
            "--metadata-dir",
            tmp_path.as_posix(),
            "--il2cpp-dumper",
            dumper_path.as_posix(),
            "--goal",
            "grant unlimited coins",
            "--no-repack",
            "--output-dir",
            output_dir.as_posix(),
        ]
    )

    assert result == 0
    assert observed["binary_bytes"] == b"64-bit"
    assert observed["metadata_bytes"] == b"metadata"
    assert Path(str(observed["dumper_path"])) == dumper_path
    assert Path(str(observed["metadata_dir"])).name == "il2cpp_dumper_output"
    assert (output_dir / "Hook_Goal.cpp").is_file()


def test_cmd_pipeline_ipa_extracts_unityframework_binary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text('project_profile:\n  name: "generic-cpp"\n')
    ipa_path = tmp_path / "game.ipa"
    with zipfile.ZipFile(ipa_path, "w") as archive:
        archive.writestr(
            "Payload/Game.app/Frameworks/UnityFramework.framework/Info.plist",
            b"<xml>metadata</xml>",
        )
        archive.writestr(
            "Payload/Game.app/Frameworks/UnityFramework.framework/UnityFramework",
            b"macho-binary-executable",
        )
        archive.writestr(
            "Payload/Game.app/Data/Managed/Metadata/global-metadata.dat",
            b"global-metadata-bytes",
        )

    dumper_path = tmp_path / "il2cpp_dumper.exe"
    dumper_path.write_bytes(b"trusted test executable")
    observed: dict[str, object] = {}

    def fake_dumper(binary, metadata, output, *, dumper_path=None):
        observed["binary_bytes"] = Path(binary).read_bytes()
        observed["metadata_bytes"] = Path(metadata).read_bytes()
        Path(output, "dump.cs").write_text("// evidence", encoding="utf-8")
        return {"success": True, "output_dir": str(output)}

    def fake_batch(args):
        target = AnalyzedTarget(
            class_name="Wallet",
            target="get_Coins",
            hook_type="return_override",
            return_value="999999",
            return_type="int32_t",
            confidence=90,
            reason="Test dumper evidence",
        )
        return 0, [], [target]

    monkeypatch.setattr(
        "reforge.core.il2cpp_parser.run_il2cpp_dumper_cli",
        fake_dumper,
    )
    monkeypatch.setattr("reforge.cli.cmd_batch.cmd_batch", fake_batch)

    output_dir = tmp_path / "ipa-output"
    result = main(
        [
            "--config",
            config_file.as_posix(),
            "pipeline",
            "--binary",
            ipa_path.as_posix(),
            "--il2cpp-dumper",
            dumper_path.as_posix(),
            "--goal",
            "grant unlimited coins",
            "--no-repack",
            "--output-dir",
            output_dir.as_posix(),
        ]
    )

    assert result == 0
    assert observed["binary_bytes"] == b"macho-binary-executable"
    assert observed["metadata_bytes"] == b"global-metadata-bytes"


def test_cmd_pipeline_windows_gameassembly_extracts_dll(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text('project_profile:\n  name: "generic-cpp"\n')
    zip_path = tmp_path / "windows_game.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(
            "Game_Data/Plugins/x86_64/GameAssembly.dll",
            b"pe-windows-binary-executable",
        )
        archive.writestr(
            "Game_Data/StreamingAssets/config.plist",
            b"<xml>ignore</xml>",
        )
        archive.writestr(
            "Game_Data/il2cpp_data/Metadata/global-metadata.dat",
            b"windows-metadata-bytes",
        )

    dumper_path = tmp_path / "il2cpp_dumper.exe"
    dumper_path.write_bytes(b"trusted test executable")
    observed: dict[str, object] = {}

    def fake_dumper(binary, metadata, output, *, dumper_path=None):
        observed["binary_bytes"] = Path(binary).read_bytes()
        observed["metadata_bytes"] = Path(metadata).read_bytes()
        Path(output, "dump.cs").write_text("// evidence", encoding="utf-8")
        return {"success": True, "output_dir": str(output)}

    def fake_batch(args):
        target = AnalyzedTarget(
            class_name="PlayerWallet",
            target="AddMoney",
            hook_type="return_override",
            return_value="999999",
            return_type="void",
            confidence=90,
            reason="Windows dumper evidence",
        )
        return 0, [], [target]

    monkeypatch.setattr(
        "reforge.core.il2cpp_parser.run_il2cpp_dumper_cli",
        fake_dumper,
    )
    monkeypatch.setattr("reforge.cli.cmd_batch.cmd_batch", fake_batch)

    output_dir = tmp_path / "windows-output"
    result = main(
        [
            "--config",
            config_file.as_posix(),
            "pipeline",
            "--binary",
            zip_path.as_posix(),
            "--il2cpp-dumper",
            dumper_path.as_posix(),
            "--goal",
            "grant unlimited money",
            "--no-repack",
            "--output-dir",
            output_dir.as_posix(),
        ]
    )

    assert result == 0
    assert observed["binary_bytes"] == b"pe-windows-binary-executable"
    assert observed["metadata_bytes"] == b"windows-metadata-bytes"


def test_metadata_only_ios_pipeline_uses_platform_neutral_input_stage(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    config_file = tmp_path / "reforge.yaml"
    config_file.write_text('project_profile:\n  name: "generic-cpp"\n')
    metadata_dir = tmp_path / "Dump0"
    metadata_dir.mkdir()
    (metadata_dir / "script.json").write_text(
        '{"ScriptMethod": []}',
        encoding="utf-8",
    )
    (metadata_dir / "dump.cs").write_text(
        "// Image 0: Assembly-CSharp.dll\n// Image 1: Unity.Notifications.iOS.dll\n",
        encoding="utf-8",
    )
    target = AnalyzedTarget(
        class_name="Wallet",
        target="get_Coins",
        hook_type="return_override",
        return_value="999999",
        return_type="int32_t",
        confidence=90,
        reason="Synthetic test evidence",
    )
    monkeypatch.setattr(
        "reforge.cli.cmd_batch.cmd_batch",
        lambda _args: (0, [], [target]),
    )

    output_dir = tmp_path / "output"
    result = main(
        [
            "--config",
            config_file.as_posix(),
            "pipeline",
            "--metadata-dir",
            metadata_dir.as_posix(),
            "--goal",
            "give infinite coins",
            "--output-dir",
            output_dir.as_posix(),
            "--no-repack",
        ]
    )

    terminal = capsys.readouterr().out
    manifest = json.loads((output_dir / "pipeline_manifest.json").read_text(encoding="utf-8"))

    assert result == 0
    assert "Pathway 4/8: Unity IL2CPP (iOS)" in terminal
    assert "Preparing pathway-specific analysis inputs" in terminal
    assert "Hermes" not in terminal
    assert manifest["pathway"]["platform"] == "ios"
    assert any("Unity.Notifications.iOS.dll" in note for note in manifest["pathway"]["detection_notes"])
    assert (output_dir / "Hook_Goal.cpp").is_file()


def test_javascript_property_scan_skips_comments_strings_and_templates() -> None:
    source = """
// {"coins": 1}
const text = "{\\"coins\\": 2}";
const template = `{"coins": 3}`;
const state = {"coins": 4, "balance": true};
"""

    properties = _scan_js_primitive_properties(source)

    assert [(name, source[start:end]) for name, start, end in properties] == [
        ("coins", "4"),
        ("balance", "true"),
    ]


def test_hermes_candidate_occurrences_are_counted_once_per_property() -> None:
    source = 'const a = {"diamonds": 1}; const b = {"diamonds": 2}; const c = {"balance": true};'

    candidates = _discover_hermes_candidates(
        source,
        "grant unlimited diamonds",
        "index.android.bundle",
    )

    diamond = next(candidate for candidate in candidates if candidate.target == "diamonds")
    assert diamond.confidence == 84
    assert "2 syntax-aware occurrences" in diamond.reason


def test_hermes_replacement_follows_goal_and_recovered_literal_type() -> None:
    source = 'const state = {"mana": 3, "collisions": true, "proAccess": false};'

    mana = _discover_hermes_candidates(source, "grant unlimited mana", "index.android.bundle")
    collisions = _discover_hermes_candidates(source, "disable collisions", "index.android.bundle")
    access = _discover_hermes_candidates(source, "unlock pro access", "index.android.bundle")

    assert next(target for target in mana if target.target == "mana").return_value == "999999999"
    assert next(target for target in collisions if target.target == "collisions").return_value == "false"
    assert next(target for target in access if target.target == "proAccess").return_value == "true"


def test_hermes_ambiguous_or_null_mutation_stays_below_activation_threshold() -> None:
    source = 'const state = {"telemetry": true, "avatar": null};'

    telemetry = _discover_hermes_candidates(source, "inspect telemetry", "index.android.bundle")
    avatar = _discover_hermes_candidates(source, "enable avatar", "index.android.bundle")

    assert telemetry[0].return_value is None
    assert telemetry[0].confidence < 85
    assert avatar[0].return_value is None
    assert avatar[0].confidence < 85


def test_hermes_domain_expansions_and_ui_evidence_do_not_become_primary() -> None:
    source = (
        'const a = {"balance": 1}; '
        'const b = {"diamondBadge": true}; '
        'const c = {"application/vnd.example.balance": null};'
    )

    candidates = _discover_hermes_candidates(
        source,
        "grant unlimited diamonds",
        "index.android.bundle",
    )
    confidence = {candidate.target: candidate.confidence for candidate in candidates}

    assert confidence["balance"] == 78
    assert confidence["diamondBadge"] == 74
    assert confidence["application/vnd.example.balance"] == 40


def test_compiled_hermes_property_names_never_claim_activation_confidence() -> None:
    candidates = _discover_hermes_candidates(
        'r3 = {"subscriptions": null, "activeSubscriptions": null};',
        "unlock subscriptions",
        "assets/index.android.bundle",
        source_is_deployable=False,
    )

    assert candidates
    assert max(candidate.confidence for candidate in candidates) < 85
    assert all("analysis-only decompiler property" in candidate.reason.lower() for candidate in candidates)


def test_compiled_hermes_export_table_is_demoted_as_library_shape() -> None:
    source = (
        "const exports = {"
        '"__esModule": true, "subscriptions": null, "products": null, '
        '"purchases": null, "restore": null, "receipt": null, "billing": null, '
        '"entitlement": null, "listener": null, "status": null}; '
        "Object.defineProperty(exports, '__esModule', {value: true});"
    )

    candidates = _discover_hermes_candidates(
        source,
        "unlock subscriptions",
        "assets/index.android.bundle",
        source_is_deployable=False,
    )
    subscriptions = next(candidate for candidate in candidates if candidate.target == "subscriptions")

    assert subscriptions.confidence <= 48
    assert "export registry" in subscriptions.reason


def test_max_tier_goal_rejects_unrelated_framework_constants() -> None:
    candidates = _discover_hermes_candidates(
        'const limits = {"MAX": 1, "MAX_SAFE_INTEGER": 2}; '
        'const account = {"maxPlan": true, "subscriptionTier": "free"};',
        "unlock Pro and Max subscriptions",
        "assets/index.android.bundle",
        source_is_deployable=False,
    )
    names = {candidate.target for candidate in candidates}

    assert "maxPlan" in names
    assert "MAX" not in names
    assert "MAX_SAFE_INTEGER" not in names


def test_named_tier_hermes_noise_cannot_outrank_subscription_evidence() -> None:
    candidates = _discover_hermes_candidates(
        'const ui = {"maxHeight": 1, "isRedmiNote9Pro": false}; '
        'const account = {"subscriptions": null, "subscriptionMax": false, '
        '"subscriptionPro": false};',
        "unlock Pro and Max subscriptions",
        "assets/index.android.bundle",
        source_is_deployable=False,
    )
    by_name = {candidate.target: candidate for candidate in candidates}

    assert "maxHeight" not in by_name
    assert "isRedmiNote9Pro" not in by_name
    assert by_name["subscriptions"].confidence >= by_name["subscriptionMax"].confidence
    assert by_name["subscriptions"].confidence >= by_name["subscriptionPro"].confidence


def test_hermes_candidate_evidence_is_bounded_and_located(tmp_path: Path) -> None:
    source = """\
_fun42: for(var _fun42_ip = 0; ; ) switch(_fun42_ip) {
case 0:
    r3 = {"subscriptions": null};
}
"""
    candidate = AnalyzedTarget(
        class_name="HermesBundle",
        target="subscriptions",
        hook_type="js_property_patch",
        confidence=74,
        reason="Analysis-only test evidence",
    )

    evidence = _write_hermes_candidate_evidence(tmp_path, source, [candidate])
    report = evidence.read_text(encoding="utf-8")

    assert "line 3" in report
    assert "_fun42" in report
    assert '"subscriptions"' in report
    assert len(report) < 2_000


def test_textual_bundle_patch_is_unambiguous_and_preserves_newlines(tmp_path: Path) -> None:
    bundle = tmp_path / "index.android.bundle"
    bundle.write_bytes(b'// {"coins": 1}\r\nconst state = {"coins": 4};\r\n')
    target = AnalyzedTarget(
        class_name="HermesBundle",
        target="coins",
        hook_type="js_property_patch",
        return_value="999",
        confidence=95,
    )

    modified, notes = _patch_textual_bundle(bundle, [target], tmp_path, 1)

    assert modified is not None
    assert modified.read_bytes() == b'// {"coins": 1}\r\nconst state = {"coins": 999};\r\n'
    assert any("Patched coins" in note for note in notes)


def test_textual_bundle_patch_rejects_duplicate_property(tmp_path: Path) -> None:
    bundle = tmp_path / "main.jsbundle"
    bundle.write_text('const a = {"coins": 1}; const b = {"coins": 2};', encoding="utf-8")
    target = AnalyzedTarget(
        class_name="HermesBundle",
        target="coins",
        hook_type="js_property_patch",
        return_value="999",
        confidence=95,
    )

    modified, notes = _patch_textual_bundle(bundle, [target], tmp_path, 1)

    assert modified is None
    assert any("found 2" in note for note in notes)


def test_textual_bundle_patch_rejects_cross_type_replacement(tmp_path: Path) -> None:
    bundle = tmp_path / "main.jsbundle"
    bundle.write_text('const state = {"telemetry": true};', encoding="utf-8")
    target = AnalyzedTarget(
        class_name="HermesBundle",
        target="telemetry",
        hook_type="js_property_patch",
        return_value="999",
        confidence=95,
    )

    modified, notes = _patch_textual_bundle(bundle, [target], tmp_path, 1)

    assert modified is None
    assert any("does not match" in note for note in notes)


def test_android_repackage_never_reuses_stale_signer_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("assets/index.android.bundle", b'const x = {"coins": 1};')
    architecture = detect_architecture_from_path(apk)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    stale = output_dir / "modded_app-aligned-signed.apk"
    stale.write_bytes(b"stale")
    signer = tmp_path / "signer.jar"
    signer.write_bytes(b"jar")
    modified = tmp_path / "modified_index.android.bundle"
    modified.write_bytes(b'const x = {"coins": 999};')

    def fake_tool(command, *, cwd=None):
        if "apktool" in command[0] and "d" in command:
            Path(command[command.index("-o") + 1]).mkdir(parents=True)
        elif "apktool" in command[0] and "b" in command:
            unsigned = Path(command[command.index("-o") + 1])
            with zipfile.ZipFile(unsigned, "w") as archive:
                archive.writestr(
                    "assets/index.android.bundle",
                    modified.read_bytes(),
                )
        return True, ""

    monkeypatch.setattr("reforge.cli.cmd_pipeline._find_apktool", lambda: "apktool")
    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline.shutil.which",
        lambda name: "java" if name == "java" else None,
    )
    monkeypatch.setattr("reforge.cli.cmd_pipeline._run_tool", fake_tool)
    monkeypatch.setenv("REFORGE_APK_SIGNER_JAR", signer.as_posix())

    success, detail = _repackage_android(
        apk,
        output_dir,
        architecture,
        [],
        modified,
    )

    assert success is False
    assert "no fresh signed APK" in detail
    assert stale.read_bytes() == b"stale"


def test_android_asset_repackage_does_not_require_apktool(
    tmp_path: Path,
    monkeypatch,
) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("assets/index.android.bundle", b'const x = {"coins": 1};')
    architecture = detect_architecture_from_path(apk)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    signer = tmp_path / "signer.jar"
    signer.write_bytes(b"jar")
    modified = tmp_path / "modified_index.android.bundle"
    modified.write_bytes(b'const x = {"coins": 999};')
    verified: list[Path] = []
    commands: list[list[str]] = []

    def fake_tool(command, *, cwd=None):
        del cwd
        commands.append(command)
        if command[0] == "java" and "--onlyVerify" not in command:
            unsigned = Path(command[command.index("--apks") + 1])
            signed = unsigned.with_name("modded_app-aligned-signed.apk")
            signed.write_bytes(unsigned.read_bytes())
        elif command[0] == "java" and "--onlyVerify" in command:
            verified.append(Path(command[command.index("--apks") + 1]))
        return True, "verified"

    monkeypatch.setattr("reforge.cli.cmd_pipeline._find_apktool", lambda: None)
    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline.shutil.which",
        lambda name: "java" if name == "java" else None,
    )
    monkeypatch.setattr("reforge.cli.cmd_pipeline._run_tool", fake_tool)
    monkeypatch.setenv("REFORGE_APK_SIGNER_JAR", signer.as_posix())

    success, detail = _repackage_android(
        apk,
        output_dir,
        architecture,
        [],
        modified,
    )

    assert success is True
    assert Path(detail).is_file()
    assert verified and verified[0].name == "modded_app-aligned-signed.apk"
    assert not any("apktool" in command[0] for command in commands)
    with zipfile.ZipFile(detail) as archive:
        assert archive.read("AndroidManifest.xml") == b"manifest"
        assert archive.read("assets/index.android.bundle") == modified.read_bytes()


def test_android_split_set_is_resigned_verified_and_packaged_together(
    tmp_path: Path,
    monkeypatch,
) -> None:
    apk = tmp_path / "base.apk"
    split = tmp_path / "split_config.en.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("assets/index.android.bundle", b'const x = {"coins": 1};')
    with zipfile.ZipFile(split, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("resources.arsc", b"resources")
    architecture = detect_architecture_from_path(apk)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    signer = tmp_path / "signer.jar"
    signer.write_bytes(b"jar")
    modified = tmp_path / "modified_index.android.bundle"
    modified.write_bytes(b'const x = {"coins": 999};')

    def fake_tool(command, *, cwd=None):
        del cwd
        if command[0] == "java" and "--onlyVerify" not in command:
            source_dir = Path(command[command.index("--apks") + 1])
            signed_dir = Path(command[command.index("--out") + 1])
            signed_dir.mkdir(parents=True)
            for source in source_dir.glob("*.apk"):
                destination = signed_dir / f"{source.stem}-aligned-debugSigned.apk"
                destination.write_bytes(source.read_bytes())
        return True, "verified"

    monkeypatch.setattr("reforge.cli.cmd_pipeline._find_apktool", lambda: None)
    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline.shutil.which",
        lambda name: "java" if name == "java" else None,
    )
    monkeypatch.setattr("reforge.cli.cmd_pipeline._run_tool", fake_tool)
    monkeypatch.setenv("REFORGE_APK_SIGNER_JAR", signer.as_posix())

    success, detail = _repackage_android(
        apk,
        output_dir,
        architecture,
        [],
        modified,
        split_apks=(split,),
        installer_package="com.example.installer",
    )

    assert success is True
    packaged = Path(detail)
    assert packaged.name == "modded_split_apks.zip"
    with zipfile.ZipFile(packaged) as archive:
        assert {name for name in archive.namelist() if name.endswith(".apk")} == {
            "base.apk",
            "split-001.apk",
        }
        with zipfile.ZipFile(io.BytesIO(archive.read("base.apk"))) as signed_base:
            assert signed_base.read("assets/index.android.bundle") == modified.read_bytes()
        notes = archive.read("INSTALL_SPLIT_APKS.txt").decode("utf-8")
        assert "com.example.installer" in notes


def test_android_repackage_embeds_and_verifies_explicit_gadget(
    tmp_path: Path,
    monkeypatch,
) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"binary-manifest-placeholder")
        archive.writestr("lib/arm64-v8a/libgame.so", b"game")
    architecture = detect_architecture_from_path(apk)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    signer = tmp_path / "signer.jar"
    signer.write_bytes(b"jar")
    gadget = tmp_path / "frida-gadget.so"
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4:7] = b"\x02\x01\x01"
    struct.pack_into("<H", header, 16, 3)
    struct.pack_into("<H", header, 18, 183)
    gadget.write_bytes(bytes(header) + b"GADGET")

    def fake_tool(command, *, cwd=None):
        del cwd
        if "apktool" in command[0] and "d" in command:
            decoded = Path(command[command.index("-o") + 1])
            (decoded / "lib" / "arm64-v8a").mkdir(parents=True)
            (decoded / "AndroidManifest.xml").write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.example.game"><application /></manifest>',
                encoding="utf-8",
            )
        elif "apktool" in command[0] and "b" in command:
            decoded = Path(command[2])
            unsigned = Path(command[command.index("-o") + 1])
            with zipfile.ZipFile(unsigned, "w") as archive:
                for path in sorted(decoded.rglob("*")):
                    if path.is_file():
                        archive.write(path, path.relative_to(decoded).as_posix())
                archive.writestr("classes.dex", b"dex\n035\x00" + GADGET_LOADER_DESCRIPTOR)
        elif command[0] == "java" and "--onlyVerify" not in command:
            unsigned = Path(command[command.index("--apks") + 1])
            signed = unsigned.with_name("modded_app-aligned-signed.apk")
            signed.write_bytes(unsigned.read_bytes())
        return True, "verified"

    monkeypatch.setattr("reforge.cli.cmd_pipeline._find_apktool", lambda: "apktool")
    monkeypatch.setattr(
        "reforge.cli.cmd_pipeline.shutil.which",
        lambda name: "java" if name == "java" else None,
    )
    monkeypatch.setattr("reforge.cli.cmd_pipeline._run_tool", fake_tool)
    monkeypatch.setenv("REFORGE_APK_SIGNER_JAR", signer.as_posix())

    success, detail = _repackage_android(
        apk,
        output_dir,
        architecture,
        [],
        None,
        gadget_path=gadget,
        gadget_on_load="resume",
        gadget_port=28042,
        gadget_version="17.15.2",
    )

    assert success is True
    assert Path(detail).is_file()
    assert (output_dir / "FRIDA_GADGET_NOTES.txt").is_file()
    with zipfile.ZipFile(detail) as archive:
        assert "lib/arm64-v8a/libreforge-gadget.so" in archive.namelist()
        assert "assets/reforge/frida-gadget-manifest.json" in archive.namelist()
