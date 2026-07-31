"""Unit tests for 1-click automated pipeline CLI command."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from re_agent.cli.cmd_pipeline import (
    _discover_hermes_candidates,
    _patch_textual_bundle,
    _repackage_android,
    _scan_js_primitive_properties,
)
from re_agent.cli.main import main
from re_agent.core.engine_detector import detect_architecture_from_path
from re_agent.llm.analyzed_target import AnalyzedTarget


def test_cmd_pipeline_generic_binary(tmp_path: Path) -> None:
    config_file = tmp_path / "re-agent.yaml"
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


def test_cmd_pipeline_uses_desktop_app_output_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "re-agent.yaml"
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
        "re_agent.cli.cmd_pipeline.default_pipeline_output_dir",
        lambda _path: output_dir,
    )
    monkeypatch.setattr(
        "re_agent.cli.cmd_batch.cmd_batch",
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
    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text("""
project_profile:
  name: "react-native"
""")

    apk_path = tmp_path / "react_app.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("assets/index.android.bundle", b'var state = {"subscription": false};')
        z.writestr("classes.dex", b"fake_dex_bytes")

    monkeypatch.setattr(
        "re_agent.cli.cmd_batch.cmd_batch",
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
    manifest = json.loads(
        (out_dir / "pipeline_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["capabilities"]["analysis_complete"] is True
    assert manifest["capabilities"]["runtime_hook_installed"] is False
    assert manifest["capabilities"]["runtime_behavior_verified"] is False


def test_pipeline_stops_before_packaging_when_all_candidates_are_review_only(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text('project_profile:\n  name: "react-native"\n')
    apk_path = tmp_path / "review-only.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "assets/index.android.bundle",
            b'const state = {"balance": 1};',
        )
    monkeypatch.setattr(
        "re_agent.cli.cmd_batch.cmd_batch",
        lambda _args: (0, [], []),
    )

    def fail_if_prompted(*_args, **_kwargs):
        raise AssertionError("review-only analysis must not offer packaging")

    monkeypatch.setattr(
        "re_agent.cli.cmd_pipeline._repack_choice",
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
    manifest = json.loads(
        (output_dir / "pipeline_manifest.json").read_text(encoding="utf-8")
    )
    discovery = next(
        stage for stage in manifest["stages"] if stage["name"] == "candidate_discovery"
    )
    packaging = next(
        stage for stage in manifest["stages"] if stage["name"] == "packaging"
    )

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
    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text('project_profile:\n  name: "react-native"\n')
    apk_path = tmp_path / "patchable.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "assets/index.android.bundle",
            b'const state = {"coins": 1};',
        )
    monkeypatch.setattr(
        "re_agent.cli.cmd_batch.cmd_batch",
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
    ):
        observed["modified_bytes"] = modified_bundle.read_bytes()
        signed = output_dir / "modded_app-aligned-signed.apk"
        signed.write_bytes(b"signed")
        return True, str(signed)

    monkeypatch.setattr(
        "re_agent.cli.cmd_pipeline._repack_choice",
        choose_repack,
    )
    monkeypatch.setattr(
        "re_agent.cli.cmd_pipeline._repackage_android",
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
    manifest = json.loads(
        (output_dir / "pipeline_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["capabilities"]["static_patch_created"] is True
    assert manifest["capabilities"]["package_artifact"].endswith(
        "modded_app-aligned-signed.apk"
    )


def test_cmd_pipeline_ios_hermes_bundle_and_deployment_notes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text('project_profile:\n  name: "ios-arm64"\n')
    ipa_path = tmp_path / "react_ios.ipa"
    with zipfile.ZipFile(ipa_path, "w") as archive:
        archive.writestr(
            "Payload/Target.app/main.jsbundle",
            b'var state = {"diamonds": 10, "balance": 1};',
        )

    monkeypatch.setattr(
        "re_agent.cli.cmd_batch.cmd_batch",
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


def test_pipeline_fails_when_requested_static_patch_is_ambiguous(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text('project_profile:\n  name: "react-native"\n')
    apk_path = tmp_path / "duplicate.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "assets/index.android.bundle",
            b'const a = {"coins": 1}; const b = {"coins": 2};',
        )
    monkeypatch.setattr(
        "re_agent.cli.cmd_batch.cmd_batch",
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
    manifest = json.loads(
        (output_dir / "pipeline_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["exit_code"] == 4
    assert manifest["capabilities"]["static_patch_created"] is False
    patch_stage = next(
        stage for stage in manifest["stages"] if stage["name"] == "static_patch"
    )
    assert patch_stage["status"] == "FAILED"


def test_cmd_pipeline_unity_package_runs_explicit_dumper_and_uses_sidecars(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "re-agent.yaml"
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
        "re_agent.core.il2cpp_parser.run_il2cpp_dumper_cli",
        fake_dumper,
    )
    monkeypatch.setattr("re_agent.cli.cmd_batch.cmd_batch", fake_batch)

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
    assert observed["dumper_path"] == dumper_path.as_posix()
    assert Path(str(observed["metadata_dir"])).name == "il2cpp_dumper_output"
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
    source = (
        'const a = {"diamonds": 1}; '
        'const b = {"diamonds": 2}; '
        'const c = {"balance": true};'
    )

    candidates = _discover_hermes_candidates(
        source,
        "grant unlimited diamonds",
        "index.android.bundle",
    )

    diamond = next(candidate for candidate in candidates if candidate.target == "diamonds")
    assert diamond.confidence == 84
    assert "2 syntax-aware occurrences" in diamond.reason


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


def test_textual_bundle_patch_is_unambiguous_and_preserves_newlines(tmp_path: Path) -> None:
    bundle = tmp_path / "index.android.bundle"
    bundle.write_bytes(b'// {\"coins\": 1}\r\nconst state = {\"coins\": 4};\r\n')
    target = AnalyzedTarget(
        class_name="HermesBundle",
        target="coins",
        hook_type="js_property_patch",
        return_value="999",
        confidence=95,
    )

    modified, notes = _patch_textual_bundle(bundle, [target], tmp_path, 1)

    assert modified is not None
    assert modified.read_bytes() == b'// {\"coins\": 1}\r\nconst state = {\"coins\": 999};\r\n'
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

    monkeypatch.setattr("re_agent.cli.cmd_pipeline._find_apktool", lambda: "apktool")
    monkeypatch.setattr(
        "re_agent.cli.cmd_pipeline.shutil.which",
        lambda name: "java" if name == "java" else None,
    )
    monkeypatch.setattr("re_agent.cli.cmd_pipeline._run_tool", fake_tool)
    monkeypatch.setenv("RE_AGENT_APK_SIGNER_JAR", signer.as_posix())

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


def test_android_repackage_verifies_fresh_signature_and_bundle(
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

    def fake_tool(command, *, cwd=None):
        del cwd
        if "apktool" in command[0] and "d" in command:
            decoded = Path(command[command.index("-o") + 1])
            (decoded / "assets").mkdir(parents=True)
        elif "apktool" in command[0] and "b" in command:
            unsigned = Path(command[command.index("-o") + 1])
            with zipfile.ZipFile(unsigned, "w") as archive:
                archive.writestr("assets/index.android.bundle", modified.read_bytes())
        elif command[0] == "java" and "--onlyVerify" not in command:
            unsigned = Path(command[command.index("--apks") + 1])
            signed = unsigned.with_name("modded_app-aligned-signed.apk")
            with zipfile.ZipFile(signed, "w") as archive:
                archive.writestr("assets/index.android.bundle", modified.read_bytes())
        elif command[0] == "java" and "--onlyVerify" in command:
            verified.append(Path(command[command.index("--apks") + 1]))
        return True, "verified"

    monkeypatch.setattr("re_agent.cli.cmd_pipeline._find_apktool", lambda: "apktool")
    monkeypatch.setattr(
        "re_agent.cli.cmd_pipeline.shutil.which",
        lambda name: "java" if name == "java" else None,
    )
    monkeypatch.setattr("re_agent.cli.cmd_pipeline._run_tool", fake_tool)
    monkeypatch.setenv("RE_AGENT_APK_SIGNER_JAR", signer.as_posix())

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
