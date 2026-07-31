"""Unit tests for re-agent hook CLI command."""

from __future__ import annotations

from pathlib import Path

from re_agent.cli.main import main


def test_cmd_hook_ios(tmp_path: Path) -> None:
    hook_file = tmp_path / "Hook_Test.mm"
    args = [
        "hook",
        "--address",
        "0x1000",
        "--symbol",
        "UpdateHealth",
        "--platform",
        "ios-arm64",
        "--output",
        hook_file.as_posix(),
    ]
    out = main(args)
    assert out == 0
    assert hook_file.exists()
    content = hook_file.read_text(encoding="utf-8")
    assert "MobileSubstrate" in content
    assert "UpdateHealth" in content


def test_cmd_hook_android(tmp_path: Path) -> None:
    hook_file = tmp_path / "Hook_Android.cpp"
    args = [
        "hook",
        "--address",
        "0x2000",
        "--symbol",
        "GetLevel",
        "--platform",
        "android-arm64",
        "--output",
        hook_file.as_posix(),
    ]
    out = main(args)
    assert out == 0
    assert hook_file.exists()
    content = hook_file.read_text(encoding="utf-8")
    assert "ReAgentHook" in content


def test_cmd_hook_rust(tmp_path: Path) -> None:
    hook_file = tmp_path / "Hook_Rust.rs"
    args = [
        "hook",
        "--address",
        "0x3000",
        "--symbol",
        "PlayerUpdate",
        "--language",
        "rust",
        "--output",
        hook_file.as_posix(),
    ]
    out = main(args)
    assert out == 0
    assert hook_file.exists()
    content = hook_file.read_text(encoding="utf-8")
    assert "cydia-substrate-rs" in content
    assert "MSHookFunction" in content


def test_cmd_hook_sanitizes_complex_symbols() -> None:
    from re_agent.cli.cmd_hook import generate_universal_hook_for_goal
    from re_agent.llm.analyzed_target import AnalyzedTarget

    complex_target = AnalyzedTarget(
        target="GetItem<int>$Inner[0]",
        class_name="com.game.UI::Store$Dialog",
        hook_type="return_override",
        return_value="999999",
        confidence=90,
        reason="Complex symbol test",
    )

    hook_code = generate_universal_hook_for_goal("test goal", analyzed_targets=[complex_target])
    assert "com_game_UI_Store_Dialog_GetItem_int_Inner_0" in hook_code
    assert "999999" in hook_code


def test_generate_universal_hook_types() -> None:
    from re_agent.cli.cmd_hook import generate_universal_hook_for_goal
    from re_agent.llm.analyzed_target import AnalyzedTarget

    targets = [
        AnalyzedTarget("WalletModel", "GetCurrency", hook_type="return_override", return_value="999999999"),
        AnalyzedTarget("WalletOnRunModel", "Coins", offset=0x30, hook_type="memory_patch", return_value="999999"),
        AnalyzedTarget(
            "CharacterMotor",
            "CheckCollision",
            hook_type="skip_call",
            return_type="bool",
            return_value="false",
        ),
        AnalyzedTarget("PlayerTransform", "GetPosition", hook_type="esp_overlay"),
        AnalyzedTarget("TimeManager", "GetDeltaTime", hook_type="speed_modify", return_value="3.0f"),
        AnalyzedTarget("AntiCheatManager", "ValidateIntegrity", hook_type="nop"),
    ]

    code = generate_universal_hook_for_goal("test goal", analyzed_targets=targets)
    assert "hk_WalletModel_GetCurrency" in code
    assert "return 999999999;" in code
    assert "*(int32_t*)((uintptr_t)self + 0x30) = 999999;" in code
    assert "return false; // Skipped by re-agent" in code
    assert "WorldToScreen" in code
    assert "* 3.0f; // Speed multiplied by re-agent" in code
    assert "Function disabled by re-agent" in code


def test_generate_universal_hook_keeps_all_multi_field_offsets() -> None:
    from re_agent.cli.cmd_hook import generate_universal_hook_for_goal
    from re_agent.llm.analyzed_target import AnalyzedTarget

    targets = [
        AnalyzedTarget(
            "Wallet",
            "Coins",
            offset=0x10,
            hook_type="memory_patch",
            confidence=95,
        ),
        AnalyzedTarget(
            "Wallet",
            "Gems",
            offset=0x20,
            hook_type="memory_patch",
            confidence=90,
        ),
    ]
    code = generate_universal_hook_for_goal("unlimited currency", analyzed_targets=targets)
    assert "+ 0x10" in code
    assert "+ 0x20" in code


def test_universal_hook_bounds_review_candidates() -> None:
    from re_agent.cli.cmd_hook import (
        MAX_REVIEW_HOOK_CANDIDATES,
        generate_universal_hook_for_goal,
    )
    from re_agent.llm.analyzed_target import AnalyzedTarget

    targets = [
        AnalyzedTarget(
            "WalletModel" if index == 0 else f"Candidate{index}",
            "GetCurrency" if index == 0 else f"GetValue{index}",
            confidence=95 - min(index, 20),
            reason="Review candidate",
        )
        for index in range(100)
    ]

    code = generate_universal_hook_for_goal(
        "give infinite coins and keys",
        analyzed_targets=targets,
    )

    assert "WalletModel::GetCurrency" in code
    assert (
        f"Emitting {MAX_REVIEW_HOOK_CANDIDATES} of {len(targets)} "
        "review candidates."
    ) in code
    assert "80 additional review candidates" in code
    assert "Candidate99::GetValue99" not in code
    assert len(code) < 100_000


def test_mixed_confidence_fields_do_not_share_activation() -> None:
    from re_agent.cli.cmd_hook import generate_universal_hook_for_goal
    from re_agent.llm.analyzed_target import AnalyzedTarget

    targets = [
        AnalyzedTarget(
            "Wallet",
            "Coins",
            offset=0x10,
            hook_type="memory_patch",
            confidence=95,
            signature_verified=True,
            address_verified=True,
            implementation_ready=True,
        ),
        AnalyzedTarget(
            "Wallet",
            "DebugCoins",
            offset=0x20,
            hook_type="memory_patch",
            confidence=10,
            signature_verified=True,
            address_verified=True,
            implementation_ready=True,
        ),
    ]

    code = generate_universal_hook_for_goal(
        "unlimited currency",
        analyzed_targets=targets,
    )
    active, review = code.split("// TARGET GROUP B", maxsplit=1)

    assert "+ 0x10" in active
    assert "+ 0x20" not in active
    assert "+ 0x20" in review


def test_unresolved_field_offset_is_never_active() -> None:
    from re_agent.cli.cmd_hook import generate_universal_hook_for_goal
    from re_agent.llm.analyzed_target import AnalyzedTarget

    target = AnalyzedTarget(
        "Wallet",
        "Coins",
        hook_type="memory_patch",
        confidence=99,
        signature_verified=True,
        address_verified=True,
        implementation_ready=True,
    )

    code = generate_universal_hook_for_goal(
        "unlimited coins",
        analyzed_targets=[target],
    )
    active, review = code.split("// TARGET GROUP B", maxsplit=1)

    assert "Wallet::Coins" not in active
    assert "Wallet::Coins" in review
    assert "no verified field offset" in review


def test_il2cpp_activation_requires_all_readiness_evidence() -> None:
    from re_agent.cli.cmd_hook import generate_universal_hook_for_goal
    from re_agent.llm.analyzed_target import AnalyzedTarget

    verified = AnalyzedTarget(
        "Wallet",
        "GetCoins",
        hook_type="return_override",
        confidence=95,
        signature_verified=True,
        address_verified=True,
        implementation_ready=True,
    )
    unverified = AnalyzedTarget(
        "Wallet",
        "GetGems",
        hook_type="return_override",
        confidence=99,
    )

    code = generate_universal_hook_for_goal(
        "unlimited currency",
        analyzed_targets=[verified, unverified],
    )
    active, review = code.split("// TARGET GROUP B", maxsplit=1)

    assert "Wallet::GetCoins" in active
    assert "Wallet::GetGems" not in active
    assert "Wallet::GetGems" in review


def test_hook_generation_has_no_implicit_file_write(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from re_agent.cli.cmd_hook import generate_universal_hook_for_goal
    from re_agent.llm.analyzed_target import AnalyzedTarget

    monkeypatch.chdir(tmp_path)
    generate_universal_hook_for_goal(
        "coins",
        analyzed_targets=[AnalyzedTarget("Wallet", "Coins", confidence=95)],
    )
    assert not (tmp_path / "output" / "Hook_Frida.js").exists()


def test_frida_output_has_modular_primary_and_secondary_groups() -> None:
    from re_agent.cli.cmd_hook import generate_frida_java_script
    from re_agent.llm.analyzed_target import AnalyzedTarget

    targets = [
        AnalyzedTarget("Wallet", "GetCoins", confidence=95),
        AnalyzedTarget("Wallet", "GetGems", confidence=80),
    ]
    code = generate_frida_java_script("unlimited currency", targets)
    assert "TARGET GROUP A (VERIFIED ACTIVE TARGETS" in code
    assert "[95%] Wallet::GetCoins" in code
    assert "TARGET GROUP B (REVIEW-ONLY / UNVERIFIED" in code
    assert "[80%] Wallet::GetGems" in code


def test_frida_dex_uses_exact_recovered_overload() -> None:
    from re_agent.cli.cmd_hook import generate_frida_java_script
    from re_agent.llm.analyzed_target import AnalyzedTarget

    target = AnalyzedTarget(
        "com.game.Wallet",
        "getCoins",
        confidence=95,
        parameter_types=("int", "java.lang.String"),
        method_descriptor="(ILjava/lang/String;)I",
        signature_verified=True,
        address_verified=True,
        implementation_ready=True,
    )

    code = generate_frida_java_script(
        "unlimited coins",
        [target],
        pathway="android-java-kotlin-dex",
    )

    assert '.overload("int", "java.lang.String")' in code
    assert "overload.implementation = function" in code
    assert "return 999999999;" in code


def test_frida_hybrid_hermes_path_activates_verified_dex_overload() -> None:
    from re_agent.cli.cmd_hook import generate_frida_java_script
    from re_agent.llm.analyzed_target import AnalyzedTarget

    target = AnalyzedTarget(
        "com.game.Wallet",
        "getCoins",
        confidence=95,
        parameter_types=(),
        method_descriptor="()I",
        signature_verified=True,
        address_verified=True,
        implementation_ready=True,
    )

    code = generate_frida_java_script(
        "unlimited coins",
        [target],
        pathway="react-native-hermes-android",
    )
    active, review = code.split("// TARGET GROUP B", maxsplit=1)

    assert "com.game.Wallet::getCoins" in active
    assert 'TargetClass["getCoins"].overload()' in active
    assert "overload.implementation = function" in active
    assert "com.game.Wallet::getCoins" not in review


def test_frida_keeps_unverified_and_hermes_scaffolds_review_only() -> None:
    from re_agent.cli.cmd_hook import generate_frida_java_script
    from re_agent.llm.analyzed_target import AnalyzedTarget

    unverified = AnalyzedTarget(
        "com.game.Wallet",
        "getCoins",
        confidence=99,
        method_descriptor="()I",
    )
    java_code = generate_frida_java_script(
        "unlimited coins",
        [unverified],
        pathway="android-java-kotlin-dex",
    )
    java_active, java_review = java_code.split(
        "// TARGET GROUP B",
        maxsplit=1,
    )
    assert "com.game.Wallet::getCoins" not in java_active
    assert "com.game.Wallet::getCoins" in java_review

    hermes = AnalyzedTarget(
        "HermesBundle",
        "coins",
        hook_type="js_property_patch",
        confidence=99,
        signature_verified=True,
        address_verified=True,
        implementation_ready=True,
    )
    hermes_code = generate_frida_java_script(
        "unlimited coins",
        [hermes],
        pathway="react-native-hermes-android",
    )
    hermes_active, hermes_review = hermes_code.split(
        "// TARGET GROUP B",
        maxsplit=1,
    )
    assert "HermesBundle::coins" not in hermes_active
    assert "HermesBundle::coins" in hermes_review


def test_native_todo_scaffold_is_review_only_even_with_readiness_flags() -> None:
    from re_agent.cli.cmd_hook import generate_cpp_hook_for_pathway
    from re_agent.llm.analyzed_target import AnalyzedTarget

    target = AnalyzedTarget(
        "libgame.so",
        "GetCoins",
        confidence=99,
        method_rva=0x1234,
        signature_verified=True,
        address_verified=True,
        implementation_ready=True,
    )
    code = generate_cpp_hook_for_pathway(
        "unlimited coins",
        [target],
        pathway="native-cpp-unreal-flutter",
    )
    active, review = code.split("// TARGET GROUP B", maxsplit=1)

    assert "libgame.so::GetCoins" not in active
    assert "libgame.so::GetCoins" in review


def test_frida_il2cpp_uses_only_typed_method_rvas_as_code_addresses() -> None:
    from re_agent.cli.cmd_hook import generate_frida_java_script
    from re_agent.llm.analyzed_target import AnalyzedTarget

    method = AnalyzedTarget(
        "Wallet",
        "GetCoins",
        confidence=95,
        method_rva=0x1234,
    )
    field = AnalyzedTarget(
        "Wallet",
        "coins",
        offset=0x18,
        hook_type="memory_patch",
        confidence=90,
    )

    code = generate_frida_java_script(
        "unlimited coins",
        [method, field],
        pathway="unity-il2cpp-android",
    )

    assert 'Process.getModuleByName("libil2cpp.so")' in code
    assert "module.base.add(0x1234)" in code
    assert "module.base.add(0x18)" not in code


def test_esp_helper_is_emitted_once_with_matching_signature() -> None:
    from re_agent.cli.cmd_hook import generate_universal_hook_for_goal
    from re_agent.llm.analyzed_target import AnalyzedTarget

    targets = [
        AnalyzedTarget("Player", "Position", hook_type="esp_overlay", confidence=95),
        AnalyzedTarget("Enemy", "Position", hook_type="esp_overlay", confidence=90),
    ]
    code = generate_universal_hook_for_goal("esp", analyzed_targets=targets)
    assert code.count("struct Vector2 { float x, y; };") == 1
    assert "WorldToScreen(worldPos, viewMatrix, screenW, screenH, screenPos)" in code
