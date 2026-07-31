"""Unit tests for re-agent batch CLI command."""

from __future__ import annotations

from pathlib import Path

from re_agent.cli.main import main


def test_cmd_batch_auto_discover(tmp_path: Path) -> None:
    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text(f"""
project_profile:
  name: "ios-arm64"
  language_standard: "C++20"
  source_root: "{tmp_path.as_posix()}/src"
""")

    out_dir = (tmp_path / "src").as_posix()
    args = ["--config", config_file.as_posix(), "batch", "--auto-discover", "--output-dir", out_dir]
    out = main(args)
    assert out == 3
    assert not (tmp_path / "src" / "ReconstructedModule.h").exists()
    assert not (tmp_path / "src" / "ReconstructedModule.cpp").exists()


def test_cmd_batch_symbol(tmp_path: Path) -> None:
    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text(f"""
project_profile:
  name: "generic-cpp"
  source_root: "{tmp_path.as_posix()}/src"
""")

    out_dir = (tmp_path / "src").as_posix()
    args = [
        "--config",
        config_file.as_posix(),
        "batch",
        "--symbol",
        "GetLevel",
        "--class",
        "Player",
        "--output-dir",
        out_dir,
    ]
    out = main(args)
    assert out == 3
    assert not (tmp_path / "src" / "Player.h").exists()


def test_resolve_goal_keywords_clean() -> None:
    from re_agent.cli.cmd_batch import _match_keyword, resolve_goal_keywords

    keywords = resolve_goal_keywords("avoid hitting obstacles")
    assert "obstacles" in keywords or "hitting" in keywords
    assert resolve_goal_keywords("grant unlimited") == []
    assert _match_keyword("pro", "ProcessManager") is False
    assert _match_keyword("key", "KeyboardController") is False
    assert _match_keyword("currency", "PlayerCurrencyManager") is True


def test_known_domain_goal_does_not_spend_an_llm_call() -> None:
    from re_agent.cli.cmd_batch import resolve_goal_keywords

    class FailIfCalled:
        def send(self, _messages, **_kwargs):
            raise AssertionError("known domain expansion must remain local")

    keywords = resolve_goal_keywords(
        "grant unlimited diamonds",
        provider=FailIfCalled(),
    )

    assert "diamonds" in keywords
    assert "wallet" in keywords


def test_rank_classes_by_relevance_wrapper_penalty() -> None:
    from re_agent.cli.cmd_batch import rank_classes_by_relevance

    candidates = [
        ("ThemeEffectCollision", [{"name": "OnHit"}], []),
        ("CharacterCollision", [{"name": "OnHit"}], []),
    ]
    keywords = ["collision", "character"]
    ranked = rank_classes_by_relevance(candidates, keywords)

    # CharacterCollision should rank higher than ThemeEffectCollision due to wrapper penalty on Theme/Effect
    top_class = ranked[0][0]
    assert top_class == "CharacterCollision"


def test_currency_ranking_rejects_framework_keys_and_prefers_wallet() -> None:
    from re_agent.cli.cmd_batch import (
        _match_candidate_keyword,
        rank_classes_by_relevance,
    )

    candidates = [
        (
            "AesCng",
            [{"method_name": "get_Key", "return_type": "int"}],
            [],
        ),
        (
            "Dictionary",
            [{"method_name": "get_Keys", "return_type": "int"}],
            [],
        ),
        (
            "WalletModel",
            [{"method_name": "GetCurrency", "return_type": "int"}],
            [],
        ),
        (
            "CoreRunnerManager",
            [{"method_name": "GetAvailableKeysForUse", "return_type": "int"}],
            [],
        ),
    ]

    ranked = rank_classes_by_relevance(
        candidates,
        ["keys", "currency", "wallet"],
        direct_keywords=["keys"],
    )

    assert ranked[0][0] == "WalletModel"
    assert _match_candidate_keyword("keys", "AesCng", "get_Key") is False
    assert _match_candidate_keyword("keys", "Dictionary", "get_Keys") is False
    assert (
        _match_candidate_keyword(
            "keys",
            "KeyPairPersistence",
            "get_UseDefaultKeyContainer",
        )
        is False
    )
    assert (
        _match_candidate_keyword(
            "keys",
            "CoreRunnerManager",
            "GetAvailableKeysForUse",
        )
        is True
    )


def test_scalar_currency_field_filter_rejects_delegates_and_collections() -> None:
    from re_agent.cli.cmd_batch import _is_scalar_currency_field_type

    assert _is_scalar_currency_field_type("int")
    assert _is_scalar_currency_field_type("SafeInt")
    assert not _is_scalar_currency_field_type("Action<Currency, int>")
    assert not _is_scalar_currency_field_type("Dictionary<CurrencyType, int>")
    assert not _is_scalar_currency_field_type("string")


def test_dump_merge_keeps_rva_signature_and_overloads() -> None:
    from re_agent.cli.cmd_batch import _merge_dump_method_evidence

    script_methods = [
        {"method_name": "GetCurrency", "signature": "native-one"},
        {"method_name": "GetCurrency", "signature": "native-two"},
    ]
    dump_methods = [
        {
            "method_name": "GetCurrency",
            "return_type": "int",
            "rva": 0x1000,
            "address_kind": "method_rva",
            "parameter_types": ("CurrencyType",),
            "parameters": [{"type": "CurrencyType"}],
        },
        {
            "method_name": "GetCurrency",
            "return_type": "int",
            "rva": 0x2000,
            "address_kind": "method_rva",
            "parameter_types": ("CurrencyType", "bool"),
            "parameters": [{"type": "CurrencyType"}, {"type": "bool"}],
        },
    ]

    _merge_dump_method_evidence(script_methods, dump_methods)

    assert [method["rva"] for method in script_methods] == [0x1000, 0x2000]
    assert script_methods[0]["signature"] == "native-one"
    assert script_methods[1]["parameter_types"] == ("CurrencyType", "bool")


def test_only_exact_executable_dex_override_is_activation_ready() -> None:
    from re_agent.cli.cmd_batch import _method_activation_facts

    evidence = {
        "descriptor": "()I",
        "return_type": "int",
        "is_declared": True,
        "is_executable": True,
        "is_constructor": False,
        "is_static": False,
    }

    assert _method_activation_facts(
        "android-java-dex",
        evidence,
        "return_override",
    ) == {
        "signature_verified": True,
        "address_verified": True,
        "implementation_ready": True,
    }
    assert _method_activation_facts(
        "react-native-hermes",
        evidence,
        "return_override",
    ) == {
        "signature_verified": True,
        "address_verified": True,
        "implementation_ready": True,
    }
    evidence["is_executable"] = False
    assert not any(
        _method_activation_facts(
            "android-java-dex",
            evidence,
            "return_override",
        ).values()
    )


def test_large_metadata_inventory_detects_once_and_bounds_header_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text('project_profile:\n  name: "generic-cpp"\n')
    metadata_dir = tmp_path / "Dump0"
    metadata_dir.mkdir()
    (metadata_dir / "script.json").write_text(
        '{"ScriptMethod": []}',
        encoding="utf-8",
    )
    synthetic_structs = [
        {
            "name": f"Wallet{index}",
            "fields": [
                {
                    "name": "coins",
                    "offset": 0x10 + index,
                    "type": "int32_t",
                }
            ],
        }
        for index in range(75)
    ]
    monkeypatch.setattr(
        "re_agent.cli.cmd_batch.find_il2cpp_metadata_in_dir",
        lambda _path: {
            "methods": [],
            "structs": synthetic_structs,
            "classes": [],
        },
    )
    monkeypatch.setattr(
        "re_agent.llm.registry.create_provider",
        lambda _config: None,
    )

    from re_agent.core import engine_detector

    original_detect = engine_detector.detect_architecture_from_path
    detection_calls = 0

    def counted_detect(*args, **kwargs):
        nonlocal detection_calls
        detection_calls += 1
        return original_detect(*args, **kwargs)

    monkeypatch.setattr(
        engine_detector,
        "detect_architecture_from_path",
        counted_detect,
    )
    output_dir = tmp_path / "output"

    result = main(
        [
            "--config",
            config_file.as_posix(),
            "batch",
            "--metadata-dir",
            metadata_dir.as_posix(),
            "--platform",
            "ios",
            "--goal",
            "give infinite coins",
            "--output-dir",
            output_dir.as_posix(),
        ]
    )

    assert result == 0
    assert detection_calls == 1
    assert len(list(output_dir.glob("*.h"))) == 50


def test_metadata_join_does_not_add_lowercase_class_aliases(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from argparse import Namespace

    from re_agent.cli.cmd_batch import cmd_batch

    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text('project_profile:\n  name: "generic-cpp"\n')
    metadata_dir = tmp_path / "Dump0"
    metadata_dir.mkdir()
    monkeypatch.setattr(
        "re_agent.cli.cmd_batch.find_il2cpp_metadata_in_dir",
        lambda _path: {
            "methods": [
                {
                    "name": "EndRunSequence$$get_CurrentCoins",
                    "address": 0x1000,
                }
            ],
            "structs": [
                {
                    "name": "EndRunSequence",
                    "fields": [
                        {
                            "name": "_currentCoins",
                            "offset": 0x20,
                            "type": "int",
                        }
                    ],
                }
            ],
            "classes": [],
        },
    )
    monkeypatch.setattr(
        "re_agent.llm.registry.create_provider",
        lambda _config: None,
    )

    result = cmd_batch(
        Namespace(
            config=config_file.as_posix(),
            auto_discover=True,
            goal="give infinite coins",
            symbol=None,
            string=None,
            class_name=None,
            binary=None,
            metadata=None,
            metadata_dir=metadata_dir.as_posix(),
            platform="ios",
            output_dir=(tmp_path / "output").as_posix(),
            limit=50,
            _return_matches=True,
            _suppress_candidate_display=True,
        )
    )

    assert isinstance(result, tuple)
    class_names = {target.class_name for target in result[2]}
    assert "EndRunSequence" in class_names
    assert "endrunsequence" not in class_names
