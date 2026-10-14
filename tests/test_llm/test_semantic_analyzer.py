"""Unit tests for semantic analyzer and AnalyzedTarget."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from re_agent.llm.analyzed_target import AnalyzedTarget
from re_agent.llm.semantic_analyzer import (
    _build_metadata_summary,
    _deduplicate_targets,
    _parse_llm_response,
    _target_score,
    analyze_metadata_with_llm,
    create_gemini_provider,
)


class MockLLMProvider:
    """Mock LLM provider for testing without real API calls."""

    def __init__(self, response_text: str) -> None:
        self.response_text = response_text
        self.last_messages: list[Any] = []

    def send(self, messages: list[Any], **kwargs: Any) -> str:
        self.last_messages = messages
        return self.response_text

    @property
    def supports_conversations(self) -> bool:
        return True

    def new_conversation(self, system: str) -> str:
        return "mock-conv-id"

    def resume(self, conversation_id: str, message: str) -> str:
        return self.response_text


def test_analyzed_target_validation() -> None:
    target = AnalyzedTarget(
        class_name="WalletModel",
        target="GetCurrency",
        hook_type="return_override",
        return_value="999999999",
        confidence=95,
        reason="Getter for currency balance",
    )
    assert target.class_name == "WalletModel"
    assert target.target == "GetCurrency"
    assert target.hook_type == "return_override"

    with pytest.raises(ValueError, match="Invalid hook_type"):
        AnalyzedTarget(class_name="Test", target="Test", hook_type="invalid_type")


def test_build_metadata_summary() -> None:
    candidates = [
        (
            "WalletModel",
            [{"method_name": "GetCurrency", "address": 0x1000}],
            [{"name": "m_Coins", "type": "int32_t", "offset": 0x20}],
        )
    ]
    summary = _build_metadata_summary(candidates)
    payload = json.loads(summary)
    assert payload[0]["class"] == "WalletModel"
    assert payload[0]["fields"][0]["offset"] == 0x20
    assert payload[0]["methods"][0]["address"] == 0x1000


def test_large_metadata_summary_stays_bounded_and_valid_json() -> None:
    candidates = [
        (
            f"VeryLongWalletClass{index:03d}" + ("X" * 220),
            [
                {
                    "method_name": f"GetCurrency{member:03d}" + ("Y" * 220),
                    "descriptor": "(" + ("I" * 500) + ")I",
                }
                for member in range(12)
            ],
            [
                {
                    "name": f"CurrencyField{member:03d}" + ("Z" * 220),
                    "type": "int32_t",
                    "offset": member * 4,
                }
                for member in range(12)
            ],
        )
        for index in range(50)
    ]

    summary = _build_metadata_summary(candidates)

    assert len(summary) <= 60_000
    payload = json.loads(summary)
    assert payload
    assert len(payload) < len(candidates)


def test_goal_relevant_method_survives_per_class_summary_limit() -> None:
    methods = [
        {
            "method_name": f"UnrelatedMethod{index}",
            "return_type": "void",
        }
        for index in range(20)
    ]
    methods.append(
        {
            "method_name": "GetCurrency",
            "return_type": "int",
            "rva": 0x4C3A9DC,
            "address": 0x4C3A9DC,
            "address_kind": "method_rva",
            "parameter_types": ("CurrencyType",),
        }
    )

    summary = _build_metadata_summary(
        [("WalletModel", methods, [])],
        entity_terms=["coins", "currency", "wallet"],
    )
    payload = json.loads(summary)
    selected_names = {method["name"] for method in payload[0]["methods"]}

    assert "GetCurrency" in selected_names
    assert len(selected_names) == 12


def test_unknown_goal_entity_after_first_fifty_classes_is_submitted_and_grounded() -> None:
    candidates = [
        (
            f"UnrelatedComponent{index}",
            [{"method_name": "readStatus", "return_type": "boolean", "descriptor": "()Z"}],
            [],
        )
        for index in range(60)
    ]
    candidates.append(
        (
            "org.example.GlimmerRepository",
            [
                {
                    "method_name": "getGlimmers",
                    "return_type": "long",
                    "descriptor": "()J",
                    "parameter_types": (),
                    "is_declared": True,
                    "is_executable": True,
                    "is_constructor": False,
                    "is_static": False,
                }
            ],
            [],
        )
    )
    response = json.dumps(
        [
            {
                "class_name": "org.example.GlimmerRepository",
                "target": "getGlimmers",
                "hook_type": "return_override",
                "return_value": "9223372036854775807",
                "return_type": "int64_t",
                "confidence": 97,
                "reason": "Exact primitive getter for the requested entity",
            }
        ]
    )
    provider = MockLLMProvider(response)

    targets = analyze_metadata_with_llm(provider, "set glimmers to maximum", candidates)

    submitted_prompt = provider.last_messages[-1].content
    assert "org.example.GlimmerRepository" in submitted_prompt
    assert '"class":"UnrelatedComponent49"' not in submitted_prompt
    assert len(targets) == 1
    assert targets[0].target == "getGlimmers"
    assert targets[0].return_type == "int64_t"
    assert targets[0].implementation_ready is True


def test_semantic_prompt_is_binary_neutral_and_fail_closed() -> None:
    provider = MockLLMProvider("[]")
    analyze_metadata_with_llm(
        provider,
        "enable custom capability",
        [("CapabilityState", [], [])],
    )

    system_prompt = provider.last_messages[0].content
    user_prompt = provider.last_messages[1].content
    assert "do not assume the application is a game" in system_prompt.lower()
    assert "verified primitive scalar return type" in system_prompt
    assert "DEX or IL2CPP" in user_prompt
    assert "Wallet, Balance, Currency" not in system_prompt


def test_grounding_excludes_ranked_classes_omitted_by_character_budget() -> None:
    methods = [
        {
            "method_name": "getCapability" if index == 0 else f"CapabilityDetail{index}",
            "return_type": "int32_t",
            "descriptor": "(" + ("I" * 500) + ")I",
            "parameter_types": (),
            "is_declared": True,
            "is_executable": True,
            "is_constructor": False,
            "is_static": False,
        }
        for index in range(12)
    ]
    candidates = [(f"CapabilityStore{index}", methods, []) for index in range(50)]
    omitted_class = "CapabilityStore20"
    response = json.dumps(
        [
            {
                "class_name": omitted_class,
                "target": "getCapability",
                "hook_type": "return_override",
                "return_value": "1",
                "return_type": "int32_t",
                "confidence": 100,
                "reason": "Must be rejected when its class was not submitted",
            }
        ]
    )
    provider = MockLLMProvider(response)

    targets = analyze_metadata_with_llm(provider, "enable capability", candidates)

    assert omitted_class not in provider.last_messages[-1].content
    assert targets == []


def test_parse_llm_response_json() -> None:
    json_resp = json.dumps(
        [
            {
                "class_name": "WalletModel",
                "target": "GetCurrency",
                "offset": None,
                "hook_type": "return_override",
                "return_value": "999999999",
                "return_type": "int32_t",
                "confidence": 95,
                "reason": "Returns currency",
            },
            {
                "class_name": "WalletOnRunModel",
                "target": "Keys",
                "offset": "0x30",
                "hook_type": "memory_patch",
                "return_value": "999999",
                "return_type": "int32_t",
                "confidence": 90,
                "reason": "Direct field offset",
            },
        ]
    )

    targets = _parse_llm_response(json_resp)
    assert len(targets) == 2
    assert targets[0].class_name == "WalletOnRunModel"
    assert targets[0].offset == 0x30
    assert targets[1].class_name == "WalletModel"
    assert targets[1].hook_type == "return_override"


def test_parse_llm_response_with_markdown_fences() -> None:
    raw = """```json
[
  {
    "class_name": "CharacterMotor",
    "target": "CheckFrontalImpact",
    "hook_type": "skip_call",
    "return_value": "false",
    "return_type": "bool",
    "confidence": 85,
    "reason": "Disables collision"
  }
]
```"""
    targets = _parse_llm_response(raw)
    assert len(targets) == 1
    assert targets[0].class_name == "CharacterMotor"
    assert targets[0].hook_type == "skip_call"


def test_analyze_metadata_with_llm_mock() -> None:
    mock_resp = json.dumps(
        [
            {
                "class_name": "WalletModel",
                "target": "GetCurrency",
                "hook_type": "return_override",
                "return_value": "999999999",
                "confidence": 95,
                "reason": "Currency getter",
            }
        ]
    )
    provider = MockLLMProvider(mock_resp)
    candidates = [
        (
            "WalletModel",
            [
                {
                    "method_name": "GetCurrency",
                    "address": 0x100,
                    "rva": 0x100,
                    "address_kind": "method_rva",
                    "return_type": "int32_t",
                    "parameter_types": ("int",),
                    "descriptor": "(I)I",
                }
            ],
            [],
        )
    ]

    targets = analyze_metadata_with_llm(provider, "give infinite coins", candidates)
    assert len(targets) == 1
    assert targets[0].class_name == "WalletModel"
    assert targets[0].target == "GetCurrency"
    assert targets[0].confidence == 88
    assert targets[0].method_rva == 0x100
    assert targets[0].parameter_types == ("int",)
    assert targets[0].method_descriptor == "(I)I"


def test_llm_target_after_first_twelve_members_is_still_grounded() -> None:
    response = json.dumps(
        [
            {
                "class_name": "WalletModel",
                "target": "GetCurrency",
                "hook_type": "return_override",
                "return_value": "999999999",
                "return_type": "int32_t",
                "confidence": 95,
                "reason": "Currency getter",
            }
        ]
    )
    methods = [{"method_name": f"Noise{index}", "return_type": "void"} for index in range(20)]
    methods.append(
        {
            "method_name": "GetCurrency",
            "return_type": "int",
            "rva": 0x4C3A9DC,
            "address_kind": "method_rva",
            "parameter_types": ("CurrencyType",),
        }
    )

    targets = analyze_metadata_with_llm(
        MockLLMProvider(response),
        "give infinite coins",
        [("WalletModel", methods, [])],
    )

    assert len(targets) == 1
    assert targets[0].target == "GetCurrency"
    assert targets[0].method_rva == 0x4C3A9DC
    assert targets[0].parameter_types == ("CurrencyType",)
    assert targets[0].address_verified is True
    assert targets[0].signature_verified is True
    assert targets[0].implementation_ready is True


def test_analyze_metadata_can_surface_provider_failure() -> None:
    class FailingProvider(MockLLMProvider):
        def send(self, messages: list[Any], **kwargs: Any) -> str:
            del messages, kwargs
            raise RuntimeError("provider unavailable")

    with pytest.raises(RuntimeError, match="provider unavailable"):
        analyze_metadata_with_llm(
            FailingProvider(""),
            "give infinite coins",
            [],
            raise_on_provider_error=True,
        )


def test_grounded_dex_method_sets_verified_java_activation_facts() -> None:
    response = json.dumps(
        [
            {
                "class_name": "com.game.Wallet",
                "target": "getCoins",
                "hook_type": "return_override",
                "return_value": "999999999",
                "return_type": "int32_t",
                "confidence": 95,
                "reason": "Exact getter",
            }
        ]
    )
    candidates = [
        (
            "com.game.Wallet",
            [
                {
                    "method_name": "getCoins",
                    "return_type": "int",
                    "parameter_types": (),
                    "descriptor": "()I",
                    "is_declared": True,
                    "is_executable": True,
                    "is_constructor": False,
                    "is_static": False,
                }
            ],
            [],
        )
    ]

    targets = analyze_metadata_with_llm(
        MockLLMProvider(response),
        "grant unlimited coins",
        candidates,
    )

    assert len(targets) == 1
    assert targets[0].return_type == "int32_t"
    assert targets[0].signature_verified is True
    assert targets[0].address_verified is True
    assert targets[0].implementation_ready is True


def test_analyze_metadata_rejects_hallucinated_or_changed_offset() -> None:
    response = json.dumps(
        [
            {
                "class_name": "WalletModel",
                "target": "Coins",
                "offset": "0x30",
                "hook_type": "memory_patch",
                "return_value": "999",
                "return_type": "int32_t",
                "confidence": 100,
                "reason": "invented offset",
            },
            {
                "class_name": "MadeUp",
                "target": "Coins",
                "offset": "0x20",
                "hook_type": "memory_patch",
                "return_value": "999",
                "return_type": "int32_t",
                "confidence": 100,
                "reason": "invented class",
            },
        ]
    )
    candidates = [
        (
            "WalletModel",
            [],
            [{"name": "Coins", "offset": 0x20, "type": "int32_t"}],
        )
    ]

    assert (
        analyze_metadata_with_llm(
            MockLLMProvider(response),
            "infinite coins",
            candidates,
        )
        == []
    )


def test_deduplication_preserves_getter_and_setter_with_same_stem() -> None:
    getter = AnalyzedTarget(
        class_name="FeatureState",
        target="get_Value",
        hook_type="return_override",
        confidence=90,
    )
    setter = AnalyzedTarget(
        class_name="FeatureState",
        target="set_Value",
        hook_type="skip_call",
        return_type="void",
        return_value=None,
        confidence=89,
    )

    assert _deduplicate_targets([getter, setter]) == [getter, setter]


def test_deduplication_keeps_highest_scored_true_duplicate_only() -> None:
    lower = AnalyzedTarget(
        class_name="FeatureState",
        target="get_Value",
        hook_type="return_override",
        confidence=70,
    )
    higher = AnalyzedTarget(
        class_name="FeatureState",
        target="get_Value",
        hook_type="return_override",
        confidence=90,
    )

    assert _deduplicate_targets([lower, higher]) == [higher]


def test_deduplication_preserves_overloaded_exact_methods() -> None:
    integer_overload = AnalyzedTarget(
        class_name="FeatureState",
        target="getValue",
        hook_type="return_override",
        method_descriptor="(I)I",
        parameter_types=("int",),
        confidence=90,
    )
    string_overload = AnalyzedTarget(
        class_name="FeatureState",
        target="getValue",
        hook_type="return_override",
        method_descriptor="(Ljava/lang/String;)I",
        parameter_types=("java.lang.String",),
        confidence=89,
    )

    assert _deduplicate_targets([integer_overload, string_overload]) == [
        integer_overload,
        string_overload,
    ]


def test_ui_names_have_no_unconditional_ranking_penalty() -> None:
    ui_backed_state = AnalyzedTarget(
        class_name="FeatureUIState",
        target="get_Entitlement",
        hook_type="return_override",
        confidence=90,
    )
    neutral_state = AnalyzedTarget(
        class_name="FeatureState",
        target="get_Entitlement",
        hook_type="return_override",
        confidence=90,
    )

    assert _target_score(ui_backed_state) == _target_score(neutral_state)


def test_gemini_provider_uses_central_config_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_provider = MockLLMProvider("[]")
    config = SimpleNamespace(
        llm=SimpleNamespace(provider="gemini", model="configured-model")
    )
    loaded_paths: list[object] = []

    def fake_load_config(path: object) -> object:
        loaded_paths.append(path)
        return config

    monkeypatch.setattr("re_agent.config.loader.load_config", fake_load_config)
    monkeypatch.setattr(
        "re_agent.llm.registry.create_provider",
        lambda _config: configured_provider,
    )

    assert create_gemini_provider() is configured_provider
    assert loaded_paths == [None]
