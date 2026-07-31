"""Unit tests for Gemini semantic analyzer and AnalyzedTarget."""

from __future__ import annotations

import json
from typing import Any

import pytest

from re_agent.llm.analyzed_target import AnalyzedTarget
from re_agent.llm.semantic_analyzer import (
    _build_metadata_summary,
    _parse_llm_response,
    analyze_metadata_with_llm,
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
