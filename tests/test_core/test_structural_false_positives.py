"""Structural ranking must not promote unrelated numeric methods."""

from __future__ import annotations

from re_agent.core.structural_analysis import analyze_structures


def test_unrelated_numeric_getter_is_not_currency() -> None:
    results = analyze_structures(
        [
            (
                "TelemetryModel",
                [{"name": "GetRetryCount", "return_type": "int32_t", "parameters": []}],
                [{"name": "_retryCount", "type": "int32_t", "offset": 0x20}],
            )
        ]
    )

    assert not results


def test_framework_key_getters_are_not_gameplay_currency() -> None:
    results = analyze_structures(
        [
            (
                "AesCng",
                [{"name": "get_Key", "return_type": "int32_t", "parameters": []}],
                [{"name": "_keySize", "type": "int32_t", "offset": 0x20}],
            ),
            (
                "Dictionary",
                [{"name": "get_Keys", "return_type": "int32_t", "parameters": []}],
                [{"name": "_count", "type": "int32_t", "offset": 0x20}],
            ),
            (
                "CoreRunnerManager",
                [
                    {
                        "name": "GetAvailableKeysForUse",
                        "return_type": "int32_t",
                        "parameters": [],
                    }
                ],
                [{"name": "_availableKeys", "type": "int32_t", "offset": 0x20}],
            ),
        ]
    )

    assert [(result.class_name, result.target_name) for result in results] == [
        ("CoreRunnerManager", "GetAvailableKeysForUse")
    ]
