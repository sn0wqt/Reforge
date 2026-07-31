"""Unit tests for structural_analysis module."""

from __future__ import annotations

from re_agent.core.structural_analysis import analyze_structures


def test_analyze_structures_currency_getter() -> None:
    candidates = [
        (
            "WalletModel",
            [
                {"name": "get_Currency", "return_type": "int32_t", "parameters": []},
            ],
            [{"name": "_balance", "type": "int32_t", "offset": 32}],
        )
    ]
    results = analyze_structures(candidates)
    assert len(results) == 1
    assert results[0].class_name == "WalletModel"
    assert results[0].target_name == "get_Currency"
    assert results[0].category == "currency_getter"
    assert results[0].confidence == 85


def test_analyze_structures_damage_check() -> None:
    candidates = [
        (
            "PlayerMotor",
            [
                {"name": "TakeDamage", "return_type": "void", "parameters": [{"type": "float"}]},
            ],
            [],
        )
    ]
    results = analyze_structures(candidates)
    assert len(results) == 1
    assert results[0].class_name == "PlayerMotor"
    assert results[0].target_name == "TakeDamage"
    assert results[0].category == "damage_check"


def test_analyze_structures_position_getter() -> None:
    candidates = [
        (
            "PlayerTransform",
            [
                {"name": "get_position", "return_type": "Vector3", "parameters": []},
            ],
            [],
        )
    ]
    results = analyze_structures(candidates)
    assert len(results) == 1
    assert results[0].class_name == "PlayerTransform"
    assert results[0].category == "position_getter"
