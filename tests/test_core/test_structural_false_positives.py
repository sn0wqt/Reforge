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
