"""Tests for universal confidence-ranked candidate grouping."""

from __future__ import annotations

from re_agent.core.candidates import rank_candidates, render_candidate_summary, split_candidates
from re_agent.llm.analyzed_target import AnalyzedTarget


def test_primary_candidates_are_thresholded_and_limited() -> None:
    targets = [
        AnalyzedTarget("Class", f"Target{index}", confidence=confidence)
        for index, confidence in enumerate((99, 97, 95, 90, 85, 84, 60))
    ]
    groups = split_candidates(targets)
    assert [target.confidence for target in groups.primary] == [99, 97, 95, 90, 85]
    assert [target.confidence for target in groups.secondary] == [84, 60]


def test_expanded_summary_retains_exact_scores() -> None:
    targets = [
        AnalyzedTarget("Wallet", "Coins", confidence=95),
        AnalyzedTarget("Wallet", "Gems", confidence=80),
    ]
    summary = render_candidate_summary(targets)
    assert "TOP HIGH-CONFIDENCE TARGETS (>=85%, max 5)" in summary
    assert "[95%] Wallet::Coins" in summary
    assert "EXPANDED CANDIDATES SUMMARY (1 remaining)" in summary
    assert "[80%] Wallet::Gems" in summary


def test_ranking_does_not_mutate_caller_targets() -> None:
    target = AnalyzedTarget("Wallet", "Coins", confidence=150)
    ranked = rank_candidates([target])

    assert target.confidence == 150
    assert ranked[0].confidence == 100


def test_conflicting_strategies_are_never_primary() -> None:
    targets = [
        AnalyzedTarget("Wallet", "Coins", offset=0x20, hook_type="memory_patch", confidence=95),
        AnalyzedTarget("Wallet", "Coins", hook_type="return_override", confidence=95),
    ]

    groups = split_candidates(targets)

    assert not groups.primary
    assert len(groups.secondary) == 2
    assert all(target.confidence == 84 for target in groups.secondary)


def test_equal_confidence_prefers_wallet_state_over_derived_currency_helpers() -> None:
    targets = [
        AnalyzedTarget(
            "CurrencyExtensions",
            "IsExpirableCurrency",
            method_rva=0x1000,
            return_type="bool",
            confidence=92,
        ),
        AnalyzedTarget(
            "CurrencyRewardHandler",
            "GetCurrencyExpiration",
            method_rva=0x2000,
            confidence=92,
        ),
        AnalyzedTarget(
            "WalletModel",
            "GetCurrency",
            method_rva=0x3000,
            parameter_types=("CurrencyType",),
            confidence=92,
        ),
        AnalyzedTarget(
            "WalletOnRunModel",
            "Coins",
            offset=0x30,
            hook_type="memory_patch",
            confidence=92,
        ),
    ]

    ranked = rank_candidates(targets)

    assert {
        (target.class_name, target.target)
        for target in ranked[:2]
    } == {
        ("WalletModel", "GetCurrency"),
        ("WalletOnRunModel", "Coins"),
    }
