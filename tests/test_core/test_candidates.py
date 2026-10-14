"""Tests for universal confidence-ranked candidate grouping."""

from __future__ import annotations

from re_agent.core.candidates import (
    rank_candidates,
    render_candidate_summary,
    split_candidates,
    target_activation_facts,
)
from re_agent.llm.analyzed_target import AnalyzedTarget


def test_primary_candidates_are_thresholded_and_limited() -> None:
    targets = [
        AnalyzedTarget("Class", f"Target{index}", confidence=confidence)
        for index, confidence in enumerate((99, 97, 95, 90, 85, 84, 60))
    ]
    groups = split_candidates(targets)
    assert [target.confidence for target in groups.primary] == [99, 97, 95, 90, 85]
    assert [target.confidence for target in groups.secondary] == [84, 60]


def test_goal_selects_one_best_candidate_per_requested_entity() -> None:
    targets = [
        AnalyzedTarget("RunSessionData", "GetAvailableCoinsForUse", confidence=97),
        AnalyzedTarget("WalletModel", "Coins", confidence=95),
        AnalyzedTarget("RunSessionData", "GetAvailableKeysForUse", confidence=94),
        AnalyzedTarget("WalletModel", "Keys", confidence=91),
        AnalyzedTarget("WalletModel", "Gems", confidence=99),
    ]

    groups = split_candidates(targets, goal_prompt="grant unlimited coins and keys")

    assert [(target.target, target.confidence) for target in groups.primary] == [
        ("GetAvailableCoinsForUse", 97),
        ("GetAvailableKeysForUse", 94),
    ]
    assert len(groups.secondary) == 3


def test_singular_and_plural_are_one_entity_and_threshold_still_applies() -> None:
    targets = [
        AnalyzedTarget("Wallet", "Coins", confidence=96),
        AnalyzedTarget("Wallet", "Coin", confidence=93),
        AnalyzedTarget("Wallet", "Keys", confidence=84),
    ]

    groups = split_candidates(targets, goal_prompt="unlimited coins and keys")

    assert [target.target for target in groups.primary] == ["Coins"]
    assert [target.target for target in groups.secondary] == ["Coin", "Keys"]


def test_unknown_singular_and_plural_are_one_requested_entity() -> None:
    targets = [
        AnalyzedTarget("Inventory", "Orbs", confidence=96),
        AnalyzedTarget("Inventory", "Orb", confidence=93),
    ]

    groups = split_candidates(targets, goal_prompt="grant unlimited orbs")

    assert [target.target for target in groups.primary] == ["Orbs"]
    assert [target.target for target in groups.secondary] == ["Orb"]


def test_unknown_compound_goal_matches_camel_case_member_tokens() -> None:
    targets = [
        AnalyzedTarget("DriveState", "GetWarpCharges", confidence=96),
        AnalyzedTarget("DriveState", "GetWarpSpeed", confidence=99),
    ]

    groups = split_candidates(targets, goal_prompt="grant unlimited warpcharges")

    assert [target.target for target in groups.primary] == ["GetWarpCharges"]
    assert [target.target for target in groups.secondary] == ["GetWarpSpeed"]


def test_spaced_compound_is_one_entity_and_beats_constituent_decoy() -> None:
    targets = [
        AnalyzedTarget("DriveState", "GetWarpSpeed", confidence=99),
        AnalyzedTarget("DriveState", "GetWarpCharges", confidence=96),
        AnalyzedTarget("DriveState", "GetCharges", confidence=95),
    ]

    groups = split_candidates(targets, goal_prompt="grant unlimited warp charges")

    assert [target.target for target in groups.primary] == ["GetWarpCharges"]
    assert [target.target for target in groups.secondary] == ["GetWarpSpeed", "GetCharges"]


def test_member_entity_match_wins_over_class_name_match_and_prompt_order() -> None:
    targets = [
        AnalyzedTarget("KeyWallet", "GetCoins", confidence=99),
        AnalyzedTarget("KeyWallet", "GetKeys", confidence=98),
    ]

    groups = split_candidates(targets, goal_prompt="grant keys and coins")

    assert [target.target for target in groups.primary] == ["GetCoins", "GetKeys"]


def test_short_requested_entities_select_distinct_targets() -> None:
    targets = [
        AnalyzedTarget("CharacterStats", "CurrentXP", confidence=96),
        AnalyzedTarget("CharacterStats", "CurrentHP", confidence=95),
    ]

    groups = split_candidates(targets, goal_prompt="set XP and HP")

    assert [target.target for target in groups.primary] == ["CurrentXP", "CurrentHP"]


def test_generic_subscription_goal_selects_only_best_subscription_target() -> None:
    targets = [
        AnalyzedTarget("EntitlementModel", "HasPremium", confidence=96),
        AnalyzedTarget("BillingModel", "ActiveSubscription", confidence=93),
        AnalyzedTarget("Wallet", "Coins", confidence=99),
    ]

    groups = split_candidates(targets, goal_prompt="enable subscription")

    assert [target.target for target in groups.primary] == ["HasPremium"]
    assert len(groups.secondary) == 2


def test_specific_tiers_suppress_redundant_generic_subscription_slot() -> None:
    targets = [
        AnalyzedTarget("SubscriptionModel", "HasPro", confidence=97),
        AnalyzedTarget("SubscriptionModel", "HasMax", confidence=96),
        AnalyzedTarget("SubscriptionModel", "ActiveSubscription", confidence=95),
    ]

    groups = split_candidates(targets, goal_prompt="unlock Pro and Max subscriptions")

    assert [target.target for target in groups.primary] == ["HasPro", "HasMax"]
    assert [target.target for target in groups.secondary] == ["ActiveSubscription"]


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


def test_equal_confidence_uses_domain_neutral_readiness_evidence() -> None:
    targets = [
        AnalyzedTarget(
            "WalletModel",
            "Coins",
            method_rva=0x1000,
            confidence=92,
        ),
        AnalyzedTarget(
            "EntitlementModel",
            "HasAccess",
            method_rva=0x2000,
            confidence=92,
            signature_verified=True,
            address_verified=True,
            implementation_ready=True,
        ),
    ]

    ranked = rank_candidates(targets)

    assert [(target.class_name, target.target) for target in ranked] == [
        ("EntitlementModel", "HasAccess"),
        ("WalletModel", "Coins"),
    ]


def test_equal_confidence_without_readiness_has_no_currency_bias() -> None:
    targets = [
        AnalyzedTarget("WalletModel", "Coins", confidence=92),
        AnalyzedTarget("AccessModel", "License", confidence=92),
    ]

    ranked = rank_candidates(targets)

    assert [target.class_name for target in ranked] == ["AccessModel", "WalletModel"]


def test_summary_distinguishes_goal_mismatch_from_low_confidence() -> None:
    mismatch = render_candidate_summary(
        [AnalyzedTarget("Wallet", "Coins", confidence=95)],
        goal_prompt="enable warpcharge",
    )
    below_threshold = render_candidate_summary(
        [AnalyzedTarget("WarpDrive", "Warpcharge", confidence=84)],
        goal_prompt="enable warpcharge",
    )

    assert "none matched the requested goal entities" in mismatch
    assert "No candidate met the high-confidence threshold" in below_threshold


def test_il2cpp_integral_method_rva_is_ready_for_narrow_frida_override() -> None:
    facts = target_activation_facts(
        engine_type="unity-il2cpp",
        hook_type="return_override",
        evidence={
            "rva": 0x1234,
            "return_type": "System.Int32",
            "parameter_types": (),
        },
    )

    assert facts == {
        "signature_verified": True,
        "address_verified": True,
        "implementation_ready": True,
    }


def test_il2cpp_nonintegral_method_and_field_evidence_remain_fail_closed() -> None:
    floating = target_activation_facts(
        engine_type="unity-il2cpp",
        hook_type="return_override",
        evidence={
            "rva": 0x1234,
            "return_type": "float",
            "parameter_types": (),
        },
    )
    field = target_activation_facts(
        engine_type="unity-il2cpp",
        hook_type="memory_patch",
        evidence={"offset": 0x20},
    )

    assert floating == {
        "signature_verified": False,
        "address_verified": True,
        "implementation_ready": False,
    }
    assert field == {
        "signature_verified": False,
        "address_verified": True,
        "implementation_ready": False,
    }
