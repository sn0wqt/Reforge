"""Tests for the single immutable domain-keyword source."""

from __future__ import annotations

import ast
from pathlib import Path

from re_agent.config import domain_keywords


def test_domain_keyword_collections_are_immutable() -> None:
    names = (
        "COLLISION_KEYWORDS",
        "CURRENCY_KEYWORDS",
        "FRAMEWORK_STOPWORDS",
        "INTENT_MODIFIERS",
        "INTENT_VERBS",
    )
    for name in names:
        assert isinstance(getattr(domain_keywords, name), frozenset)


def test_domain_terms_have_expected_coverage() -> None:
    assert {"grant", "set", "add"} <= domain_keywords.INTENT_VERBS
    assert {"unlimited", "infinite"} <= domain_keywords.INTENT_MODIFIERS
    assert {"coin", "keys", "diamonds", "wallet"} <= domain_keywords.CURRENCY_KEYWORDS
    assert {"collision", "obstacle", "damage"} <= domain_keywords.COLLISION_KEYWORDS


def test_identifier_keyword_matching_uses_complete_tokens() -> None:
    assert domain_keywords.matches_identifier_keyword("coin", "PlayerCoinWallet")
    assert domain_keywords.matches_identifier_keyword("player wallet", "Player_Wallet")
    assert not domain_keywords.matches_identifier_keyword("key", "monkeyBusiness")
    assert not domain_keywords.matches_identifier_keyword("pro", "processState")


def test_identifier_keyword_matching_supports_explicit_short_entities() -> None:
    assert domain_keywords.matches_identifier_keyword("XP", "PlayerXP")
    assert domain_keywords.matches_identifier_keyword("hp", "CurrentHp")
    assert not domain_keywords.matches_identifier_keyword("hp", "shopState")


def test_identifier_keyword_matching_supports_unknown_compound_entities() -> None:
    assert domain_keywords.matches_identifier_keyword("warpcharges", "GetWarpCharges")
    assert domain_keywords.matches_identifier_keyword("warpcharge", "current_warp_charges")
    assert not domain_keywords.matches_identifier_keyword("warpcharge", "GetWarpSpeed")


def test_unknown_entities_use_conservative_general_singularization() -> None:
    assert domain_keywords.canonical_entity_token("orbs") == "orb"
    assert domain_keywords.canonical_entity_token("licenses") == "license"
    assert domain_keywords.canonical_entity_token("status") == "status"
    assert domain_keywords.canonical_entity_token("analysis") == "analysis"
    assert domain_keywords.canonical_entity_token("bonus") == "bonus"
    assert domain_keywords.canonical_entity_token("series") == "series"
    assert domain_keywords.canonical_entity_token("species") == "species"
    assert domain_keywords.canonical_entity_token("news") == "news"
    assert domain_keywords.canonical_entity_token("chaos") == "chaos"
    assert domain_keywords.canonical_entity_token("lens") == "lens"


def test_balance_value_filter_rejects_costs_and_derived_metadata() -> None:
    assert domain_keywords.is_balance_value_member("GetCurrency")
    assert domain_keywords.is_balance_value_member("CurrentKeys")
    assert not domain_keywords.is_balance_value_member("KeyCost")
    assert not domain_keywords.is_balance_value_member("GetCurrencyExpiration")
    assert not domain_keywords.is_balance_value_member("CurrencyVariableId")
    assert not domain_keywords.is_balance_value_member("TotalIAPCurrencySpent")


def test_entity_filter_does_not_apply_intent_as_arbitrary_substring() -> None:
    assert domain_keywords.filter_entity_terms(["GrantedReward"]) == ["grantedreward"]
    assert domain_keywords.filter_entity_terms(["grant", "UnlimitedCoins"]) == []


def test_entity_filter_preserves_contextual_tier_but_not_plain_modifier() -> None:
    assert domain_keywords.filter_entity_terms(["pro", "max", "subscriptions", "subscription"]) == [
        "pro",
        "max",
        "subscriptions",
        "subscription",
    ]
    assert domain_keywords.filter_entity_terms(["max", "coins", "coin"]) == ["coins", "coin"]


def test_entity_filter_keeps_short_non_stopword_entities() -> None:
    assert domain_keywords.filter_entity_terms(["XP", "hp", "do", "it"]) == ["xp", "hp"]


def test_named_tier_matches_require_behavioral_tier_context() -> None:
    assert domain_keywords.is_named_tier_match_contextual(
        "pro", "SubscriptionState", "hasPro"
    )
    assert domain_keywords.is_named_tier_match_contextual(
        "max", "EntitlementPlan", "getMax"
    )
    assert not domain_keywords.is_named_tier_match_contextual(
        "max", "CustomTabsIntent", "getMaxToolbarItems"
    )
    assert not domain_keywords.is_named_tier_match_contextual(
        "pro", "ExcludedSupportedSizesQuirk", "isRedmiNote9Pro"
    )
    assert not domain_keywords.is_named_tier_match_contextual(
        "max", "QuotaLimit", "getMaxLimit"
    )


def test_platform_library_namespace_detection_is_exact_and_generic() -> None:
    assert domain_keywords.is_platform_library_class("androidx.browser.CustomTabsIntent")
    assert domain_keywords.is_platform_library_class("java.util.HashMap")
    assert not domain_keywords.is_platform_library_class("com.example.androidxfeature.State")


def test_consumers_do_not_redefine_domain_keyword_constants() -> None:
    root = Path(__file__).parents[2]
    consumers = (
        root / "src/re_agent/cli/cmd_batch.py",
        root / "src/re_agent/cli/cmd_hook.py",
        root / "src/re_agent/llm/semantic_analyzer.py",
        root / "src/re_agent/utils/goal_parser.py",
        root / "src/re_agent/utils/mutation_intent.py",
    )
    forbidden = {
        "COLLISION_KEYWORDS",
        "CURRENCY_KEYWORDS",
        "FRAMEWORK_STOPWORDS",
        "INTENT_MODIFIERS",
        "INTENT_VERBS",
        "MUTATION_MAXIMIZE_WORDS",
        "MUTATION_INCREASE_ACTIONS",
        "MUTATION_ENABLE_ACTIONS",
        "MUTATION_NEGATIVE_ACTIONS",
        "MUTATION_POSITIVE_ACTIONS",
        "MUTATION_ZERO_WORDS",
        "NUMBER_WORD_LITERALS",
    }
    for consumer in consumers:
        tree = ast.parse(consumer.read_text(encoding="utf-8"))
        assigned = {
            target.id
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Name)
        }
        assert not assigned & forbidden, consumer
