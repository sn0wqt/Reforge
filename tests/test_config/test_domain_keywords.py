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


def test_consumers_do_not_redefine_domain_keyword_constants() -> None:
    root = Path(__file__).parents[2]
    consumers = (
        root / "src/re_agent/cli/cmd_batch.py",
        root / "src/re_agent/cli/cmd_hook.py",
        root / "src/re_agent/llm/semantic_analyzer.py",
        root / "src/re_agent/utils/goal_parser.py",
    )
    forbidden = {
        "COLLISION_KEYWORDS",
        "CURRENCY_KEYWORDS",
        "FRAMEWORK_STOPWORDS",
        "INTENT_MODIFIERS",
        "INTENT_VERBS",
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
