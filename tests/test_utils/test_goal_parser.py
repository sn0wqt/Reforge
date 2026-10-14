"""Tests for goal_parser.py utility."""

from re_agent.utils.goal_parser import expand_goal_terms, extract_entity_keywords


def test_extract_entity_keywords_basic():
    prompt = "grant unlimited diamonds"
    entities = extract_entity_keywords(prompt)
    assert "diamonds" in entities
    assert "diamond" in entities
    assert "grant" not in entities
    assert "unlimited" not in entities


def test_extract_entity_keywords_complex():
    prompt = "set infinite coins and gems"
    entities = extract_entity_keywords(prompt)
    assert "coins" in entities
    assert "coin" in entities
    assert "gems" in entities
    assert "gem" in entities
    assert "set" not in entities
    assert "infinite" not in entities


def test_extract_entity_keywords_plural_ies() -> None:
    entities = extract_entity_keywords("grant currencies and rubies")
    assert "currency" in entities
    assert "ruby" in entities
    assert "currencie" not in entities
    assert "rubie" not in entities


def test_extract_entity_keywords_does_not_damage_us_or_is_words() -> None:
    entities = extract_entity_keywords("award bonus status analysis")
    assert "bonus" in entities
    assert "bonu" not in entities
    assert "analysi" not in entities


def test_unknown_plural_entities_get_reusable_singular_variants() -> None:
    entities = extract_entity_keywords("grant orbs and licenses")

    assert entities == ["orbs", "orb", "licenses", "license"]


def test_explicit_two_character_entities_are_preserved() -> None:
    entities = extract_entity_keywords("set XP and HP")

    assert entities == ["xp", "hp"]


def test_max_is_preserved_as_a_subscription_tier_name() -> None:
    entities = extract_entity_keywords("unlock Pro and Max subscriptions")

    assert "pro" in entities
    assert "max" in entities
    assert "subscriptions" in entities


def test_max_remains_an_intent_modifier_without_tier_context() -> None:
    entities = extract_entity_keywords("set max coins")

    assert "max" not in entities
    assert "coins" in entities


def test_max_is_not_promoted_by_incidental_service_context() -> None:
    entities = extract_entity_keywords("set max service retries")

    assert "max" not in entities
    assert {"service", "retries", "retry"} <= set(entities)


def test_application_neutral_entities_survive_while_actions_and_values_do_not() -> None:
    assert extract_entity_keywords("set status to active") == ["status"]
    assert extract_entity_keywords("prevent telemetry") == ["telemetry"]
    assert extract_entity_keywords("reset retries") == ["retries", "retry"]
    assert extract_entity_keywords("set retries to 12") == ["retries", "retry"]


def test_ambiguous_terms_do_not_inject_unrelated_domain_expansions() -> None:
    key_terms = expand_goal_terms("rotate encryption keys")
    quota_terms = expand_goal_terms("increase API quota")
    speed_terms = expand_goal_terms("increase download speed")

    assert "wallet" not in key_terms
    assert "billing" not in quota_terms
    assert "flight" not in speed_terms
    assert "key" in key_terms
    assert "quota" in quota_terms
    assert "speed" in speed_terms
    assert "wallet" in expand_goal_terms("grant coins")
