"""Tests for goal_parser.py utility."""

from re_agent.utils.goal_parser import extract_entity_keywords


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
