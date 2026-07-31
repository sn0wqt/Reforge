"""Unit tests for web_knowledge module."""
from __future__ import annotations

from re_agent.core.web_knowledge import lookup_game_knowledge


def test_lookup_game_knowledge_unity() -> None:
    res = lookup_game_knowledge("Unity Game Target")
    assert res is not None
    assert "Unity" in res.game_name
    assert "PlayerState" in res.target_classes


def test_lookup_game_knowledge_react_native() -> None:
    res = lookup_game_knowledge("React-Native Application")
    assert res is not None
    assert "HybridRnIap" in res.target_classes


def test_lookup_game_knowledge_unknown() -> None:
    res = lookup_game_knowledge("UnknownIndieGame123")
    assert res is None
