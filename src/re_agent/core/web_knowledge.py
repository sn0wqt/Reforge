"""Bundled offline framework-pattern knowledge.

Provides generic architectural patterns across mobile and desktop app frameworks
(Unity, React Native, Native Android DEX, iOS, and Unreal Engine).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class KnownGamePattern:
    """Generic architectural pattern for a framework or engine."""

    game_name: str
    target_classes: list[str]
    description: str


# Generic architectural patterns across app frameworks (no game-specific hardcoding)
_KNOWN_GAME_PATTERNS: dict[str, KnownGamePattern] = {
    "unity": KnownGamePattern(
        game_name="Unity IL2CPP Framework",
        target_classes=["PlayerState", "WalletData", "SessionData", "MovementController", "GameManager"],
        description="Generic Unity architecture storing state in Data models and Controller components.",
    ),
    "react-native": KnownGamePattern(
        game_name="React Native Framework",
        target_classes=["HybridRnIap", "NitroSubscriptionStatus", "PurchaseManager", "UserAccountService"],
        description="React Native apps using Native Modules / Bridges for purchase and subscription logic.",
    ),
}


def lookup_game_knowledge(game_hint: str) -> KnownGamePattern | None:
    """Look up generic reverse engineering patterns by framework hint.

    Args:
        game_hint: Framework or engine hint (e.g. 'unity', 'react-native').

    Returns:
        A ``KnownGamePattern`` object if matched, or None.
    """
    hint_lower = game_hint.lower()
    for key, pattern in _KNOWN_GAME_PATTERNS.items():
        if key in hint_lower:
            logger.info("[BundledKnowledge] Matched framework pattern for %s", pattern.game_name)
            return pattern
    return None
