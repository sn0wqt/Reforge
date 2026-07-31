"""Immutable domain vocabulary shared by goal and candidate analysis.

Keep intent, entity, framework, and ranking terminology here so every binary
pathway applies the same filtering and expansion rules.
"""

from __future__ import annotations

import re
from typing import Final

INTENT_VERBS: Final[frozenset[str]] = frozenset(
    {
        "add",
        "award",
        "bypass",
        "disable",
        "enable",
        "get",
        "give",
        "grant",
        "has",
        "increase",
        "inject",
        "is",
        "modify",
        "mod",
        "override",
        "patch",
        "receive",
        "remove",
        "set",
        "unlock",
    }
)

INTENT_MODIFIERS: Final[frozenset[str]] = frozenset(
    {
        "all",
        "always",
        "cheat",
        "endless",
        "free",
        "full",
        "god",
        "hack",
        "infinite",
        "max",
        "maximum",
        "mode",
        "modded",
        "never",
        "no",
        "unlimited",
    }
)

CURRENCY_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "balance",
        "bank",
        "buy",
        "cash",
        "coin",
        "coins",
        "credit",
        "credits",
        "crystal",
        "crystals",
        "currencies",
        "currency",
        "diamond",
        "diamonds",
        "economy",
        "energy",
        "gem",
        "gems",
        "gold",
        "inventory",
        "key",
        "keys",
        "money",
        "price",
        "purchase",
        "rubies",
        "ruby",
        "shard",
        "shards",
        "shop",
        "stamina",
        "store",
        "token",
        "tokens",
        "wallet",
    }
)

# Some game-resource words are also heavily overloaded framework terms. They
# require gameplay/economy context before becoming currency candidates.
AMBIGUOUS_CURRENCY_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "key",
        "keys",
        "token",
        "tokens",
    }
)

CORE_CURRENCY_VALUE_KEYWORDS: Final[frozenset[str]] = (
    CURRENCY_KEYWORDS
    - frozenset(
        {
            "buy",
            "economy",
            "inventory",
            "price",
            "purchase",
            "shop",
            "store",
        }
    )
)

ECONOMY_DATA_HINTS: Final[frozenset[str]] = frozenset(
    {
        "account",
        "inventory",
        "model",
        "profile",
        "runner",
        "save",
        "session",
        "state",
        "storage",
        "wallet",
    }
)

NON_BALANCE_VALUE_HINTS: Final[frozenset[str]] = frozenset(
    {
        "after",
        "attach",
        "before",
        "cap",
        "color",
        "cooldown",
        "cost",
        "decimal",
        "delay",
        "duration",
        "expiration",
        "formatter",
        "group",
        "height",
        "id",
        "index",
        "mapping",
        "offset",
        "percent",
        "per",
        "price",
        "range",
        "ratio",
        "spent",
        "symbol",
        "text",
        "time",
        "width",
    }
)

GAMEPLAY_RESOURCE_CONTEXT_HINTS: Final[frozenset[str]] = frozenset(
    {
        "available",
        "balance",
        "booster",
        "count",
        "currency",
        "economy",
        "inventory",
        "owned",
        "profile",
        "purchase",
        "reward",
        "revive",
        "runner",
        "shop",
        "store",
        "use",
        "wallet",
    }
)

NON_GAMEPLAY_RESOURCE_HINTS: Final[frozenset[str]] = frozenset(
    {
        "aes",
        "algorithm",
        "assembly",
        "auth",
        "cache",
        "certificate",
        "cipher",
        "cng",
        "codec",
        "composer",
        "concurrent",
        "container",
        "crypto",
        "datarelation",
        "datarow",
        "datatable",
        "des",
        "dictionary",
        "dsa",
        "ecdsa",
        "encrypt",
        "foreign",
        "hash",
        "hmac",
        "input",
        "keyboard",
        "keyvalue",
        "license",
        "lookup",
        "machine",
        "metadata",
        "metric",
        "pair",
        "playerprefs",
        "primary",
        "private",
        "provider",
        "public",
        "persistence",
        "reflection",
        "rsa",
        "secret",
        "serialization",
        "ssh",
    }
)

NON_RUNTIME_CLASS_HINTS: Final[frozenset[str]] = frozenset(
    {
        "adapter",
        "builder",
        "comparer",
        "extension",
        "factory",
        "formatter",
        "helper",
        "implementation",
        "initializer",
        "merger",
        "migrator",
        "request",
        "serializer",
        "test",
    }
)

COLLISION_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "character",
        "collide",
        "collider",
        "collision",
        "damage",
        "death",
        "die",
        "godmode",
        "health",
        "hit",
        "invincible",
        "invulnerable",
        "kill",
        "motor",
        "noclip",
        "obstacle",
        "physics",
        "player",
        "stumble",
        "vulnerability",
    }
)

MOVEMENT_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "fast",
        "flight",
        "fly",
        "jump",
        "locomotion",
        "move",
        "movement",
        "speed",
        "teleport",
        "velocity",
    }
)

SUBSCRIPTION_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "billing",
        "entitlement",
        "iap",
        "license",
        "limit",
        "membership",
        "pass",
        "premium",
        "pro",
        "quota",
        "sub",
        "subscriber",
        "subscription",
        "subscriptions",
        "tier",
        "vip",
    }
)

FRAMEWORK_STOPWORDS: Final[frozenset[str]] = frozenset(
    {
        "action",
        "app",
        "code",
        "component",
        "config",
        "data",
        "event",
        "file",
        "id",
        "item",
        "items",
        "key",
        "max",
        "min",
        "name",
        "options",
        "process",
        "profile",
        "progress",
        "project",
        "promise",
        "prompt",
        "property",
        "props",
        "protocol",
        "pro",
        "provider",
        "ref",
        "state",
        "status",
        "style",
        "sub",
        "text",
        "type",
        "value",
        "view",
    }
)

QUERY_STOPWORDS: Final[frozenset[str]] = frozenset(
    {
        "a",
        "an",
        "and",
        "as",
        "be",
        "do",
        "find",
        "for",
        "game",
        "have",
        "how",
        "in",
        "info",
        "it",
        "make",
        "of",
        "offset",
        "offsets",
        "on",
        "or",
        "system",
        "that",
        "the",
        "their",
        "there",
        "this",
        "to",
        "with",
    }
)

MODEL_HINTS: Final[frozenset[str]] = frozenset(
    {
        "account",
        "balance",
        "cache",
        "character",
        "collider",
        "collision",
        "config",
        "controller",
        "data",
        "handler",
        "hit",
        "inventory",
        "manager",
        "model",
        "motor",
        "movement",
        "obstacle",
        "pawn",
        "physics",
        "player",
        "profile",
        "provider",
        "runner",
        "save",
        "service",
        "session",
        "state",
        "stats",
        "storage",
        "wallet",
    }
)

UI_PENALTY_HINTS: Final[frozenset[str]] = frozenset(
    {
        "ad",
        "ads",
        "analytics",
        "animation",
        "animator",
        "audio",
        "banner",
        "bar",
        "button",
        "clip",
        "comparer",
        "decor",
        "decoration",
        "delegate",
        "dialog",
        "drawer",
        "effect",
        "effects",
        "enumerator",
        "event",
        "formatter",
        "hud",
        "icon",
        "label",
        "listener",
        "notification",
        "observer",
        "panel",
        "popup",
        "promo",
        "renderer",
        "screen",
        "slice",
        "sound",
        "spawner",
        "text",
        "theme",
        "themed",
        "toast",
        "tooltip",
        "track",
        "tutorial",
        "tween",
        "visual",
        "visuals",
        "widget",
        "wrapper",
    }
)

ENTITY_KEYWORDS: Final[frozenset[str]] = (
    CURRENCY_KEYWORDS | COLLISION_KEYWORDS | MOVEMENT_KEYWORDS | SUBSCRIPTION_KEYWORDS
)

# Domain entities win when a framework word is also meaningful to the goal,
# for example "keys", "pro", or "max".
GOAL_STOPWORDS: Final[frozenset[str]] = (
    INTENT_VERBS | INTENT_MODIFIERS | FRAMEWORK_STOPWORDS | QUERY_STOPWORDS
) - ENTITY_KEYWORDS

DOMAIN_EXPANSION_GROUPS: Final[tuple[tuple[frozenset[str], frozenset[str]], ...]] = (
    (
        COLLISION_KEYWORDS,
        frozenset(
            {
                "character",
                "collider",
                "collision",
                "damage",
                "hit",
                "motor",
                "obstacle",
                "physics",
                "player",
            }
        ),
    ),
    (
        CURRENCY_KEYWORDS,
        frozenset(
            {
                "balance",
                "bank",
                "currency",
                "economy",
                "inventory",
                "purchase",
                "shop",
                "store",
                "wallet",
            }
        ),
    ),
    (
        MOVEMENT_KEYWORDS,
        frozenset(
            {
                "flight",
                "jump",
                "locomotion",
                "motor",
                "movement",
                "speed",
                "velocity",
            }
        ),
    ),
    (
        SUBSCRIPTION_KEYWORDS,
        frozenset(
            {
                "billing",
                "entitlement",
                "iap",
                "license",
                "membership",
                "premium",
                "quota",
                "subscriber",
                "subscription",
                "tier",
                "vip",
            }
        ),
    ),
)


def is_entity_keyword(value: str) -> bool:
    """Return whether a normalized token is a known domain entity."""
    return value.lower() in ENTITY_KEYWORDS


def identifier_tokens(value: object, *, min_length: int = 1) -> frozenset[str]:
    """Split snake/camel/punctuated identifiers into normalized whole tokens."""
    text = str(value)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    return frozenset(
        token.casefold()
        for token in re.findall(r"[A-Za-z0-9]+", text)
        if len(token) >= min_length
    )


def matches_identifier_keyword(
    keyword: object,
    candidate: object,
    *,
    min_keyword_length: int = 3,
) -> bool:
    """Match complete identifier tokens, never arbitrary substrings."""
    keyword_text = str(keyword).strip()
    candidate_text = str(candidate).strip()
    if (
        len(keyword_text) < min_keyword_length
        or len(candidate_text) < min_keyword_length
    ):
        return False
    keyword_parts = identifier_tokens(keyword_text, min_length=min_keyword_length)
    candidate_parts = identifier_tokens(candidate_text)
    return bool(keyword_parts) and keyword_parts <= candidate_parts


def is_contextual_currency_match(
    keyword: object,
    class_name: object,
    member_name: object,
) -> bool:
    """Reject overloaded resource words without gameplay/economy context."""
    keyword_text = str(keyword).strip().casefold()
    if keyword_text not in AMBIGUOUS_CURRENCY_KEYWORDS:
        return True

    combined = f"{class_name} {member_name}"
    tokens = identifier_tokens(combined)
    compact = re.sub(r"[^a-z0-9]", "", combined.casefold())
    if tokens & NON_GAMEPLAY_RESOURCE_HINTS or any(
        hint in compact
        for hint in NON_GAMEPLAY_RESOURCE_HINTS
        if len(hint) >= 3
    ):
        return False
    return bool(tokens & GAMEPLAY_RESOURCE_CONTEXT_HINTS)


def has_economy_data_context(class_name: object) -> bool:
    """Return whether a class name looks like persistent gameplay economy data."""
    return bool(identifier_tokens(class_name) & ECONOMY_DATA_HINTS)


def is_balance_value_member(member_name: object) -> bool:
    """Reject prices, presentation values, identifiers, and derived metadata."""
    return not bool(identifier_tokens(member_name) & NON_BALANCE_VALUE_HINTS)


def filter_entity_terms(values: list[str]) -> list[str]:
    """Normalize and deduplicate candidate entity terms."""
    clean: list[str] = []
    seen: set[str] = set()
    for value in values:
        term = value.strip().lower()
        if len(term) <= 2 or term in GOAL_STOPWORDS or term in seen:
            continue
        if identifier_tokens(value) & (INTENT_VERBS | INTENT_MODIFIERS):
            continue
        seen.add(term)
        clean.append(term)
    return clean
