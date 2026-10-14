"""Immutable domain vocabulary shared by goal and candidate analysis.

Keep intent, entity, framework, and ranking terminology here so every binary
pathway applies the same filtering and expansion rules.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

MUTATION_NEGATIVE_ACTIONS: Final[frozenset[str]] = frozenset(
    {"block", "deactivate", "deny", "disable", "hide", "prevent", "remove", "stop"}
)
MUTATION_INCREASE_ACTIONS: Final[frozenset[str]] = frozenset({"add", "award", "give", "grant", "increase"})
MUTATION_ENABLE_ACTIONS: Final[frozenset[str]] = frozenset({"activate", "allow", "enable", "unlock"})
MUTATION_POSITIVE_ACTIONS: Final[frozenset[str]] = MUTATION_INCREASE_ACTIONS | MUTATION_ENABLE_ACTIONS
MUTATION_MAXIMIZE_ACTIONS: Final[frozenset[str]] = frozenset({"maximize"})
MUTATION_MAXIMIZE_VALUES: Final[frozenset[str]] = frozenset({"endless", "infinite", "max", "maximum", "unlimited"})
MUTATION_MAXIMIZE_WORDS: Final[frozenset[str]] = MUTATION_MAXIMIZE_ACTIONS | MUTATION_MAXIMIZE_VALUES
MUTATION_MAGNITUDE_ASSIGNMENT_ACTIONS: Final[frozenset[str]] = frozenset({"add", "increase", "set"})
MUTATION_ZERO_ACTIONS: Final[frozenset[str]] = frozenset({"clear", "reset"})
MUTATION_ZERO_VALUES: Final[frozenset[str]] = frozenset({"empty", "none", "zero"})
MUTATION_ZERO_WORDS: Final[frozenset[str]] = MUTATION_ZERO_ACTIONS | MUTATION_ZERO_VALUES
MUTATION_FALSE_WORDS: Final[frozenset[str]] = frozenset({"false", "inactive", "off"})
MUTATION_TRUE_WORDS: Final[frozenset[str]] = frozenset({"active", "on", "true"})
MUTATION_BOOLEAN_WORDS: Final[frozenset[str]] = MUTATION_FALSE_WORDS | MUTATION_TRUE_WORDS
NUMBER_WORD_LITERALS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "zero": "0",
        "one": "1",
        "two": "2",
        "three": "3",
        "four": "4",
        "five": "5",
        "six": "6",
        "seven": "7",
        "eight": "8",
        "nine": "9",
        "ten": "10",
    }
)

INTENT_VERBS: Final[frozenset[str]] = (
    frozenset(
        {
            "bypass",
            "get",
            "has",
            "inject",
            "is",
            "modify",
            "mod",
            "override",
            "patch",
            "receive",
            "rotate",
            "scan",
            "set",
            "trace",
        }
    )
    | MUTATION_NEGATIVE_ACTIONS
    | MUTATION_POSITIVE_ACTIONS
    | MUTATION_MAXIMIZE_ACTIONS
    | MUTATION_ZERO_ACTIONS
)

INTENT_MODIFIERS: Final[frozenset[str]] = (
    frozenset(
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
    | MUTATION_MAXIMIZE_VALUES
    | MUTATION_ZERO_VALUES
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

CORE_CURRENCY_VALUE_KEYWORDS: Final[frozenset[str]] = CURRENCY_KEYWORDS - frozenset(
    {
        "bank",
        "buy",
        "currencies",
        "currency",
        "economy",
        "inventory",
        "price",
        "purchase",
        "shop",
        "store",
        "wallet",
    }
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
        "label",
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
        "title",
        "time",
        "variant",
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

AD_NETWORK_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "applovin",
        "chartboost",
        "vungle",
        "ironsource",
        "singular",
        "adjust",
        "bidmachine",
        "googlemobileads",
        "unityads",
        "mopub",
        "inmobi",
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
        "collection",
        "collections",
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
        "system",
        "appstore",
        "playstore",
        "storekit",
        "store_id",
        "storeid",
        "storeurl",
        "store_url",
        "admob",
    }.union(AD_NETWORK_KEYWORDS)
)

IGNORED_SDK_PREFIXES: Final[frozenset[str]] = frozenset(
    {
        "com.appsflyer.",
        "com.singular.sdk",
        "com.adjust.sdk",
        "com.google.android.gms",
        "com.google.firebase",
        "com.inmobi",
        "com.applovin",
        "com.chartboost",
        "com.vungle",
        "com.ironsource",
        "com.unity3d.ads",
        "inmobisdk",
    }.union(AD_NETWORK_KEYWORDS)
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

# Runtime/framework namespaces that can be present in an application's DEX but
# are not application-owned code.  Keep this separate from telemetry/ad SDKs:
# these packages are useful inventory evidence, but a goal word such as
# ``max`` or ``pro`` must never turn a framework helper into an active hook.
PLATFORM_LIBRARY_PREFIXES: Final[frozenset[str]] = frozenset(
    {
        "android.",
        "androidx.",
        "android.support.",
        "dalvik.",
        "java.",
        "javax.",
        "jdk.",
        "kotlin.",
        "kotlinx.",
        "org.chromium.",
        "org.jetbrains.",
        "sun.",
    }
)

# Words that make an otherwise ordinary magnitude modifier meaningful as a
# named product, access, or service tier.  This is linguistic context, not an
# application-specific target list: it prevents ``set max coins`` from
# treating ``max`` as an entity while preserving ``Max subscription``.
NAMED_TIER_CONTEXT_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "access",
        "edition",
        "entitlement",
        "license",
        "membership",
        "package",
        "plan",
        "service",
        "subscription",
        "tier",
    }
)

NAMED_TIER_ENTITY_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "max",
        "maximum",
        "premium",
        "pro",
        "vip",
    }
)
MAXIMUM_TIER_ENTITY_KEYWORDS: Final[frozenset[str]] = NAMED_TIER_ENTITY_KEYWORDS & MUTATION_MAXIMIZE_VALUES

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
    INTENT_VERBS | INTENT_MODIFIERS | QUERY_STOPWORDS | MUTATION_BOOLEAN_WORDS | frozenset(NUMBER_WORD_LITERALS)
) - ENTITY_KEYWORDS

DOMAIN_EXPANSION_GROUPS: Final[tuple[tuple[frozenset[str], frozenset[str], frozenset[str]], ...]] = (
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
        frozenset(
            {
                "character",
                "damage",
                "death",
                "health",
                "hit",
                "kill",
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
        AMBIGUOUS_CURRENCY_KEYWORDS,
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
        frozenset({"fast", "move", "speed"}),
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
        frozenset({"license", "limit", "pass", "quota"}),
    ),
)


def is_entity_keyword(value: str) -> bool:
    """Return whether a normalized token is a known domain entity."""
    return value.lower() in ENTITY_KEYWORDS


_IRREGULAR_SINGULARS: Final[dict[str, str]] = {
    "aliases": "alias",
    "analyses": "analysis",
    "axes": "axis",
    "bases": "basis",
    "biases": "bias",
    "bonuses": "bonus",
    "canvases": "canvas",
    "chaos": "chaos",
    "cosmos": "cosmos",
    "lens": "lens",
    "news": "news",
    "statuses": "status",
    "series": "series",
    "species": "species",
}

_SINGULAR_S_ENDINGS: Final[tuple[str, ...]] = (
    "alias",
    "analysis",
    "basis",
    "bias",
    "bonus",
    "canvas",
    "is",
    "ous",
    "ss",
    "status",
    "us",
)


def singularize_entity_token(value: object) -> str:
    """Return a conservative singular form for any project entity token.

    The transformation is deliberately independent of the built-in domain
    vocabulary so an unknown app's ``orbs`` and ``licenses`` group with
    ``orb`` and ``license``.  Singular words whose endings merely resemble a
    plural (``status``, ``analysis``, ``bonus``) remain unchanged.
    """
    token = str(value).strip().casefold()
    if not token:
        return token
    irregular = _IRREGULAR_SINGULARS.get(token)
    if irregular is not None:
        return irregular
    if token.endswith(_SINGULAR_S_ENDINGS):
        return token
    if token.endswith("ies") and len(token) > 4:
        return token[:-3] + "y"
    if token.endswith(("ches", "shes", "xes", "zes", "sses")) and len(token) > 4:
        return token[:-2]
    # Most words ending in ``-se`` (license, promise, case) pluralize by
    # appending only ``s``.  Removing ``es`` would produce broken stems.
    if token.endswith("ses") and len(token) > 4:
        return token[:-1]
    if token.endswith("s") and len(token) > 3:
        return token[:-1]
    return token


def canonical_entity_token(value: object) -> str:
    """Normalize a domain entity token without conflating distinct resources.

    Plural forms collapse to their conservative singular entity (``coins``
    becomes ``coin`` and unknown ``orbs`` becomes ``orb``), while unrelated
    concepts such as coins and keys remain distinct.
    """
    return singularize_entity_token(value)


def _identifier_token_sequence(value: object, *, min_length: int = 1) -> tuple[str, ...]:
    text = str(value)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    return tuple(token.casefold() for token in re.findall(r"[A-Za-z0-9]+", text) if len(token) >= min_length)


def identifier_tokens(value: object, *, min_length: int = 1) -> frozenset[str]:
    """Split snake/camel/punctuated identifiers into normalized whole tokens."""
    return frozenset(_identifier_token_sequence(value, min_length=min_length))


def matches_identifier_keyword(
    keyword: object,
    candidate: object,
    *,
    min_keyword_length: int = 2,
) -> bool:
    """Match complete identifier tokens, never arbitrary substrings."""
    keyword_text = str(keyword).strip()
    candidate_text = str(candidate).strip()
    if len(keyword_text) < min_keyword_length or len(candidate_text) < min_keyword_length:
        return False
    keyword_parts = identifier_tokens(keyword_text, min_length=min_keyword_length)
    candidate_parts = identifier_tokens(candidate_text)
    if not keyword_parts:
        return False
    if keyword_parts <= candidate_parts:
        return True

    # A user's unknown entity may be written as one word while the recovered
    # identifier uses camel/snake word boundaries (``warpcharges`` versus
    # ``GetWarpCharges``).  Match only complete contiguous identifier-token
    # spans, not arbitrary character substrings.
    keyword_compact = "".join(
        singularize_entity_token(token)
        for token in _identifier_token_sequence(keyword_text, min_length=min_keyword_length)
    )
    candidate_sequence = _identifier_token_sequence(candidate_text)
    for start in range(len(candidate_sequence)):
        compact = ""
        for token in candidate_sequence[start:]:
            compact += singularize_entity_token(token)
            if compact == keyword_compact:
                return True
            if len(compact) >= len(keyword_compact):
                break
    return False


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
        hint in compact for hint in NON_GAMEPLAY_RESOURCE_HINTS if len(hint) >= 3
    ):
        return False
    return bool(tokens & GAMEPLAY_RESOURCE_CONTEXT_HINTS)


def has_economy_data_context(class_name: object) -> bool:
    """Return whether a class name looks like persistent gameplay economy data."""
    return bool(identifier_tokens(class_name) & ECONOMY_DATA_HINTS)


def is_named_tier_match_contextual(
    keyword: object,
    class_name: object,
    member_name: object,
) -> bool:
    """Require product/access context for overloaded tier words.

    Names such as ``SubscriptionState.hasPro`` and ``Plan.getMax`` carry
    behavioral tier context.  ``getMaxToolbarItems`` and
    ``isRedmiNote9Pro`` do not.  The rule is linguistic and namespace-neutral;
    it contains no application, publisher, or product names.
    """
    normalized_keyword = singularize_entity_token(str(keyword).strip().casefold())
    if normalized_keyword not in NAMED_TIER_ENTITY_KEYWORDS:
        return True
    surrounding_tokens = {
        singularize_entity_token(token)
        for token in identifier_tokens(f"{class_name} {member_name}")
        if singularize_entity_token(token) != normalized_keyword
    }
    return bool(surrounding_tokens & NAMED_TIER_CONTEXT_KEYWORDS)


def is_platform_library_class(class_name: object) -> bool:
    """Return whether a dotted DEX class belongs to a platform namespace."""
    normalized = str(class_name).strip().casefold()
    return any(normalized.startswith(prefix) for prefix in PLATFORM_LIBRARY_PREFIXES)


def is_balance_value_member(member_name: object) -> bool:
    """Reject prices, presentation values, identifiers, and derived metadata."""
    return not bool(identifier_tokens(member_name) & NON_BALANCE_VALUE_HINTS)


def filter_entity_terms(values: list[str]) -> list[str]:
    """Normalize and deduplicate candidate entity terms."""
    normalized_values = [value.strip().casefold() for value in values]
    has_named_tier_context = bool(
        {singularize_entity_token(value) for value in normalized_values} & NAMED_TIER_CONTEXT_KEYWORDS
    )
    clean: list[str] = []
    seen: set[str] = set()
    for value in values:
        term = value.strip().casefold()
        contextual_tier = term in {"max", "maximum"} and has_named_tier_context
        if len(term) <= 1 or (term in GOAL_STOPWORDS and not contextual_tier) or term in seen:
            continue
        if not contextual_tier and identifier_tokens(value) & (INTENT_VERBS | INTENT_MODIFIERS):
            continue
        seen.add(term)
        clean.append(term)
    return clean
