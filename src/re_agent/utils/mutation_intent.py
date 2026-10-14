"""Conservative, application-neutral primitive mutation intent inference.

This module translates an explicit natural-language action into a primitive
literal only when the requested direction and the recovered value type agree.
It intentionally knows nothing about games, currencies, subscriptions, or any
other application domain.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

from re_agent.config.domain_keywords import (
    MUTATION_ENABLE_ACTIONS,
    MUTATION_FALSE_WORDS,
    MUTATION_INCREASE_ACTIONS,
    MUTATION_MAXIMIZE_WORDS,
    MUTATION_NEGATIVE_ACTIONS,
    MUTATION_POSITIVE_ACTIONS,
    MUTATION_TRUE_WORDS,
    MUTATION_ZERO_WORDS,
    NUMBER_WORD_LITERALS,
)

SAFE_CPP_TYPES = frozenset({"int32_t", "int64_t", "float", "double", "bool", "void", "void*"})
MUTABLE_SCALAR_CPP_TYPES = frozenset({"int32_t", "int64_t", "float", "double", "bool"})
DEX_SCALAR_TYPE_MAP = {
    "boolean": "bool",
    "byte": "int32_t",
    "char": "int32_t",
    "double": "double",
    "float": "float",
    "int": "int32_t",
    "long": "int64_t",
    "short": "int32_t",
}

_BOOLEAN_TYPES = frozenset({"bool", "boolean", "system.boolean", "z"})
_INTEGER_TYPES = frozenset(
    {
        "byte",
        "char",
        "int",
        "int16",
        "int16_t",
        "int32",
        "int32_t",
        "int64",
        "int64_t",
        "long",
        "safeint",
        "safelong",
        "sbyte",
        "short",
        "system.byte",
        "system.char",
        "system.int16",
        "system.int32",
        "system.int64",
        "system.sbyte",
        "system.uint16",
        "system.uint32",
        "system.uint64",
        "uint",
        "uint16",
        "uint16_t",
        "uint32",
        "uint32_t",
        "uint64",
        "uint64_t",
        "ulong",
    }
)
_FLOAT_TYPES = frozenset({"double", "float", "system.double", "system.single"})

_NUMBER_LITERAL = re.compile(r"[-+]?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")

_INTEGER_RANGES = {
    "byte": (-128, 127),
    "char": (0, 65_535),
    "int": (-2_147_483_648, 2_147_483_647),
    "int16": (-32_768, 32_767),
    "int16_t": (-32_768, 32_767),
    "int32": (-2_147_483_648, 2_147_483_647),
    "int32_t": (-2_147_483_648, 2_147_483_647),
    "int64": (-9_223_372_036_854_775_808, 9_223_372_036_854_775_807),
    "int64_t": (-9_223_372_036_854_775_808, 9_223_372_036_854_775_807),
    "long": (-9_223_372_036_854_775_808, 9_223_372_036_854_775_807),
    "safelong": (-9_223_372_036_854_775_808, 9_223_372_036_854_775_807),
    "safeint": (-2_147_483_648, 2_147_483_647),
    "sbyte": (-128, 127),
    "short": (-32_768, 32_767),
    "system.byte": (0, 255),
    "system.char": (0, 65_535),
    "system.int16": (-32_768, 32_767),
    "system.int32": (-2_147_483_648, 2_147_483_647),
    "system.int64": (-9_223_372_036_854_775_808, 9_223_372_036_854_775_807),
    "system.sbyte": (-128, 127),
    "system.uint16": (0, 65_535),
    "system.uint32": (0, 4_294_967_295),
    "system.uint64": (0, 18_446_744_073_709_551_615),
    "uint": (0, 4_294_967_295),
    "uint16": (0, 65_535),
    "uint16_t": (0, 65_535),
    "uint32": (0, 4_294_967_295),
    "uint32_t": (0, 4_294_967_295),
    "uint64": (0, 18_446_744_073_709_551_615),
    "uint64_t": (0, 18_446_744_073_709_551_615),
    "ulong": (0, 18_446_744_073_709_551_615),
}
_FLOAT_MAXIMA = {
    "double": Decimal("1.7976931348623157e308"),
    "float": Decimal("3.4028235e38"),
    "system.double": Decimal("1.7976931348623157e308"),
    "system.single": Decimal("3.4028235e38"),
}


def primitive_literal_kind(value: object) -> str | None:
    """Return ``bool``, ``integer``, ``float``, or ``null`` for a JS literal."""
    literal = str(value).strip().casefold()
    if literal in {"true", "false"}:
        return "bool"
    if literal == "null":
        return "null"
    if not _NUMBER_LITERAL.fullmatch(literal):
        return None
    return "float" if any(marker in literal for marker in (".", "e")) else "integer"


def primitive_type_kind(type_name: object) -> str | None:
    """Normalize common DEX, C#, C++, and Objective-C scalar type names."""
    normalized = re.sub(r"\s+", "", str(type_name)).casefold()
    if normalized in _BOOLEAN_TYPES:
        return "bool"
    if normalized in _INTEGER_TYPES:
        return "integer"
    if normalized in _FLOAT_TYPES:
        return "float"
    return None


def _explicit_number(goal: str) -> str | None:
    # Prefer values introduced by assignment language so version numbers or
    # digits embedded in entity names do not silently become patch values.
    assigned = re.search(
        r"(?:\bto\b|=)\s*([-+]?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)\b",
        goal,
        re.IGNORECASE,
    )
    if assigned:
        return assigned.group(1)
    tokens = re.findall(r"\b[a-z]+\b", goal.casefold())
    for token in tokens:
        if token in NUMBER_WORD_LITERALS:
            return NUMBER_WORD_LITERALS[token]
    return None


def infer_primitive_replacement(
    goal: str,
    *,
    type_name: object | None = None,
    current_literal: object | None = None,
) -> str | None:
    """Infer a type-compatible replacement, or ``None`` when ambiguous.

    ``current_literal`` is used for textual JavaScript evidence. ``type_name``
    is used for DEX/native metadata. If both are supplied they must agree.
    """
    literal_kind = primitive_literal_kind(current_literal) if current_literal is not None else None
    type_kind = primitive_type_kind(type_name) if type_name is not None else None
    if literal_kind == "null" or (literal_kind and type_kind and literal_kind != type_kind):
        return None
    kind = literal_kind or type_kind
    if kind not in {"bool", "integer", "float"}:
        return None

    tokens = set(re.findall(r"\b[a-z]+\b", goal.casefold()))
    explicit = _explicit_number(goal)
    explicit_bool: str | None = None
    if tokens & MUTATION_FALSE_WORDS:
        explicit_bool = "false"
    elif tokens & MUTATION_TRUE_WORDS:
        explicit_bool = "true"

    if kind == "bool":
        if explicit in {"0", "0.0"}:
            return "false"
        if explicit in {"1", "1.0"}:
            return "true"
        if explicit is not None:
            return None
        if explicit_bool is not None:
            return explicit_bool
        if tokens & (MUTATION_NEGATIVE_ACTIONS | MUTATION_ZERO_WORDS):
            return "false"
        if tokens & (MUTATION_POSITIVE_ACTIONS | MUTATION_MAXIMIZE_WORDS):
            return "true"
        return None

    if explicit is not None:
        if kind == "integer" and not re.fullmatch(r"[-+]?\d+", explicit):
            return None
        normalized_type = re.sub(r"\s+", "", str(type_name)).casefold()
        integer_range = _INTEGER_RANGES.get(normalized_type)
        if kind == "integer" and integer_range is not None:
            numeric_value = int(explicit)
            if not integer_range[0] <= numeric_value <= integer_range[1]:
                return None
        if kind == "integer":
            return explicit
        float_maximum = _FLOAT_MAXIMA.get(normalized_type)
        if float_maximum is not None:
            try:
                if abs(Decimal(explicit)) > float_maximum:
                    return None
            except InvalidOperation:
                return None
        return explicit if any(marker in explicit.casefold() for marker in (".", "e")) else f"{explicit}.0"
    if tokens & (MUTATION_NEGATIVE_ACTIONS | MUTATION_ZERO_WORDS):
        return "0" if kind == "integer" else "0.0"
    if tokens & MUTATION_MAXIMIZE_WORDS or tokens & MUTATION_INCREASE_ACTIONS:
        normalized_type = re.sub(r"\s+", "", str(type_name)).casefold()
        integer_range = _INTEGER_RANGES.get(normalized_type)
        if kind == "integer":
            return str(integer_range[1]) if integer_range is not None else "999999999"
        return "999999999.0"
    if tokens & MUTATION_ENABLE_ACTIONS:
        return "1" if kind == "integer" else "1.0"
    return None


def replacement_matches_literal(replacement: object, current_literal: object) -> bool:
    """Return whether a proposed JS replacement preserves primitive type."""
    replacement_kind = primitive_literal_kind(replacement)
    current_kind = primitive_literal_kind(current_literal)
    return replacement_kind is not None and replacement_kind == current_kind and current_kind != "null"
