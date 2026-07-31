"""Shared confidence ranking and presentation for every binary pathway."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any, TextIO

from re_agent.config.domain_keywords import (
    CORE_CURRENCY_VALUE_KEYWORDS,
    ECONOMY_DATA_HINTS,
    NON_BALANCE_VALUE_HINTS,
    NON_RUNTIME_CLASS_HINTS,
    UI_PENALTY_HINTS,
    identifier_tokens,
)
from re_agent.llm.analyzed_target import AnalyzedTarget

PRIMARY_CONFIDENCE_THRESHOLD = 85
PRIMARY_CANDIDATE_LIMIT = 5


def target_activation_facts(
    target: AnalyzedTarget | None = None,
    *,
    engine_type: str = "",
    hook_type: str = "",
    evidence: dict[str, Any] | None = None,
) -> dict[str, bool]:
    """Centralized activation readiness validation across IL2CPP and DEX pathways."""
    ev = evidence or {}
    h_type = hook_type or (target.hook_type if target is not None else "")
    offset = (target.offset if target is not None and target.offset is not None else None) or ev.get("offset")
    method_rva = (target.method_rva if target is not None and target.method_rva is not None else None) or ev.get("rva")
    descriptor = (target.method_descriptor if target is not None and target.method_descriptor is not None else None) or ev.get("descriptor")

    exact_java_override = (
        h_type == "return_override"
        and ev.get("is_declared") is True
        and ev.get("is_executable") is True
        and ev.get("is_constructor") is False
        and isinstance(ev.get("is_static"), bool)
        and bool(descriptor)
    )
    il2cpp_method_verified = (
        h_type in {"return_override", "skip_call", "nop", "speed_modify"}
        and isinstance(method_rva, int)
        and not isinstance(method_rva, bool)
        and method_rva > 0
    )
    il2cpp_field_verified = (
        engine_type.startswith("unity-il2cpp")
        and h_type in {"memory_patch", "multi_memory_patch"}
        and isinstance(offset, int)
        and not isinstance(offset, bool)
        and offset >= 0
    )
    verified = exact_java_override or il2cpp_method_verified or il2cpp_field_verified
    return {
        "signature_verified": verified,
        "address_verified": verified,
        "implementation_ready": verified,
    }


@dataclass(frozen=True)
class CandidateGroups:
    """Ranked primary and secondary hook candidates."""

    primary: tuple[AnalyzedTarget, ...]
    secondary: tuple[AnalyzedTarget, ...]

    @property
    def all(self) -> tuple[AnalyzedTarget, ...]:
        return self.primary + self.secondary


def _candidate_key(
    target: AnalyzedTarget,
) -> tuple[str, str, str, int | None, int | None, tuple[str, ...]]:
    return (
        target.class_name.casefold(),
        target.target.casefold(),
        target.hook_type,
        target.offset,
        target.method_rva,
        target.parameter_types,
    )


def _semantic_priority(target: AnalyzedTarget) -> int:
    """Break confidence ties in favor of state storage and direct value access."""
    class_tokens = identifier_tokens(target.class_name)
    member_tokens = identifier_tokens(target.target)
    score = 0

    score += 45 * len(
        class_tokens
        & (ECONOMY_DATA_HINTS - frozenset({"model", "runner", "state"}))
    )
    score += 20 * len(class_tokens & {"model", "runner", "state"})

    ignored_member_words = {
        "available",
        "current",
        "for",
        "get",
        "has",
        "m",
        "raw",
        "the",
        "total",
        "use",
    }
    value_words = member_tokens - ignored_member_words
    if value_words and value_words <= CORE_CURRENCY_VALUE_KEYWORDS:
        score += 90
    elif member_tokens & CORE_CURRENCY_VALUE_KEYWORDS:
        score += 20

    score -= 45 * len(member_tokens & NON_BALANCE_VALUE_HINTS)
    score -= 40 * len(class_tokens & UI_PENALTY_HINTS)
    score -= 50 * len(class_tokens & NON_RUNTIME_CLASS_HINTS)
    if target.return_type == "bool":
        score -= 15
    if target.method_rva is not None or target.offset is not None:
        score += 5
    if target.signature_verified:
        score += 10
    if target.address_verified:
        score += 10
    if target.implementation_ready:
        score += 10
    if target.parameter_types:
        score -= 30
    return score


def _ranking_key(target: AnalyzedTarget) -> tuple[int, int, str, str, str]:
    return (
        -target.confidence,
        -_semantic_priority(target),
        target.class_name.casefold(),
        target.target.casefold(),
        target.hook_type,
    )


def rank_candidates(
    targets: Iterable[AnalyzedTarget],
) -> tuple[AnalyzedTarget, ...]:
    """Deduplicate exact targets and retain the highest-confidence instance."""
    best: dict[
        tuple[str, str, str, int | None, int | None, tuple[str, ...]],
        AnalyzedTarget,
    ] = {}
    for target in targets:
        normalized = replace(
            target,
            confidence=max(0, min(100, int(target.confidence))),
        )
        key = _candidate_key(normalized)
        previous = best.get(key)
        if previous is None or normalized.confidence > previous.confidence:
            best[key] = normalized
    exact_ranked = tuple(
        sorted(
            best.values(),
            key=_ranking_key,
        )
    )
    by_member: dict[tuple[str, str, tuple[str, ...]], list[AnalyzedTarget]] = {}
    for target in exact_ranked:
        by_member.setdefault(
            (
                target.class_name.casefold(),
                target.target.casefold(),
                target.parameter_types,
            ),
            [],
        ).append(target)
    conflict_ids = {
        identity
        for identity, members in by_member.items()
        if len(
            {
                (
                    member.hook_type,
                    member.offset,
                    member.method_rva,
                    member.parameter_types,
                    member.return_type,
                    member.return_value,
                )
                for member in members
            }
        )
        > 1
    }
    if not conflict_ids:
        return exact_ranked
    conflicted = [
        replace(
            target,
            confidence=min(target.confidence, PRIMARY_CONFIDENCE_THRESHOLD - 1),
            reason=(
                "Conflicting candidate strategies require manual resolution. "
                + target.reason
            ).strip(),
        )
        if (
            target.class_name.casefold(),
            target.target.casefold(),
            target.parameter_types,
        ) in conflict_ids
        else target
        for target in exact_ranked
    ]
    return tuple(
        sorted(
            conflicted,
            key=_ranking_key,
        )
    )


def _extract_entity_concept(target: AnalyzedTarget) -> str:
    """Extract the primary domain entity concept (e.g., coins, keys) for entity disambiguation."""
    tokens = identifier_tokens(target.target) | identifier_tokens(target.class_name)
    currency_hits = tokens & CORE_CURRENCY_VALUE_KEYWORDS
    if currency_hits:
        return sorted(currency_hits)[0]
    return f"{target.class_name.casefold()}::{target.target.casefold()}"


def split_candidates(
    targets: Iterable[AnalyzedTarget],
    *,
    confidence_threshold: int = PRIMARY_CONFIDENCE_THRESHOLD,
    primary_limit: int = PRIMARY_CANDIDATE_LIMIT,
    goal_prompt: str | None = None,
) -> CandidateGroups:
    """Select 1 primary state target per distinct entity concept up to primary_limit, retaining remainder in secondary."""
    ranked = rank_candidates(targets)
    high_conf = [t for t in ranked if t.confidence >= confidence_threshold]

    primary: list[AnalyzedTarget] = []
    seen_entities: set[str] = set()
    specific_entities = {"coins", "keys", "gems"}
    has_specific_currency_targets = any(
        _extract_entity_concept(t) in specific_entities for t in high_conf
    )

    for target in high_conf:
        entity = _extract_entity_concept(target)
        if has_specific_currency_targets and entity not in specific_entities:
            continue
        if entity not in seen_entities:
            seen_entities.add(entity)
            primary.append(target)
            if len(primary) >= primary_limit:
                break

    primary_ids = {id(target) for target in primary}
    secondary = tuple(target for target in ranked if id(target) not in primary_ids)
    return CandidateGroups(primary=tuple(primary), secondary=secondary)


def format_candidate(target: AnalyzedTarget) -> str:
    """Format one candidate with its exact confidence and evidence."""
    if target.offset is not None:
        address = f" @ field +0x{target.offset:X}"
    elif target.method_rva is not None:
        address = f" @ method RVA 0x{target.method_rva:X}"
    else:
        address = ""
    signature = (
        f"({', '.join(target.parameter_types)})"
        if target.parameter_types
        else ""
    )
    reason = f" -> {target.reason}" if target.reason else ""
    readiness = (
        " [ACTIVE-READY]"
        if (
            target.signature_verified is True
            and target.address_verified is True
            and target.implementation_ready is True
        )
        else " [REVIEW-ONLY]"
    )
    return (
        f"[{target.confidence}%] {target.class_name}::{target.target}{signature}"
        f"{address} ({target.hook_type}){readiness}{reason}"
    )


def render_candidate_summary(
    targets: Iterable[AnalyzedTarget],
    *,
    confidence_threshold: int = PRIMARY_CONFIDENCE_THRESHOLD,
    primary_limit: int = PRIMARY_CANDIDATE_LIMIT,
    goal_prompt: str | None = None,
) -> str:
    """Render primary targets and the complete expanded-candidate remainder."""
    groups = split_candidates(
        targets,
        confidence_threshold=confidence_threshold,
        primary_limit=primary_limit,
    )
    lines = [
        f"TOP HIGH-CONFIDENCE TARGETS (>={confidence_threshold}%, max {primary_limit})",
    ]
    if groups.primary:
        lines.extend(f"  {index}. {format_candidate(target)}" for index, target in enumerate(groups.primary, 1))
    else:
        lines.append("  No candidate met the high-confidence threshold.")

    lines.append("")
    lines.append(f"EXPANDED CANDIDATES SUMMARY ({len(groups.secondary)} remaining)")
    if groups.secondary:
        lines.extend(f"  {index}. {format_candidate(target)}" for index, target in enumerate(groups.secondary, 1))
    else:
        lines.append("  No additional candidates.")
    return "\n".join(lines)


def print_candidate_summary(
    targets: Iterable[AnalyzedTarget],
    *,
    stream: TextIO,
    confidence_threshold: int = PRIMARY_CONFIDENCE_THRESHOLD,
    primary_limit: int = PRIMARY_CANDIDATE_LIMIT,
    goal_prompt: str | None = None,
) -> CandidateGroups:
    """Print the universal terminal candidate display and return its grouping."""
    target_list = list(targets)
    print(
        render_candidate_summary(
            target_list,
            confidence_threshold=confidence_threshold,
            primary_limit=primary_limit,
            goal_prompt=goal_prompt,
        ),
        file=stream,
    )
    return split_candidates(
        target_list,
        confidence_threshold=confidence_threshold,
        primary_limit=primary_limit,
        goal_prompt=goal_prompt,
    )
