"""Shared confidence ranking and presentation for every binary pathway."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any, TextIO, TypedDict

from reforge.config.domain_keywords import (
    COLLISION_KEYWORDS,
    CURRENCY_KEYWORDS,
    ENTITY_KEYWORDS,
    MOVEMENT_KEYWORDS,
    NAMED_TIER_ENTITY_KEYWORDS,
    SUBSCRIPTION_KEYWORDS,
    canonical_entity_token,
    identifier_tokens,
    matches_identifier_keyword,
)
from reforge.llm.analyzed_target import AnalyzedTarget
from reforge.utils.goal_parser import extract_entity_keywords
from reforge.utils.mutation_intent import DEX_SCALAR_TYPE_MAP, primitive_type_kind

PRIMARY_CONFIDENCE_THRESHOLD = 85
PRIMARY_CANDIDATE_LIMIT = 5
_JAVA_DEX_ENGINES = frozenset({"android-java-dex", "react-native-hermes"})
_DEX_PRIMITIVE_RETURN_TYPES = frozenset(DEX_SCALAR_TYPE_MAP)


class ActivationFacts(TypedDict):
    """Exactly the readiness fields accepted by :class:`AnalyzedTarget`."""

    signature_verified: bool
    address_verified: bool
    implementation_ready: bool


def target_activation_facts(
    target: AnalyzedTarget | None = None,
    *,
    engine_type: str = "",
    hook_type: str = "",
    evidence: dict[str, Any] | None = None,
) -> ActivationFacts:
    """Return evidence facts without treating native address evidence as ABI proof.

    Exact Java/DEX primitive overrides and exact IL2CPP integer/bool method-RVA
    overrides are implementation-ready for their corresponding Frida
    generators. Other native RVAs and field offsets may prove an address but
    do not prove mutation safety.
    """
    ev = evidence or {}
    h_type = hook_type or (target.hook_type if target is not None else "")
    offset = target.offset if target is not None and target.offset is not None else ev.get("offset")
    method_rva = target.method_rva if target is not None and target.method_rva is not None else ev.get("rva")
    descriptor = (
        target.method_descriptor if target is not None and target.method_descriptor is not None else None
    ) or ev.get("descriptor")

    exact_java_override = (
        engine_type in _JAVA_DEX_ENGINES
        and h_type == "return_override"
        and ev.get("is_declared") is True
        and ev.get("is_executable") is True
        and ev.get("is_constructor") is False
        and isinstance(ev.get("is_static"), bool)
        and bool(descriptor)
        and str(ev.get("return_type", "")).casefold() in _DEX_PRIMITIVE_RETURN_TYPES
    )
    native_method_address = (
        engine_type.startswith("unity-il2cpp")
        and h_type in {"return_override", "skip_call", "nop", "speed_modify"}
        and isinstance(method_rva, int)
        and not isinstance(method_rva, bool)
        and method_rva > 0
    )
    native_field_address = (
        engine_type.startswith("unity-il2cpp")
        and h_type in {"memory_patch", "multi_memory_patch"}
        and isinstance(offset, int)
        and not isinstance(offset, bool)
        and offset >= 0
    )
    native_return_type = (
        target.return_type
        if target is not None and target.return_type
        else ev.get("return_type", "")
    )
    exact_il2cpp_integral_override = (
        engine_type.startswith("unity-il2cpp")
        and h_type == "return_override"
        and native_method_address
        and "parameter_types" in ev
        and isinstance(ev.get("parameter_types"), (list, tuple))
        and primitive_type_kind(native_return_type) in {"bool", "integer"}
    )
    return {
        "signature_verified": exact_java_override or exact_il2cpp_integral_override,
        "address_verified": exact_java_override or native_method_address or native_field_address,
        "implementation_ready": exact_java_override or exact_il2cpp_integral_override,
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
    """Break confidence ties using only domain-neutral evidence readiness."""
    score = 0
    if target.method_rva is not None or target.offset is not None:
        score += 5
    if target.signature_verified:
        score += 20
    if target.address_verified:
        score += 20
    if target.implementation_ready:
        score += 30
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
            reason=("Conflicting candidate strategies require manual resolution. " + target.reason).strip(),
        )
        if (
            target.class_name.casefold(),
            target.target.casefold(),
            target.parameter_types,
        )
        in conflict_ids
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
    for tokens in (identifier_tokens(target.target), identifier_tokens(target.class_name)):
        entity_hits = {
            canonical_entity_token(token)
            for token in tokens
            if token in ENTITY_KEYWORDS
        }
        if entity_hits:
            return sorted(entity_hits)[0]
    return f"{target.class_name.casefold()}::{target.target.casefold()}"


def _goal_entity_concepts(goal_prompt: str | None) -> tuple[str, ...]:
    if not goal_prompt:
        return ()
    concepts = tuple(
        dict.fromkeys(
            canonical_entity_token(token)
            for token in extract_entity_keywords(goal_prompt)
            if canonical_entity_token(token)
        )
    )
    return concepts


def _goal_entity_structure(
    goal_prompt: str | None,
) -> tuple[tuple[str, ...], dict[str, frozenset[str]]]:
    """Return requested concepts with contiguous multi-word entities first."""
    individual = _goal_entity_concepts(goal_prompt)
    if not goal_prompt or not individual:
        return individual, {}

    individual_set = set(individual)
    runs: list[list[str]] = []
    current: list[str] = []
    for raw_token in re.findall(r"\b\w+\b", goal_prompt.casefold()):
        token = canonical_entity_token(raw_token)
        if token in individual_set:
            current.append(token)
        elif current:
            runs.append(current)
            current = []
    if current:
        runs.append(current)

    compounds: dict[str, frozenset[str]] = {}
    ordered_compounds: list[str] = []
    for run in runs:
        for width in range(min(4, len(run)), 1, -1):
            for start in range(len(run) - width + 1):
                parts = run[start : start + width]
                compound = "".join(parts)
                if compound not in compounds:
                    compounds[compound] = frozenset(parts)
                    ordered_compounds.append(compound)
    return tuple(ordered_compounds) + individual, compounds


def _goal_concept_for_target(
    target: AnalyzedTarget,
    requested: tuple[str, ...],
) -> str | None:
    """Map a candidate to one explicitly requested entity concept."""
    member_tokens = identifier_tokens(target.target)
    class_tokens = identifier_tokens(target.class_name)
    canonical_member_tokens = {canonical_entity_token(token) for token in member_tokens}
    canonical_class_tokens = {canonical_entity_token(token) for token in class_tokens}
    for concept in requested:
        if concept in canonical_member_tokens or matches_identifier_keyword(concept, target.target):
            return concept
    for concept in requested:
        if concept in canonical_class_tokens or matches_identifier_keyword(concept, target.class_name):
            return concept

    # Generic family requests intentionally select only one best member of the
    # family. Specific resources (coin, key, gem, etc.) still require an exact
    # entity token and therefore cannot activate an unrelated resource.
    family_requests = (
        ("currency", CURRENCY_KEYWORDS),
        ("collision", COLLISION_KEYWORDS),
        ("movement", MOVEMENT_KEYWORDS),
        ("subscription", SUBSCRIPTION_KEYWORDS),
    )
    requested_set = set(requested)
    for concept, family in family_requests:
        if concept in requested_set and member_tokens & family:
            return concept
    for concept, family in family_requests:
        if concept in requested_set and class_tokens & family:
            return concept
    return None


def split_candidates(
    targets: Iterable[AnalyzedTarget],
    *,
    confidence_threshold: int = PRIMARY_CONFIDENCE_THRESHOLD,
    primary_limit: int = PRIMARY_CANDIDATE_LIMIT,
    goal_prompt: str | None = None,
) -> CandidateGroups:
    """Select one primary state target per entity concept up to primary_limit."""
    ranked = rank_candidates(targets)
    high_conf = [t for t in ranked if t.confidence >= confidence_threshold]

    selected_by_entity: dict[str, AnalyzedTarget] = {}
    requested, compound_parts = _goal_entity_structure(goal_prompt)

    for target in high_conf:
        entity = (
            _goal_concept_for_target(target, requested)
            if requested
            else _extract_entity_concept(target)
        )
        if entity is None:
            continue
        if entity not in selected_by_entity:
            selected_by_entity[entity] = target

    selected_compounds = sorted(
        (entity for entity in compound_parts if entity in selected_by_entity),
        key=lambda entity: len(compound_parts[entity]),
        reverse=True,
    )
    for compound in selected_compounds:
        if compound not in selected_by_entity:
            continue
        parts = compound_parts[compound]
        for entity in tuple(selected_by_entity):
            if entity == compound:
                continue
            entity_parts = compound_parts.get(entity, frozenset({entity}))
            if entity_parts < parts:
                selected_by_entity.pop(entity)

    # A generic family property remains useful when it is the only grounded
    # target.  It becomes redundant only when the metadata also supplies a
    # concrete named-tier target such as Pro or Max.
    if "subscription" in selected_by_entity and any(
        entity in selected_by_entity for entity in NAMED_TIER_ENTITY_KEYWORDS
    ):
        selected_by_entity.pop("subscription")

    selected_ids = {id(target) for target in selected_by_entity.values()}
    primary = [target for target in high_conf if id(target) in selected_ids][:primary_limit]

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
    signature = f"({', '.join(target.parameter_types)})" if target.parameter_types else ""
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
        goal_prompt=goal_prompt,
    )
    lines = [
        f"TOP HIGH-CONFIDENCE TARGETS (>={confidence_threshold}%, max {primary_limit})",
    ]
    if groups.primary:
        lines.extend(f"  {index}. {format_candidate(target)}" for index, target in enumerate(groups.primary, 1))
    elif goal_prompt and any(target.confidence >= confidence_threshold for target in groups.secondary):
        lines.append("  High-confidence candidates were found, but none matched the requested goal entities.")
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
