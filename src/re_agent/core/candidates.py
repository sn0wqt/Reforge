"""Shared confidence ranking and presentation for every binary pathway."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import TextIO

from re_agent.llm.analyzed_target import AnalyzedTarget

PRIMARY_CONFIDENCE_THRESHOLD = 85
PRIMARY_CANDIDATE_LIMIT = 5


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
            key=lambda target: (
                -target.confidence,
                target.class_name.casefold(),
                target.target.casefold(),
                target.hook_type,
            ),
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
            key=lambda target: (
                -target.confidence,
                target.class_name.casefold(),
                target.target.casefold(),
                target.hook_type,
            ),
        )
    )


def split_candidates(
    targets: Iterable[AnalyzedTarget],
    *,
    confidence_threshold: int = PRIMARY_CONFIDENCE_THRESHOLD,
    primary_limit: int = PRIMARY_CANDIDATE_LIMIT,
) -> CandidateGroups:
    """Select up to five active high-confidence targets and retain every remainder."""
    ranked = rank_candidates(targets)
    primary = tuple(target for target in ranked if target.confidence >= confidence_threshold)[:primary_limit]
    primary_ids = {id(target) for target in primary}
    secondary = tuple(target for target in ranked if id(target) not in primary_ids)
    return CandidateGroups(primary=primary, secondary=secondary)


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
) -> CandidateGroups:
    """Print the universal terminal candidate display and return its grouping."""
    target_list = list(targets)
    print(
        render_candidate_summary(
            target_list,
            confidence_threshold=confidence_threshold,
            primary_limit=primary_limit,
        ),
        file=stream,
    )
    return split_candidates(
        target_list,
        confidence_threshold=confidence_threshold,
        primary_limit=primary_limit,
    )
