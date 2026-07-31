"""Structural type-signature analysis for binary metadata.

Identifies candidate hook targets based on method signatures, return types,
parameter types, and field layouts rather than string name matching alone.
These are conservative ranking signals, not proof of semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from re_agent.config.domain_keywords import (
    COLLISION_KEYWORDS,
    CURRENCY_KEYWORDS,
    is_contextual_currency_match,
    matches_identifier_keyword,
)


@dataclass
class StructuralCandidate:
    """A candidate target identified via structural type-signature analysis."""

    class_name: str
    target_name: str
    target_type: str  # 'method' or 'field'
    category: str  # 'currency_getter', 'damage_check', 'position_getter', 'speed_getter'
    confidence: int  # 0 to 100
    details: str


def analyze_structures(
    candidates: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]],
) -> list[StructuralCandidate]:
    """Perform structural type-signature analysis across candidate classes.

    Args:
        candidates: List of ``(class_name, methods_list, fields_list)``.

    Returns:
        List of ``StructuralCandidate`` objects sorted by confidence (descending).
    """
    results: list[StructuralCandidate] = []

    for cls_name, methods, fields in candidates:
        field_types = {f.get("name", ""): f.get("type", "") for f in fields}
        has_numeric_field = any(
            t.lower()
            in (
                "int32_t",
                "int64_t",
                "int",
                "long",
                "float",
                "double",
                "system.int32",
                "system.int64",
                "system.single",
                "system.double",
            )
            for t in field_types.values()
        )

        for m in methods:
            m_name = m.get("method_name", m.get("name", ""))
            return_type = m.get("return_type", "").lower()
            params = m.get("parameters", [])

            # Pattern 1: Currency / Resource Getter
            # Method returning numeric type with 0 parameters in a class with numeric fields
            if len(params) == 0 and return_type in (
                "int32_t",
                "int64_t",
                "int",
                "long",
                "system.int32",
                "system.int64",
            ):
                if (
                    has_numeric_field
                    and m_name.startswith(("get_", "Get"))
                    and any(
                        matches_identifier_keyword(keyword, m_name)
                        and is_contextual_currency_match(
                            keyword,
                            cls_name,
                            m_name,
                        )
                        for keyword in CURRENCY_KEYWORDS
                    )
                ):
                    results.append(
                        StructuralCandidate(
                            class_name=cls_name,
                            target_name=m_name,
                            target_type="method",
                            category="currency_getter",
                            confidence=85,
                            details=f"Parameterless getter returning {return_type} in {cls_name}",
                        )
                    )

            # Pattern 2: Damage / Health Check Method
            # Method taking 1 numeric parameter (damage amount) returning void or bool
            elif len(params) == 1 and return_type in ("void", "bool", "system.void", "system.boolean"):
                p_type = params[0].get("type", "").lower() if isinstance(params[0], dict) else str(params[0]).lower()
                if (
                    p_type
                    in (
                        "float",
                        "int32_t",
                        "int",
                        "double",
                        "system.single",
                        "system.int32",
                        "system.double",
                    )
                    and any(
                        matches_identifier_keyword(keyword, m_name)
                        for keyword in COLLISION_KEYWORDS
                    )
                ):
                    results.append(
                        StructuralCandidate(
                            class_name=cls_name,
                            target_name=m_name,
                            target_type="method",
                            category="damage_check",
                            confidence=80,
                            details=f"Method accepting single {p_type} parameter returning {return_type}",
                        )
                    )

            # Pattern 3: Position / Transform Getter (ESP candidate)
            elif len(params) == 0 and ("vector3" in return_type or "position" in return_type):
                results.append(
                    StructuralCandidate(
                        class_name=cls_name,
                        target_name=m_name,
                        target_type="method",
                        category="position_getter",
                        confidence=85,
                        details=f"Position getter returning {return_type}",
                    )
                )

            # Pattern 4: Speed / DeltaTime Getter
            elif (
                len(params) == 0
                and return_type in ("float", "double")
                and any(k in m_name.lower() for k in ("speed", "deltatime", "velocity"))
            ):
                results.append(
                    StructuralCandidate(
                        class_name=cls_name,
                        target_name=m_name,
                        target_type="method",
                        category="speed_getter",
                        confidence=90,
                        details=f"Speed getter returning {return_type}",
                    )
                )

    # Sort results by confidence descending
    results.sort(key=lambda x: x.confidence, reverse=True)
    return results
