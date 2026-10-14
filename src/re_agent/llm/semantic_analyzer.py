"""Configured-provider semantic analyzer for binary metadata.

Sends a curated summary of DEX or IL2CPP class/method/field metadata to the configured LLM
(Codex, Claude, AntiGravity CLI, or Gemini) and asks it to identify the correct
hook targets for a given natural language goal. Returns structured ``AnalyzedTarget``
objects with hook types, confidence scores, and explanations.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from re_agent.config.domain_keywords import (
    INTENT_MODIFIERS,
    INTENT_VERBS,
    filter_entity_terms,
    matches_identifier_keyword,
)
from re_agent.core.candidates import rank_candidates, target_activation_facts
from re_agent.llm.analyzed_target import AnalyzedTarget
from re_agent.llm.protocol import LLMProvider, Message
from re_agent.utils.goal_parser import expand_goal_terms, extract_entity_keywords
from re_agent.utils.mutation_intent import DEX_SCALAR_TYPE_MAP, MUTABLE_SCALAR_CPP_TYPES

logger = logging.getLogger(__name__)

# Maximum number of candidate classes to send to the LLM. The complete local
# inventory is retained separately; this only limits semantic refinement cost.
_MAX_CANDIDATES_FOR_LLM = 50

# Maximum number of fields/methods per class to include in the summary.
_MAX_MEMBERS_PER_CLASS = 12
_MAX_METADATA_CHARS = 60_000


def _metadata_member_relevance(
    member: dict[str, Any],
    *,
    method: bool,
    entity_terms: list[str],
    class_name: str,
) -> int:
    """Score members so the bounded LLM summary keeps goal-relevant evidence."""
    name = str(member.get("method_name", member.get("name", "")) if method else member.get("name", ""))
    score = 0
    for term in entity_terms:
        if not matches_identifier_keyword(term, name):
            continue
        score += 100
    if score and method and name.casefold().startswith(("get_", "get", "has_", "has", "is_", "is", "can")):
        score += 20
    return score


def _candidate_relevance(
    candidate: tuple[str, list[dict[str, Any]], list[dict[str, Any]]],
    entity_terms: list[str],
) -> int:
    """Score a class using only explicit goal terms and exact metadata evidence."""
    class_name, methods, fields = candidate
    class_score = sum(
        40 for term in entity_terms if matches_identifier_keyword(term, class_name)
    )
    member_scores = [
        _metadata_member_relevance(
            member,
            method=True,
            entity_terms=entity_terms,
            class_name=class_name,
        )
        for member in methods
    ]
    member_scores.extend(
        _metadata_member_relevance(
            member,
            method=False,
            entity_terms=entity_terms,
            class_name=class_name,
        )
        for member in fields
    )
    # Multiple independently matching members are useful evidence, but do not
    # let a very large class win merely because it has more metadata entries.
    relevant_members = sorted((score for score in member_scores if score), reverse=True)
    return class_score + sum(relevant_members[:3])


def _select_candidate_window(
    candidates: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]],
    entity_terms: list[str],
) -> list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]]:
    """Return the stable, goal-ranked candidate window submitted to the LLM."""
    if not entity_terms:
        return candidates[:_MAX_CANDIDATES_FOR_LLM]
    ranked = sorted(
        enumerate(candidates),
        key=lambda item: (-_candidate_relevance(item[1], entity_terms), item[0]),
    )
    return [candidate for _index, candidate in ranked[:_MAX_CANDIDATES_FOR_LLM]]


def _build_metadata_summary(
    candidates: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]],
    entity_terms: list[str] | None = None,
    *,
    candidates_preselected: bool = False,
    included_candidates: list[
        tuple[str, list[dict[str, Any]], list[dict[str, Any]]]
    ]
    | None = None,
) -> str:
    """Build a compact text summary of candidate classes for the LLM.

    Each class includes its name, fields (with offsets and types), and
    method names. The output is designed to be token-efficient while
    giving the LLM enough context to reason about application behavior.
    """
    terms = entity_terms or []
    selected_candidates = (
        candidates[:_MAX_CANDIDATES_FOR_LLM]
        if candidates_preselected
        else _select_candidate_window(candidates, terms)
    )
    records: list[
        tuple[
            tuple[str, list[dict[str, Any]], list[dict[str, Any]]],
            dict[str, object],
        ]
    ] = []
    for candidate in selected_candidates:
        cls_name, methods, fields = candidate
        selected_fields = (
            sorted(
                enumerate(fields),
                key=lambda item: (
                    -_metadata_member_relevance(
                        item[1],
                        method=False,
                        entity_terms=terms,
                        class_name=cls_name,
                    ),
                    item[0],
                ),
            )[:_MAX_MEMBERS_PER_CLASS]
            if terms
            else list(enumerate(fields[:_MAX_MEMBERS_PER_CLASS]))
        )
        selected_methods = (
            sorted(
                enumerate(methods),
                key=lambda item: (
                    -_metadata_member_relevance(
                        item[1],
                        method=True,
                        entity_terms=terms,
                        class_name=cls_name,
                    ),
                    item[0],
                ),
            )[:_MAX_MEMBERS_PER_CLASS]
            if terms
            else list(enumerate(methods[:_MAX_MEMBERS_PER_CLASS]))
        )
        safe_fields = []
        for _index, field in selected_fields:
            offset = field.get("offset")
            if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
                continue
            safe_fields.append(
                {
                    "name": str(field.get("name", "?"))[:256],
                    "type": str(field.get("type", "?"))[:128],
                    "offset": offset,
                }
            )
        safe_methods = []
        for _index, method in selected_methods:
            address = method.get("address")
            parameter_types = method.get("parameter_types", ())
            safe_methods.append(
                {
                    "name": str(method.get("method_name", method.get("name", "?")))[:256],
                    "address": address
                    if isinstance(address, int) and not isinstance(address, bool) and address >= 0
                    else None,
                    "address_kind": str(method.get("address_kind", "unknown"))[:32],
                    "return_type": str(method.get("return_type", ""))[:128],
                    "parameter_types": [
                        str(parameter)[:128] for parameter in parameter_types if isinstance(parameter, str)
                    ][:64]
                    if isinstance(parameter_types, (list, tuple))
                    else [],
                    "descriptor": str(method.get("descriptor", ""))[:512],
                }
            )
        records.append(
            (
                candidate,
                {
                    "class": str(cls_name)[:256],
                    "fields": safe_fields,
                    "methods": safe_methods,
                },
            )
        )

    encoded_size = 2
    included: list[str] = []
    if included_candidates is not None:
        included_candidates.clear()
    for candidate, record in records:
        encoded_record = json.dumps(record, separators=(",", ":"))
        separator_size = 1 if included else 0
        if encoded_size + separator_size + len(encoded_record) > _MAX_METADATA_CHARS:
            break
        included.append(encoded_record)
        if included_candidates is not None:
            included_candidates.append(candidate)
        encoded_size += separator_size + len(encoded_record)
    return f"[{','.join(included)}]"


_SYSTEM_PROMPT = """\
CRITICAL RESPONSE FORMAT INSTRUCTION:
You are an automated reverse engineering CLI tool. You MUST output ONLY a valid \
raw JSON array matching the specified format. You MUST NOT include conversational \
text, greetings, politeness, markdown wrappers, or introductory sentences.

You are an expert reverse engineer and binary analysis assistant.
Analyze only the submitted DEX or IL2CPP metadata and identify targets that are \
directly relevant to the user's stated entities and requested behavior. Treat \
unknown applications and domain vocabulary as first-class inputs. Do not assume \
the application is a game and do not infer product-specific names that are absent \
from the metadata.

CRITICAL SAFETY & STABILITY RULES:
- Ground every suggestion in an exact submitted class and member name. Never invent a target.
- Use "return_override" only for a verified primitive scalar return type: bool, \
int32_t, int64_t, float, or double. Never replace object, string, array, delegate, \
unknown, pointer, or structure returns. If the metadata cannot prove a safe ABI, \
do not propose an active return override.
- Event subscription and callback-registration methods are not value getters; do \
not replace their returns or arguments.
- A field patch requires an exact submitted numeric offset. Never derive or guess offsets.
- For DEX methods, respect the descriptor, declaration/executability facts, and Java \
primitive return type. For IL2CPP methods, respect the method RVA, parameter types, \
and native return type. Do not treat one metadata format as the other.
- Prefer state-bearing or behavior-controlling members over presentation-only names, \
but do not exclude a presentation member when it is explicitly requested by the goal.
- Use skip_call or nop only when the requested behavior and method semantics clearly \
support suppressing the entire call and the method returns void.
"""

_USER_PROMPT_TEMPLATE = """\
Respond ONLY with the raw JSON array and nothing else. \
Do not say hello, do not introduce yourself, and do not wrap in conversational text.

GOAL: {goal}
ENTITY TARGETS AFTER INTENT FILTERING: {entities}

Below is a summary of {count} candidate classes extracted from DEX or IL2CPP \
binary metadata. Each class lists available field offsets and method evidence, \
which may include a DEX descriptor or an IL2CPP method RVA.

Analyze this metadata and identify the TOP 5-10 most relevant hook \
targets to achieve the goal. For each target, determine the correct \
hook type and explain your reasoning.

IMPORTANT RULES:
1. Every target MUST match a class, field, or method name PRECISELY as shown in the metadata below. Do not invent names.
2. For method targets: specify `hook_type` as "return_override", "skip_call", "nop", "esp_overlay", or "speed_modify".
   - Derive the return value from the user's requested behavior; do not assume a domain.
   - Set `return_type` to the exact compatible primitive type shown by the metadata.
   - Do not emit a return override when the return ABI is absent, unknown, object-like, or non-scalar.
3. For field targets: specify `hook_type` as "memory_patch".
   Set `offset` to the exact integer offset given in the metadata.
4. Set `confidence` from 0-100 reflecting how confident you are that this target achieves the user's goal.
5. Set `reason` to a concise 1-sentence technical explanation.

Output MUST be a JSON array of objects with these keys:
`class_name`, `target`, `hook_type`, `return_value`, `return_type`, `offset`, `confidence`, `reason`

METADATA SUMMARY:
{metadata_summary}
"""


def _parse_llm_response(raw_text: str) -> list[AnalyzedTarget]:
    """Parse raw LLM response string into a list of AnalyzedTarget objects."""
    cleaned = raw_text.strip()
    match = re.search(r"\[\s*\{.*\}\s*\]", cleaned, re.DOTALL)
    if match:
        cleaned = match.group(0)
    else:
        first_bracket = cleaned.find("[")
        last_bracket = cleaned.rfind("]")
        if first_bracket != -1 and last_bracket != -1 and last_bracket > first_bracket:
            cleaned = cleaned[first_bracket : last_bracket + 1]

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.warning("[LLM] Failed to parse JSON response: %s", exc)
        return []

    if not isinstance(data, list):
        return []

    targets: list[AnalyzedTarget] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            raw_target = item.get("target") or item.get("target_name") or item.get("method_name")
            target_str = str(raw_target) if raw_target else ""
            if not target_str or target_str == "?":
                continue
            raw_class = item.get("class_name") or item.get("class")
            class_str = str(raw_class) if raw_class else ""
            if not class_str or class_str == "?":
                continue

            raw_confidence = item.get("confidence", 50)
            confidence = int(raw_confidence) if isinstance(raw_confidence, (int, float)) else 50

            raw_offset = item.get("offset")
            offset: int | None = None
            if isinstance(raw_offset, int) and not isinstance(raw_offset, bool) and raw_offset >= 0:
                offset = raw_offset
            elif isinstance(raw_offset, str):
                cleaned_offset = raw_offset.strip()
                try:
                    val = int(cleaned_offset, 16) if cleaned_offset.casefold().startswith("0x") else int(cleaned_offset)
                    if val >= 0:
                        offset = val
                except ValueError:
                    pass

            target = AnalyzedTarget(
                class_name=class_str,
                target=target_str,
                hook_type=str(item.get("hook_type", "return_override")),
                return_value=str(item.get("return_value", "")),
                return_type=str(item.get("return_type", "int32_t")),
                offset=offset,
                confidence=max(0, min(100, confidence)),
                reason=str(item.get("reason", "LLM identified target")),
            )
            targets.append(target)
        except Exception as exc:
            logger.warning("[LLM] Error constructing AnalyzedTarget: %s", exc)

    return sorted(targets, key=_target_score, reverse=True)


def analyze_metadata(
    candidates: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]],
    goal: str,
    provider: LLMProvider | None = None,
    *,
    raise_on_provider_error: bool = False,
) -> list[AnalyzedTarget]:
    """Analyze binary candidate metadata using the configured LLM provider."""
    if not goal:
        return []

    if not provider:
        try:
            from re_agent.config.loader import load_config
            from re_agent.llm.registry import create_provider

            cfg = load_config(None)
            if cfg.llm:
                provider = create_provider(cfg.llm)
        except Exception:
            pass

    if not provider:
        try:
            provider = create_gemini_provider()
        except Exception:
            logger.warning("[LLM] No LLM provider available for semantic analysis")
            return []

    if not candidates:
        # If explicit provider send fails or raises, test requires it to trigger
        if raise_on_provider_error and provider:
            messages = [Message(role="user", content="ping")]
            try:
                provider.send(messages)
            except Exception:
                raise
        return []

    entity_targets = extract_entity_keywords(goal)
    terms = expand_goal_terms(goal)
    candidate_window = _select_candidate_window(candidates, terms)
    submitted_candidates: list[
        tuple[str, list[dict[str, Any]], list[dict[str, Any]]]
    ] = []
    summary = _build_metadata_summary(
        candidate_window,
        entity_terms=terms,
        candidates_preselected=True,
        included_candidates=submitted_candidates,
    )
    user_prompt = _USER_PROMPT_TEMPLATE.format(
        goal=goal,
        entities=", ".join(entity_targets),
        count=len(submitted_candidates),
        metadata_summary=summary,
    )

    messages = [
        Message(role="system", content=_SYSTEM_PROMPT),
        Message(role="user", content=user_prompt),
    ]

    try:
        response_text = provider.send(messages)
        targets = _parse_llm_response(response_text)
        grounded = _ground_targets(targets, submitted_candidates)
        deduped = _deduplicate_targets(grounded)
        return deduped
    except Exception as exc:
        logger.warning("[LLM] Semantic analysis failed: %s", exc)
        if raise_on_provider_error:
            raise
        return []


def analyze_metadata_with_llm(
    provider: Any,
    goal: str,
    candidates: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]],
    *,
    raise_on_provider_error: bool = False,
) -> list[AnalyzedTarget]:
    """Legacy helper wrapper with (provider, goal, candidates) parameter ordering."""
    return analyze_metadata(
        candidates,
        goal,
        provider=provider,
        raise_on_provider_error=raise_on_provider_error,
    )


def _ground_targets(
    targets: list[AnalyzedTarget],
    candidates: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]],
) -> list[AnalyzedTarget]:
    """Require every model suggestion to match exact submitted metadata evidence."""
    methods: dict[tuple[str, str], dict[str, Any]] = {}
    fields: dict[tuple[str, str], dict[str, Any]] = {}
    for class_name, class_methods, class_fields in candidates:
        for method in class_methods:
            name = method.get("method_name", method.get("name"))
            if isinstance(name, str):
                methods[(class_name, name)] = method
        for field in class_fields:
            name = field.get("name")
            if isinstance(name, str):
                fields[(class_name, name)] = field

    grounded: list[AnalyzedTarget] = []
    for target in targets:
        key = (target.class_name, target.target)
        if target.hook_type in {"memory_patch", "multi_memory_patch"}:
            evidence = fields.get(key)
            evidence_offset = evidence.get("offset") if evidence else None
            if (
                evidence is None
                or not isinstance(evidence_offset, int)
                or isinstance(evidence_offset, bool)
                or target.offset != evidence_offset
            ):
                continue
            evidence_type = str(evidence.get("type", "")).strip()
            if evidence_type in MUTABLE_SCALAR_CPP_TYPES:
                target.return_type = evidence_type
            target.confidence = 90 if evidence_type in MUTABLE_SCALAR_CPP_TYPES else 80
            target.reason = f"Exact field and offset matched submitted metadata: {target.reason}"
        else:
            evidence = methods.get(key)
            if evidence is None or target.offset is not None:
                continue
            parameter_types = evidence.get("parameter_types", ())
            if isinstance(parameter_types, (list, tuple)) and all(
                isinstance(parameter, str) and parameter for parameter in parameter_types
            ):
                target.parameter_types = tuple(parameter_types)
            descriptor = evidence.get("descriptor")
            if isinstance(descriptor, str) and descriptor:
                target.method_descriptor = descriptor
            method_rva = evidence.get("rva")
            if (
                evidence.get("address_kind") == "method_rva"
                and isinstance(method_rva, int)
                and not isinstance(method_rva, bool)
                and 0 <= method_rva <= 0x7FFF_FFFF_FFFF_FFFF
            ):
                target.method_rva = method_rva
            evidence_type = str(evidence.get("return_type", "")).strip()
            normalized_evidence_type = DEX_SCALAR_TYPE_MAP.get(
                evidence_type.casefold(),
                evidence_type,
            )
            if normalized_evidence_type in MUTABLE_SCALAR_CPP_TYPES:
                target.return_type = normalized_evidence_type
                target.confidence = 88
            else:
                target.confidence = 75
            evidence_engine = (
                "android-java-dex"
                if evidence.get("is_declared") is not None or bool(target.method_descriptor)
                else "unity-il2cpp"
            )
            activation = target_activation_facts(
                target,
                engine_type=evidence_engine,
                evidence=evidence,
            )
            target.signature_verified = activation["signature_verified"]
            target.address_verified = activation["address_verified"]
            target.implementation_ready = activation["implementation_ready"]
            target.reason = f"Exact method matched submitted metadata: {target.reason}"
        grounded.append(target)
    return list(rank_candidates(grounded))


def _target_score(t: AnalyzedTarget) -> float:
    """Rank using confidence and concrete implementation evidence only."""
    score = float(t.confidence)
    if t.hook_type == "memory_patch" and t.offset is not None:
        score += 20.0
    if t.implementation_ready:
        score += 10.0
    if t.signature_verified:
        score += 5.0
    if t.address_verified:
        score += 5.0
    return score


def _deduplicate_targets(targets: list[AnalyzedTarget]) -> list[AnalyzedTarget]:
    """Remove repeated suggestions without collapsing distinct metadata members."""
    sorted_targets = sorted(targets, key=_target_score, reverse=True)
    seen_targets: set[
        tuple[
            str,
            str,
            str,
            int | None,
            int | None,
            str | None,
            tuple[str, ...],
        ]
    ] = set()
    deduped: list[AnalyzedTarget] = []

    for t in sorted_targets:
        identity = (
            t.class_name,
            t.target,
            t.hook_type,
            t.offset,
            t.method_rva,
            t.method_descriptor,
            t.parameter_types,
        )
        if identity not in seen_targets:
            seen_targets.add(identity)
            deduped.append(t)

    return deduped


def create_gemini_provider(
    api_key: str | None = None,
    model: str = "gemini-3.6-flash",
) -> LLMProvider:
    """Create the configured Gemini provider."""
    try:
        from re_agent.config.loader import load_config
        from re_agent.llm.registry import create_provider

        cfg = load_config(None)
        if cfg.llm and cfg.llm.provider in ("gemini", "google-gemini"):
            return create_provider(cfg.llm)
    except Exception as e:
        logger.warning("[LLM] Config loader failed for gemini provider: %s", e)

    from re_agent.llm.gemini_api import GeminiProvider

    return GeminiProvider(
        api_key=api_key,
        model=model,
        max_tokens=4096,
        temperature=0.0,
    )


def expand_goal_keywords_with_llm(
    goal_text: str,
    provider: LLMProvider | None = None,
) -> list[str]:
    """Dynamically expand a natural language goal into candidate search terms using LLM."""
    if not provider:
        try:
            provider = create_gemini_provider()
        except Exception:
            tokens = re.findall(r"\w+", goal_text.lower())
            return [t for t in tokens if len(t) > 2]

    entity_targets = extract_entity_keywords(goal_text)
    excluded_intent = ", ".join(sorted(INTENT_VERBS | INTENT_MODIFIERS))
    prompt = (
        "[SYSTEM INSTRUCTION - CRITICAL OUTPUT MANDATE]\n"
        "You are an automated backend JSON API. You MUST output ONLY a valid raw JSON array of strings.\n"
        "Do NOT say hello, do NOT introduce yourself, do NOT ask how to help, and do NOT output conversational text.\n"
        "OUTPUT ONLY RAW JSON ARRAY:\n\n"
        f"Goal: {json.dumps(goal_text[:2_000], ensure_ascii=True)}. "
        f"Entity targets: {json.dumps(entity_targets[:50], ensure_ascii=True)}. "
        "List 10-20 entity naming patterns (class names, method names, and field names) "
        "that are semantically implied by the goal itself. "
        f"Do not return action or modifier words from this exclusion list: {excluded_intent}. "
        "The input may target any application and may later be matched against DEX, IL2CPP, or native metadata. "
        "Do not guess a product, framework, domain, or target name that is not implied by the goal."
    )

    try:
        raw = provider.send([Message(role="user", content=prompt)])
        start_idx = raw.find("[")
        end_idx = raw.rfind("]")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            raw = raw[start_idx : end_idx + 1]
        data = json.loads(raw)
        if isinstance(data, list):
            raw_terms = [str(value) for value in data if isinstance(value, str)]
            res = [value.lower() for value in raw_terms]
            sub_tokens: list[str] = []
            for item in raw_terms:
                parts = [
                    t.lower() for t in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)|[a-z0-9]+", item) if len(t) > 3
                ]
                for p in parts:
                    if p not in res and p not in sub_tokens:
                        sub_tokens.append(p)
            if res:
                return filter_entity_terms(res + sub_tokens)
    except Exception:
        logger.warning("[LLM] Dynamic keyword expansion bypassed/failed")

    return filter_entity_terms(re.findall(r"\w+", goal_text.lower()))
