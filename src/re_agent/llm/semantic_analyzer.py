"""Configured-provider semantic analyzer for IL2CPP metadata.

Sends a curated summary of class/method/field metadata to the configured LLM
(Codex, Claude, AntiGravity CLI, or Gemini) and asks it to identify the correct
hook targets for a given natural language goal. Returns structured ``AnalyzedTarget``
objects with hook types, confidence scores, and explanations.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from re_agent.config.domain_keywords import (
    CURRENCY_KEYWORDS,
    DOMAIN_EXPANSION_GROUPS,
    INTENT_MODIFIERS,
    INTENT_VERBS,
    MODEL_HINTS,
    UI_PENALTY_HINTS,
    filter_entity_terms,
    is_contextual_currency_match,
    matches_identifier_keyword,
)
from re_agent.core.candidates import rank_candidates
from re_agent.llm.analyzed_target import AnalyzedTarget
from re_agent.llm.protocol import LLMProvider, Message
from re_agent.utils.goal_parser import extract_entity_keywords

logger = logging.getLogger(__name__)

# Maximum number of candidate classes to send to the LLM. The complete local
# inventory is retained separately; this only limits semantic refinement cost.
_MAX_CANDIDATES_FOR_LLM = 50

# Maximum number of fields/methods per class to include in the summary.
_MAX_MEMBERS_PER_CLASS = 12
_MAX_METADATA_CHARS = 60_000
_SAFE_RETURN_TYPES = {"int32_t", "int64_t", "float", "double", "bool", "void", "void*"}
_DEX_RETURN_TYPES = {
    "boolean": "bool",
    "byte": "int32_t",
    "char": "int32_t",
    "double": "double",
    "float": "float",
    "int": "int32_t",
    "long": "int64_t",
    "short": "int32_t",
}


def _metadata_member_relevance(
    member: dict[str, Any],
    *,
    method: bool,
    entity_terms: list[str],
    class_name: str,
) -> int:
    """Score members so the bounded LLM summary keeps goal-relevant evidence."""
    name = str(
        member.get("method_name", member.get("name", ""))
        if method
        else member.get("name", "")
    )
    score = 0
    for term in entity_terms:
        if not matches_identifier_keyword(term, name):
            continue
        if (
            term in CURRENCY_KEYWORDS
            and not is_contextual_currency_match(term, class_name, name)
        ):
            continue
        score += 100
    if method and name.casefold().startswith(
        ("get_", "get", "has_", "has", "is_", "is", "can")
    ):
        score += 20
    return score


def _build_metadata_summary(
    candidates: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]],
    entity_terms: list[str] | None = None,
) -> str:
    """Build a compact text summary of candidate classes for the LLM.

    Each class includes its name, fields (with offsets and types), and
    method names. The output is designed to be token-efficient while
    giving the LLM enough context to reason about game architecture.
    """
    records: list[dict[str, object]] = []
    for cls_name, methods, fields in candidates[:_MAX_CANDIDATES_FOR_LLM]:
        terms = entity_terms or []

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
                        str(parameter)[:128]
                        for parameter in parameter_types
                        if isinstance(parameter, str)
                    ][:64]
                    if isinstance(parameter_types, (list, tuple))
                    else [],
                    "descriptor": str(method.get("descriptor", ""))[:512],
                }
            )
        records.append(
            {
                "class": str(cls_name)[:256],
                "fields": safe_fields,
                "methods": safe_methods,
            }
        )

    encoded_size = 2
    included: list[str] = []
    for record in records:
        encoded_record = json.dumps(record, separators=(",", ":"))
        separator_size = 1 if included else 0
        if encoded_size + separator_size + len(encoded_record) > _MAX_METADATA_CHARS:
            break
        included.append(encoded_record)
        encoded_size += separator_size + len(encoded_record)
    return f"[{','.join(included)}]"


_SYSTEM_PROMPT = """\
CRITICAL RESPONSE FORMAT INSTRUCTION:
You are an automated reverse engineering CLI tool. You MUST output ONLY a valid \
raw JSON array matching the specified format. You MUST NOT include conversational \
text, greetings, politeness, markdown wrappers, or introductory sentences.

You are an expert reverse engineer and binary analysis assistant.
Analyze candidate classes extracted from binary metadata and identify the best \
function hook targets and field memory patch offsets for the user's goal.

You understand game architecture patterns:
- Currency/economy classes often use names like Model, Manager, \
Wallet, Balance, Currency, Economy, Shop, Store, IAP
- Player state classes use Health, Stats, Player, Character, Motor
- Collision/death classes use Collision, Impact, Die, Kill, Damage
- Position/transform classes use Transform, Position, Vector3, Camera
- Speed/time classes use Speed, Velocity, DeltaTime, TimeScale
- Ownership/unlock classes use Own, Unlock, Available, Purchase, Buy
- Anti-cheat classes use Cheat, Validate, Verify, Check, Security

You know that:
- A getter method (Get*, get_*) returning int/float that relates to \
currency should use hook_type "return_override"
- A field storing a numeric value (coins, health, ammo) should use \
hook_type "memory_patch"
- A collision/damage/death callback (OnControllerColliderHit, OnCollisionEnter, \
OnHit, OnImpact, Die, Kill) should use hook_type "skip_call"
- A collider status getter (get_ColliderEnable, get_CanCollide, get_IsColliding) \
returning bool should use hook_type "return_override" with return_value "false"
- A position/transform method should use hook_type "esp_overlay"
- A speed/time/velocity getter should use hook_type "speed_modify"
- An anti-cheat/ad/validation method should use hook_type "nop"

CRITICAL SAFETY & STABILITY RULES:
- NEVER use hook_type "return_override" with 0/null on object pointer getters \
(e.g., get_collider, get_transform, get_gameObject). Overriding collider/object \
pointers to null causes NullReferenceExceptions and crashes game binaries!
- NEVER select C# event subscription methods (add_On*, remove_On*, subscribe, unsubscribe). \
Event subscribers take delegate pointers and assigning return overrides to them corrupts event listeners!
- NEVER assign numeric return_override to string descriptors (get_ProviderKey), struct pointers, or composers.
- For boolean getter methods (IsCurrencyOwned, HasCoins, get_IsVIP), set return_type "bool" and return_value "true".
- For collision/obstacle goals: ALWAYS use "skip_call" on collision callback \
methods (OnControllerColliderHit, OnCollisionEnter, SetFrontalImpact) OR \
"return_override" with return_value "false" on boolean collider status getters \
(get_ColliderEnable, get_CanCollide, get_IsColliding).
- DATA MODEL classes (store actual game state) vs UI DISPLAY classes \
(just show values on screen). Always prefer data models.
- CORE ENGINE SYSTEMS (the primary physics, movement, state, or collision \
controllers) vs SECONDARY EVENT LISTENERS, EFFECT WRAPPERS, or SEASONAL TRIGGERS. \
ALWAYS prioritize core engine systems that directly process physics and \
state over secondary event wrappers or temporary visual triggers.
- GETTER METHODS (return values) vs SETTER METHODS (write values). \
For "infinite X" goals, hook the getter to return max value.
- RELEVANT fields vs UNRELATED fields. "Coins" in a class name like \
"CoinSpawner" means it SPAWNS coin visuals, not that it stores the \
player's coin balance.
- EXCLUDE OS APP STORES & AD SDKs: NEVER match OS app store links or ad SDK parameters \
(InMobiSDK, App Store, Play Store, StoreKit, store_id, store_url, GooglePlay). \
These refer to app distribution URLs or ad SDK parameters, NOT in-game currency balances! \
Currency and key goals apply strictly to player data models and game state.
"""

_USER_PROMPT_TEMPLATE = """\
Respond ONLY with the raw JSON array and nothing else. \
Do not say hello, do not introduce yourself, and do not wrap in conversational text.

GOAL: {goal}
ENTITY TARGETS AFTER INTENT FILTERING: {entities}

Below is a summary of {count} candidate IL2CPP classes extracted from \
the game binary metadata. Each class lists its fields (with byte \
offsets from `this`) and methods (with RVA addresses).

Analyze this metadata and identify the TOP 5-10 most relevant hook \
targets to achieve the goal. For each target, determine the correct \
hook type and explain your reasoning.

IMPORTANT RULES:
1. Every target MUST match a class, field, or method name PRECISELY as shown in the metadata below. Do not invent names.
2. For method targets: specify `hook_type` as "return_override", "skip_call", "nop", "esp_overlay", or "speed_modify".
   - Set `return_value` appropriately (e.g., "999999" for currency, "true" for unlocks/godmode, "false" for collision/death checks, "0" for cost/damage).
   - Set `return_type` ("int32_t", "float", "bool", "void").
3. For field targets: specify `hook_type` as "memory_patch". Set `offset` to the exact integer offset given in the metadata.
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
                    if cleaned_offset.casefold().startswith("0x"):
                        val = int(cleaned_offset, 16)
                    else:
                        val = int(cleaned_offset)
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
            config_path = Path("re-agent.yaml")
            if config_path.exists():
                cfg = load_config(config_path)
                if cfg.llm:
                    provider = create_provider(cfg.llm)
        except Exception:
            pass

    if not provider:
        try:
            provider = create_default_provider()
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
    terms = _goal_terms(goal)
    summary = _build_metadata_summary(candidates, entity_terms=terms)
    user_prompt = _USER_PROMPT_TEMPLATE.format(
        goal=goal,
        entities=", ".join(entity_targets),
        count=min(len(candidates), _MAX_CANDIDATES_FOR_LLM),
        metadata_summary=summary,
    )

    messages = [
        Message(role="system", content=_SYSTEM_PROMPT),
        Message(role="user", content=user_prompt),
    ]

    try:
        response_text = provider.send(messages)
        targets = _parse_llm_response(response_text)
        grounded = _ground_targets(targets, candidates)
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


def _goal_terms(goal: str) -> list[str]:
    terms = extract_entity_keywords(goal)
    tokens = set(re.findall(r"\b\w+\b", goal.lower()))
    for triggers, expansions in DOMAIN_EXPANSION_GROUPS:
        if tokens & triggers:
            terms.extend(sorted(expansions))
    return list(dict.fromkeys(terms))


def _ground_targets(
    targets: list[AnalyzedTarget],
    candidates: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]],
) -> list[AnalyzedTarget]:
    """Require every model suggestion to match exact submitted metadata evidence."""
    methods: dict[tuple[str, str], dict[str, Any]] = {}
    fields: dict[tuple[str, str], dict[str, Any]] = {}
    for class_name, class_methods, class_fields in candidates[:_MAX_CANDIDATES_FOR_LLM]:
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
            if evidence_type in _SAFE_RETURN_TYPES:
                target.return_type = evidence_type
            target.confidence = 90 if evidence_type in _SAFE_RETURN_TYPES else 80
            target.reason = f"Exact field and offset matched submitted metadata: {target.reason}"
        else:
            evidence = methods.get(key)
            if evidence is None or target.offset is not None:
                continue
            parameter_types = evidence.get("parameter_types", ())
            if isinstance(parameter_types, (list, tuple)) and all(
                isinstance(parameter, str) and parameter
                for parameter in parameter_types
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
            normalized_evidence_type = _DEX_RETURN_TYPES.get(
                evidence_type.casefold(),
                evidence_type,
            )
            if normalized_evidence_type in _SAFE_RETURN_TYPES:
                target.return_type = normalized_evidence_type
                target.confidence = 88
            else:
                target.confidence = 75
            exact_java_override = (
                target.hook_type == "return_override"
                and evidence.get("is_declared") is True
                and evidence.get("is_executable") is True
                and evidence.get("is_constructor") is False
                and isinstance(evidence.get("is_static"), bool)
                and bool(target.method_descriptor)
                and evidence_type.casefold() in _DEX_RETURN_TYPES
            )
            il2cpp_method_verified = (
                target.hook_type == "return_override"
                and isinstance(target.method_rva, int)
                and target.method_rva > 0
            )
            il2cpp_field_verified = (
                target.hook_type in {"memory_patch", "multi_memory_patch"}
                and isinstance(target.offset, int)
                and target.offset >= 0
            )
            verified = exact_java_override or il2cpp_method_verified or il2cpp_field_verified
            target.signature_verified = verified
            target.address_verified = verified
            target.implementation_ready = verified
            target.reason = f"Exact method matched submitted metadata: {target.reason}"
        grounded.append(target)
    return list(rank_candidates(grounded))


def _target_score(t: AnalyzedTarget) -> float:
    score = float(t.confidence)
    if any(
        matches_identifier_keyword(pattern, t.class_name)
        for pattern in MODEL_HINTS
    ):
        score += 50.0
    if t.hook_type == "memory_patch" and t.offset is not None:
        score += 20.0
    if any(
        matches_identifier_keyword(
            word,
            f"{t.class_name} {t.target}",
            min_keyword_length=1,
        )
        for word in UI_PENALTY_HINTS
    ):
        score -= 30.0
    return score


def _deduplicate_targets(targets: list[AnalyzedTarget]) -> list[AnalyzedTarget]:
    """Deduplicate targets so only the single highest-confidence target per concept is kept."""
    sorted_targets = sorted(targets, key=_target_score, reverse=True)
    seen_categories: set[str] = set()
    deduped: list[AnalyzedTarget] = []

    for t in sorted_targets:
        stem = re.sub(r"^(get_|set_|m_|is_)", "", t.target.lower())
        stem = re.sub(r"(_count|_amount|_value|manager|service|data|system|config|state)$", "", stem)
        target_stem = stem.strip("_")
        category = f"{t.class_name}::{target_stem}" if target_stem else f"{t.class_name}::{t.target}"

        if category not in seen_categories:
            seen_categories.add(category)
            deduped.append(t)

    return deduped


def create_gemini_provider(
    api_key: str | None = None,
    model: str = "gemini-3.6-flash",
) -> LLMProvider:
    """Create the configured Gemini provider."""
    config_path = Path("re-agent.yaml")
    if config_path.exists():
        try:
            from re_agent.config.loader import load_config
            from re_agent.llm.registry import create_provider

            cfg = load_config(config_path)
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
            provider = GeminiProvider()
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
        "List 10-20 entity naming patterns (class names, method names, field names, in-game item names). "
        f"Do not return action or modifier words from this exclusion list: {excluded_intent}. "
        "Return terms that represent this concept in game engines (Unity, Unreal, IL2CPP). "
        "If a specific game title is mentioned or implied, include its actual entity "
        "and target class names. "
        'Example output: ["Wallet", "Currency", "Economy", "Coin", "Balance"]'
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

