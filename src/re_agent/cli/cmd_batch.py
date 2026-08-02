"""CLI command for autonomous batch discovery and C++ source code dumping."""

from __future__ import annotations

import argparse
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any

from re_agent.config.domain_keywords import (
    COLLISION_KEYWORDS,
    CORE_CURRENCY_VALUE_KEYWORDS,
    CURRENCY_KEYWORDS,
    DOMAIN_EXPANSION_GROUPS,
    MODEL_HINTS,
    MOVEMENT_KEYWORDS,
    NON_RUNTIME_CLASS_HINTS,
    UI_PENALTY_HINTS,
    filter_entity_terms,
    has_economy_data_context,
    identifier_tokens,
    is_balance_value_member,
    is_contextual_currency_match,
    is_entity_keyword,
    matches_identifier_keyword,
)
from re_agent.config.loader import load_config
from re_agent.core.candidates import (
    print_candidate_summary,
    rank_candidates,
    target_activation_facts,
)
from re_agent.core.il2cpp_parser import find_il2cpp_metadata_in_dir
from re_agent.llm.analyzed_target import AnalyzedTarget
from re_agent.utils.goal_parser import extract_entity_keywords
from re_agent.utils.paths import safe_filename
from re_agent.utils.vtable import generate_vtable_header

logger = logging.getLogger(__name__)
MAX_OFFSET_INVENTORY_FILES = 50


def _method_activation_facts(
    engine_type: str,
    evidence: dict[str, Any],
    hook_type: str,
) -> dict[str, bool]:
    """Prove activation readiness using centralized candidate facts."""
    return target_activation_facts(
        target=None,
        engine_type=engine_type,
        hook_type=hook_type,
        evidence=evidence,
    )


def resolve_goal_keywords(goal_text: str, provider: Any = None) -> list[str]:
    """Extract key target keywords from natural language goal prompt.

    Optionally uses the configured provider for goal expansion, then applies
    deterministic domain expansions and filtering.
    """
    keywords = extract_entity_keywords(goal_text)
    known_domain_goal = any(is_entity_keyword(keyword) for keyword in keywords)
    if provider is not None and not known_domain_goal:
        try:
            from re_agent.llm.semantic_analyzer import expand_goal_keywords_with_llm

            expanded = expand_goal_keywords_with_llm(goal_text, provider=provider)
            if expanded:
                keywords.extend(expanded)
        except Exception:
            pass

    goal_tokens = set(re.findall(r"\b\w+\b", goal_text.lower()))
    for triggers, expansions in DOMAIN_EXPANSION_GROUPS:
        if goal_tokens & triggers:
            keywords.extend(sorted(expansions))

    clean = filter_entity_terms(keywords)
    return clean


def _match_keyword(keyword: str, candidate: str) -> bool:
    """Match normalized whole tokens without short substring collisions."""
    return matches_identifier_keyword(keyword, candidate)


def _match_candidate_keyword(
    keyword: str,
    class_name: str,
    member_name: str,
) -> bool:
    """Match one entity while rejecting overloaded framework terminology."""
    return _match_keyword(keyword, member_name) and (
        keyword not in CURRENCY_KEYWORDS or is_contextual_currency_match(keyword, class_name, member_name)
    )


def _is_scalar_currency_field_type(type_name: object) -> bool:
    """Accept only scalar numeric storage, never delegates or collections."""
    normalized = re.sub(r"\s+", "", str(type_name)).casefold()
    return normalized in {
        "byte",
        "double",
        "float",
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
        "system.double",
        "system.int16",
        "system.int32",
        "system.int64",
        "system.sbyte",
        "system.single",
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


def group_methods_by_class(methods: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group IL2CPP script.json methods by class name using DotNetSignature, Group, or Name."""
    classes: dict[str, list[dict[str, Any]]] = {}
    for m in methods:
        dotnet_sig = m.get("dotnet_signature", "")
        group = m.get("group", "")
        name = m.get("name", "")

        cls_name = ""
        method_name = name

        if dotnet_sig and "::" in dotnet_sig:
            parts = dotnet_sig.split("::", 1)
            raw_cls = parts[0].strip()
            method_name = parts[1].split("(")[0].strip()
            cls_name = raw_cls.rsplit(".", 1)[-1] if "." in raw_cls else raw_cls
        elif group and "/" in group:
            parts = group.split("/")
            cls_name = parts[-1].strip()
        elif "$$" in name:
            cls_name, method_name = name.split("$$", 1)
        elif "::" in name:
            parts = name.rsplit("::", 1)
            cls_name, method_name = parts[0], parts[1]

        if not cls_name:
            cls_name = "GlobalNamespace"

        cls_name = re.sub(r"[^a-zA-Z0-9_]", "_", cls_name).strip("_")
        if not cls_name:
            cls_name = "GlobalNamespace"

        m_copy = dict(m)
        m_copy["method_name"] = method_name
        classes.setdefault(cls_name, []).append(m_copy)

    return classes


def _merge_dump_method_evidence(
    script_methods: list[dict[str, Any]],
    dump_methods: list[dict[str, Any]],
) -> None:
    """Merge dump.cs evidence without collapsing same-name overloads."""
    existing_by_name: dict[str, list[dict[str, Any]]] = {}
    for method in script_methods:
        method_name = str(method.get("method_name", method.get("name", "")))
        existing_by_name.setdefault(method_name, []).append(method)

    merged_counts: dict[str, int] = {}
    evidence_keys = (
        "return_type",
        "is_event",
        "rva",
        "address",
        "address_kind",
        "args",
        "parameter_types",
        "parameters",
    )
    for dump_method in dump_methods:
        method_name = str(dump_method.get("method_name", dump_method.get("name", "")))
        matches = existing_by_name.get(method_name, [])
        match_index = merged_counts.get(method_name, 0)
        if match_index >= len(matches):
            script_methods.append(dump_method)
            continue
        destination = matches[match_index]
        merged_counts[method_name] = match_index + 1
        for key in evidence_keys:
            if key in dump_method:
                destination[key] = dump_method[key]


def rank_classes_by_relevance(
    candidates: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]],
    keywords: list[str],
    direct_keywords: list[str] | None = None,
) -> list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]]:
    """Rank candidate classes by keyword relevance with structural heuristics.

    Prefers core data-model and engine physics classes over UI, animation,
    spawner, listener, visual effects, and secondary theme/decor wrappers.
    """
    if not keywords:
        return candidates

    def score_entry(
        entry: tuple[str, list[dict[str, Any]], list[dict[str, Any]]],
    ) -> int:
        cls_name, methods, fields = entry
        score = 0
        direct_terms = set(direct_keywords or ())
        class_tokens = identifier_tokens(cls_name)

        matched_kw_count = 0
        for kw in keywords:
            if not _match_candidate_keyword(kw, cls_name, cls_name):
                continue
            if kw.casefold() == cls_name.casefold():
                score += 100 if kw in direct_terms else 80
            else:
                score += 50 if kw in direct_terms else 30
            matched_kw_count += 1

        # Multi-keyword match bonus: classes matching MULTIPLE target keywords (e.g., Character + Collision)
        if matched_kw_count > 1:
            score += 40 * (matched_kw_count - 1)

        # Keyword matches on member fields
        for f in fields:
            f_name = str(f.get("name", ""))
            matches = [kw for kw in keywords if _match_candidate_keyword(kw, cls_name, f_name)]
            if matches:
                score += 20 if any(kw in direct_terms for kw in matches) else 10

        # Keyword matches on method names
        for m in methods:
            m_name = str(m.get("method_name", m.get("name", "")))
            matches = [kw for kw in keywords if _match_candidate_keyword(kw, cls_name, m_name)]
            if matches:
                score += 15 if any(kw in direct_terms for kw in matches) else 7

        if any(keyword in CURRENCY_KEYWORDS for keyword in keywords) and has_economy_data_context(cls_name):
            score += 100

        # Boost core data-model & engine physics classes
        if any(_match_keyword(hint, cls_name) for hint in MODEL_HINTS):
            score += 20

        # Heavy penalty for third-party SDK / logger / analytics packages
        _SDK_PREFIXES = (
            "com.facebook.",
            "com.google.",
            "com.tencent.",
            "com.ss.bytertc.",
            "com.nirvana.",
            "com.mobile.auth.",
            "com.reactnativecommunity.",
            "com.horcrux.svg.",
            "com.swmansion.",
            "org.chromium.",
            "io.sentry.",
            "com.adjust.",
            "com.appsflyer.",
            "androidx.",
            "android.support.",
        )
        if any(cls_name.startswith(p) or f".{p}" in cls_name for p in _SDK_PREFIXES):
            score -= 200

        # Heavy penalty for UI / visual / audio / decor / wrapper classes
        penalty_count = sum(1 for hint in UI_PENALTY_HINTS if _match_keyword(hint, cls_name))
        if penalty_count > 0:
            score -= 100 * penalty_count
        if class_tokens & NON_RUNTIME_CLASS_HINTS:
            score -= 250

        return score

    return sorted(candidates, key=score_entry, reverse=True)


def cmd_batch(
    args: argparse.Namespace,
) -> int | tuple[int, list[tuple[str, str, int]], list[AnalyzedTarget]]:
    """Execute autonomous batch discovery and C++ dumping.

    Returns:
        int: Exit code when called standalone.
        tuple[int, list]: (exit_code, discovered_targets) when
            _return_matches=True is set on args by the pipeline.
            Each target is (class_name, field_name, hex_offset).
    """
    config_path = Path(args.config)
    config = load_config(config_path) if config_path.exists() else load_config(None)
    output_dir = Path(args.output_dir or config.project_profile.source_root)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Starting re-agent batch processing (Profile: {config.project_profile.name})...")

    meta_dir = getattr(args, "metadata_dir", None) or "."
    metadata_source = getattr(args, "metadata", None) or meta_dir
    binary_arg = getattr(args, "binary", None) or meta_dir

    # Detect engine type to route metadata loading correctly
    from re_agent.core.engine_detector import detect_architecture_from_path

    architecture = detect_architecture_from_path(
        binary_arg,
        platform_hint=getattr(args, "platform", None),
    )
    engine_type = architecture.engine_type

    # Only scan for IL2CPP metadata if engine is Unity IL2CPP or metadata was explicitly provided
    explicit_metadata = getattr(args, "metadata", None) or getattr(args, "metadata_dir", None)
    il2cpp_meta = (
        find_il2cpp_metadata_in_dir(metadata_source) if engine_type == "unity-il2cpp" or explicit_metadata else None
    )
    methods = il2cpp_meta.get("methods", []) if il2cpp_meta else []
    structs_list = il2cpp_meta.get("structs", []) if il2cpp_meta else []
    dump_cs_classes = il2cpp_meta.get("classes", []) if il2cpp_meta else []

    # Check for Android DEX / APK binaries if no IL2CPP metadata found
    if not (methods or structs_list or dump_cs_classes) and binary_arg:
        from re_agent.core.dex_parser import parse_apk_or_dex

        dex_meta = parse_apk_or_dex(binary_arg)
        if dex_meta and dex_meta.get("classes"):
            dex_classes = dex_meta["classes"]
            dump_cs_classes = [
                {"name": cls_name, "methods": m_list, "fields": []} for cls_name, m_list in dex_classes.items()
            ]
            methods = dex_meta.get("methods", [])
            print(
                f"[+] Loaded Android DEX Java/Kotlin metadata from '{binary_arg}' "
                f"({len(methods)} methods across {len(dump_cs_classes)} classes)."
            )

    structs_map: dict[str, list[dict[str, Any]]] = {}
    struct_display_names: dict[str, str] = {}
    for s in structs_list:
        struct_name = str(s.get("name", ""))
        normalized_name = struct_name.casefold()
        structs_map[normalized_name] = s.get("fields", [])
        if struct_name:
            struct_display_names.setdefault(normalized_name, struct_name)
    for c in dump_cs_classes:
        display_name = str(c.get("name", ""))
        c_name = display_name.casefold()
        if c.get("fields"):
            structs_map[c_name] = c.get("fields", [])
        if display_name:
            struct_display_names[c_name] = display_name

    goal_prompt = getattr(args, "goal", None)
    direct_goal_keywords = extract_entity_keywords(goal_prompt) if goal_prompt else []
    known_domain_goal = any(is_entity_keyword(keyword) for keyword in direct_goal_keywords) if goal_prompt else False
    provider = None

    # A configured provider refines the bounded local shortlist automatically for
    # every goal. Policy is checked before any provider (including fallbacks) is
    # initialized, and local discovery remains usable when the provider is denied
    # or unavailable.
    if goal_prompt:
        try:
            from re_agent.config.policy import require_provider_allowed
            from re_agent.llm.registry import create_provider

            require_provider_allowed(
                config.data_handling,
                config.llm,
                role="batch semantic-analysis",
            )
            provider = create_provider(config.llm)
        except Exception as exc:
            detail = " ".join(str(exc).split())[:500] or type(exc).__name__
            logger.warning("Configured LLM semantic analysis unavailable: %s", detail)
            print(
                f"[!] Configured-provider semantic analysis unavailable; continuing with local evidence only: {detail}",
                flush=True,
            )

    if goal_prompt:
        known_domain_goal = any(is_entity_keyword(keyword) for keyword in direct_goal_keywords)
        if provider is not None:
            route_description = f"local rules plus configured {config.llm.provider} semantic refinement"
        elif known_domain_goal:
            route_description = "local domain rules"
        else:
            route_description = "local rules only"
        print(
            f"[+] Resolving Natural Language Goal ({route_description}): '{goal_prompt}'",
            flush=True,
        )
    goal_keywords = resolve_goal_keywords(goal_prompt, provider=provider) if goal_prompt else []
    if goal_prompt:
        print(f"[+] Resolved Target Patterns: {goal_keywords}")

    # Pillar 1: bundled offline knowledge lookup
    from re_agent.core.web_knowledge import lookup_game_knowledge

    game_hint = getattr(args, "game_name", None) or ""
    search_text = f"{game_hint} {meta_dir} {goal_prompt or ''}".lower()
    known_pattern = lookup_game_knowledge(search_text)
    if known_pattern:
        print(f"[+] Bundled Knowledge Matched: '{known_pattern.game_name}'")
        print(f"    • Known targets: {known_pattern.target_classes}")
        print(f"    • Details: {known_pattern.description}")
        goal_keywords.extend([c.lower() for c in known_pattern.target_classes])

    if methods or structs_list or dump_cs_classes:
        if methods and il2cpp_meta:
            print(f"[+] Loaded IL2CPP metadata from '{meta_dir}' with {len(methods)} methods.")
        if structs_list or (dump_cs_classes and il2cpp_meta):
            print(f"[+] Loaded {len(structs_map)} C++ class/struct layouts from il2cpp.h / dump.cs.")

        class_map = group_methods_by_class(methods) if methods else {}

        # Merge method return types and signatures from dump.cs classes if present
        for c in dump_cs_classes:
            c_name = c.get("name", "")
            c_methods = c.get("methods", [])
            if not c_name or not c_methods:
                continue
            if c_name not in class_map or not class_map[c_name]:
                class_map[c_name] = c_methods
            else:
                _merge_dump_method_evidence(class_map[c_name], c_methods)

        # Also include struct names from il2cpp.h / dump.cs in class_map
        class_names_casefold = {class_name.casefold() for class_name in class_map}
        for normalized_name in structs_map:
            if normalized_name in class_names_casefold:
                continue
            display_name = struct_display_names.get(
                normalized_name,
                normalized_name,
            )
            class_map[display_name] = []
            class_names_casefold.add(normalized_name)

        cls_label = "Java/Kotlin" if engine_type in ["android-java-dex", "react-native-hermes"] else "C++"
        print(f"[+] Discovered {len(class_map)} {cls_label} classes/structs.")

        limit = getattr(args, "limit", None)
        if limit is None:
            limit = 50

        target_classes = []
        if goal_keywords:
            target_classes.extend(goal_keywords)
        if getattr(args, "class_name", None):
            target_classes.extend([c.strip().lower() for c in args.class_name.split(",")])
        if getattr(args, "string", None):
            target_classes.extend(resolve_goal_keywords(args.string, provider=provider))

        raw_candidates: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]] = []

        skip_packages = (
            "java.",
            "javax.",
            "android.",
            "androidx.",
            "kotlin.",
            "kotlinx.",
            "com.google.",
            "com.facebook.",
            "io.sentry.",
            "org.apache.",
            "org.json.",
            "com.squareup.",
            "com.appsflyer.",
            "com.adjust.",
            "com.unity3d.",
            "com.android.",
            "com.amazon.",
            "com.amplitude.",
            "com.braze.",
            "com.onesignal.",
        )

        for cls_name, cls_methods in class_map.items():
            if any(cls_name.startswith(pkg) for pkg in skip_packages):
                continue

            cls_fields = structs_map.get(cls_name.lower(), [])

            if target_classes:
                name_match = any(_match_candidate_keyword(term, cls_name, cls_name) for term in target_classes)
                field_match = any(
                    any(
                        _match_candidate_keyword(
                            term,
                            cls_name,
                            str(field.get("name", "")),
                        )
                        for term in target_classes
                    )
                    for field in cls_fields
                )
                method_match = any(
                    any(
                        _match_candidate_keyword(
                            term,
                            cls_name,
                            str(
                                method.get(
                                    "method_name",
                                    method.get("name", ""),
                                )
                            ),
                        )
                        for term in target_classes
                    )
                    for method in cls_methods
                )
                if not name_match and not field_match and not method_match:
                    continue

            if getattr(args, "symbol", None):
                cls_methods = [m for m in cls_methods if args.symbol.lower() in m.get("name", "").lower()]
                if not cls_methods and cls_name.lower() not in structs_map:
                    continue

            raw_candidates.append((cls_name, cls_methods, cls_fields))

        # Keep the complete locally discovered inventory. The user-facing
        # ``limit`` bounds only the external-model semantic shortlist; it must
        # never discard deterministic candidates from the expanded summary.
        ranked_candidates = rank_classes_by_relevance(
            raw_candidates,
            target_classes,
            direct_goal_keywords,
        )
        semantic_shortlist = ranked_candidates[:limit]

        # Structural Type-Signature Analysis (Obfuscation-Proof Layer)
        from re_agent.core.structural_analysis import analyze_structures

        struct_hits = analyze_structures(ranked_candidates)
        goal_tokens = set(re.findall(r"\b\w+\b", (goal_prompt or "").lower()))
        is_currency_goal = bool(goal_tokens & CURRENCY_KEYWORDS)
        is_collision_goal = bool(goal_tokens & COLLISION_KEYWORDS)
        is_movement_goal = bool(goal_tokens & MOVEMENT_KEYWORDS)
        allowed_structural_categories: set[str] = set()
        if is_currency_goal:
            allowed_structural_categories.add("currency_getter")
        if is_collision_goal:
            allowed_structural_categories.add("damage_check")
        if is_movement_goal:
            allowed_structural_categories.update({"position_getter", "speed_getter"})
        struct_hits = [
            hit
            for hit in struct_hits
            if hit.category in allowed_structural_categories
            and (
                hit.category != "currency_getter"
                or any(
                    _match_candidate_keyword(
                        keyword,
                        hit.class_name,
                        hit.target_name,
                    )
                    for keyword in goal_keywords
                    if keyword in CURRENCY_KEYWORDS
                )
            )
        ]
        if struct_hits:
            print(f"[+] Structural Type Analysis identified {len(struct_hits)} candidates matching method signatures.")

        structural_targets: list[AnalyzedTarget] = []
        method_evidence = {
            (class_name, str(method.get("method_name", method.get("name", "")))): method
            for class_name, class_methods, _class_fields in ranked_candidates
            for method in class_methods
        }
        structural_hook_types = {
            "currency_getter": ("return_override", "int32_t", "999999999"),
            "damage_check": ("skip_call", "void", None),
            "position_getter": ("esp_overlay", "void", None),
            "speed_getter": ("speed_modify", "float", "3.0f"),
        }
        for hit in struct_hits:
            hook_type, return_type, return_value = structural_hook_types.get(
                hit.category,
                ("return_override", "int32_t", "999999999"),
            )
            direct_relevance = not direct_goal_keywords or any(
                _match_candidate_keyword(
                    term,
                    hit.class_name,
                    hit.target_name,
                )
                for term in direct_goal_keywords
            )
            structural_confidence = hit.confidence if direct_relevance else min(hit.confidence, 74)
            relevance_note = "" if direct_relevance else "Indirect domain expansion only; "
            evidence = method_evidence.get((hit.class_name, hit.target_name), {})
            parameter_types = evidence.get("parameter_types", ())
            method_rva = evidence.get("rva") if evidence.get("address_kind") == "method_rva" else None
            structural_targets.append(
                AnalyzedTarget(
                    class_name=hit.class_name,
                    target=hit.target_name,
                    hook_type=hook_type,
                    return_value=return_value,
                    return_type=return_type,
                    confidence=structural_confidence,
                    reason=f"{relevance_note}{hit.details}",
                    method_rva=method_rva if isinstance(method_rva, int) else None,
                    parameter_types=tuple(parameter_types) if isinstance(parameter_types, (list, tuple)) else (),
                    method_descriptor=(str(evidence["descriptor"]) if evidence.get("descriptor") else None),
                    **_method_activation_facts(
                        engine_type,
                        evidence,
                        hook_type,
                    ),
                )
            )

        # Optional configured-provider semantic refinement step.
        llm_targets: list[AnalyzedTarget] = []
        if goal_prompt and provider is not None and semantic_shortlist:
            analysis_started = time.monotonic()
            try:
                from re_agent.llm.semantic_analyzer import analyze_metadata_with_llm

                print(
                    f"[+] Running {config.llm.provider} semantic analysis on "
                    f"{len(semantic_shortlist)} of {len(ranked_candidates)} "
                    "locally discovered candidates...",
                    flush=True,
                )
                llm_targets = analyze_metadata_with_llm(
                    provider,
                    goal_prompt,
                    semantic_shortlist,
                    raise_on_provider_error=True,
                )
                if is_currency_goal:
                    for target in llm_targets:
                        direct_match = any(
                            _match_candidate_keyword(
                                keyword,
                                target.class_name,
                                target.target,
                            )
                            for keyword in direct_goal_keywords
                            if keyword in CURRENCY_KEYWORDS
                        )
                        core_value_match = any(
                            _match_candidate_keyword(
                                keyword,
                                target.class_name,
                                target.target,
                            )
                            for keyword in CORE_CURRENCY_VALUE_KEYWORDS
                        )
                        broad_currency_match = any(
                            _match_candidate_keyword(
                                keyword,
                                target.class_name,
                                target.target,
                            )
                            for keyword in goal_keywords
                            if keyword in CURRENCY_KEYWORDS
                        )
                        if core_value_match and has_economy_data_context(target.class_name):
                            target.confidence = max(target.confidence, 96)
                        elif direct_match:
                            target.confidence = max(target.confidence, 90)
                        elif broad_currency_match:
                            target.confidence = min(target.confidence, 78)
                        else:
                            target.confidence = min(target.confidence, 69)
                elapsed = time.monotonic() - analysis_started
                metadata = getattr(provider, "last_metadata", {})
                selected_provider = metadata.get("provider") if isinstance(metadata, dict) else None
                route_text = (
                    f" via {selected_provider}" if isinstance(selected_provider, str) and selected_provider else ""
                )
                if llm_targets:
                    print(
                        f"[+] Configured-provider analysis{route_text} identified "
                        f"{len(llm_targets)} exact metadata-grounded hook target(s) "
                        f"in {elapsed:.1f}s.",
                        flush=True,
                    )
                else:
                    print(
                        f"[!] Configured-provider analysis{route_text} completed "
                        f"in {elapsed:.1f}s but returned no exact metadata-grounded "
                        "hook targets; continuing with local evidence only.",
                        flush=True,
                    )
            except Exception as e:
                elapsed = time.monotonic() - analysis_started
                detail = " ".join(str(e).split())[:500] or type(e).__name__
                print(
                    f"[!] Configured-provider analysis failed after {elapsed:.1f}s; "
                    f"continuing with local evidence only: {detail}",
                    flush=True,
                )

        # Synthesize structural targets and merge with LLM targets.
        synthesis_started = time.monotonic()
        print(
            "[*] Combining configured-provider results with local structural and field evidence...",
            flush=True,
        )
        fallback_targets: list[AnalyzedTarget] = []
        if goal_prompt:
            currency_terms = [keyword for keyword in goal_keywords if keyword in CORE_CURRENCY_VALUE_KEYWORDS]
            direct_currency_terms = [keyword for keyword in direct_goal_keywords if keyword in CURRENCY_KEYWORDS]
            collision_terms = [keyword for keyword in goal_keywords if keyword in COLLISION_KEYWORDS]
            direct_collision_terms = [keyword for keyword in direct_goal_keywords if keyword in COLLISION_KEYWORDS]
            skip_classes = {
                "Array",
                "Dictionary",
                "GlobalNamespace",
                "InnerResolver",
                "Interop",
                "List",
                "Object",
                "String",
                "Visibility",
                "VisibilityState",
                "c",
            }

            # Exclude non-gameplay/auth key methods
            ignored_key_patterns = {
                "authkey",
                "cryptokey",
                "iscompatiblekey",
                "keycomposer",
                "licensekey",
                "providerkey",
                "sshkey",
            }
            ignored_return_types = {
                "action",
                "delegate",
                "ienumerable",
                "string",
                "system.string",
                "task",
                "void",
            }

            # Primitive C# types allowed for scalar return_override
            primitive_numeric_types = {
                "int",
                "int32",
                "int32_t",
                "uint",
                "uint32",
                "uint32_t",
                "long",
                "int64",
                "int64_t",
                "ulong",
                "uint64",
                "float",
                "double",
                "short",
                "int16",
                "uint16",
                "byte",
                "sbyte",
            }

            for cls_name, cls_methods, cls_fields in ranked_candidates:
                if (
                    cls_name in skip_classes
                    or identifier_tokens(cls_name) & NON_RUNTIME_CLASS_HINTS
                    or any(
                        matches_identifier_keyword(
                            hint,
                            cls_name,
                            min_keyword_length=1,
                        )
                        for hint in UI_PENALTY_HINTS
                    )
                ):
                    continue

                # Currency Goal Matching
                if is_currency_goal:
                    for f in cls_fields:
                        f_name = f.get("name", "")
                        f_off = f.get("offset")
                        if f_off is None:
                            continue
                        if not isinstance(f_off, int) or f_off < 0:
                            continue
                        f_lower = f_name.lower()
                        f_type = str(f.get("type", "int32_t")).lower().strip()
                        if not _is_scalar_currency_field_type(f_type) or not is_balance_value_member(f_name):
                            continue
                        matched_kw = next(
                            (
                                keyword
                                for keyword in currency_terms
                                if _match_candidate_keyword(
                                    keyword,
                                    cls_name,
                                    f_name,
                                )
                            ),
                            None,
                        )
                        if matched_kw:
                            if any(ig in f_lower for ig in ignored_key_patterns):
                                continue
                            direct_match = any(
                                _match_candidate_keyword(
                                    keyword,
                                    cls_name,
                                    f_name,
                                )
                                for keyword in direct_currency_terms
                            )
                            contextual_value_match = (
                                matched_kw in CORE_CURRENCY_VALUE_KEYWORDS and has_economy_data_context(cls_name)
                            )
                            c_label = matched_kw.capitalize()
                            fallback_targets.append(
                                AnalyzedTarget(
                                    class_name=cls_name,
                                    target=f_name,
                                    offset=f_off,
                                    hook_type="memory_patch",
                                    return_value="999999",
                                    return_type="int32_t",
                                    confidence=(96 if contextual_value_match else 90 if direct_match else 74),
                                    reason=(
                                        f"{'Direct goal' if direct_match else 'Indirect domain'} "
                                        f"structural match: {c_label} field in {cls_name}"
                                    ),
                                )
                            )
                    for m in cls_methods:
                        m_name = m.get("method_name", m.get("name", ""))
                        m_lower = m_name.lower()
                        m_ret = m.get("return_type", "int32_t").lower().strip()

                        # Skip C# event subscriptions (add_On*, remove_On*)
                        if m.get("is_event") or m_lower.startswith(("add_", "remove_", "subscribe", "unsubscribe")):
                            continue
                        if any(ig in m_lower for ig in ignored_key_patterns):
                            continue
                        if not is_balance_value_member(m_name):
                            continue
                        if any(ig in m_ret for ig in ignored_return_types) or "*" in m_ret:
                            continue

                        is_bool = "bool" in m_ret or m_lower.startswith(("is", "has"))
                        if not is_bool and m_ret not in primitive_numeric_types:
                            # Skip custom C# class objects (Product, CurrencyType, etc.)
                            continue
                        if is_bool and not m_lower.startswith(("has_", "has")):
                            continue

                        matched_kw = next(
                            (
                                keyword
                                for keyword in currency_terms
                                if _match_candidate_keyword(
                                    keyword,
                                    cls_name,
                                    m_name,
                                )
                            ),
                            None,
                        )
                        if m_lower.startswith(("get_", "get", "has_", "has")) and matched_kw:
                            ret_type = "bool" if is_bool else "int32_t"
                            ret_val = "true" if is_bool else "999999999"
                            direct_match = any(
                                _match_candidate_keyword(
                                    keyword,
                                    cls_name,
                                    m_name,
                                )
                                for keyword in direct_currency_terms
                            )
                            contextual_value_match = (
                                matched_kw in CORE_CURRENCY_VALUE_KEYWORDS and has_economy_data_context(cls_name)
                            )
                            c_label = matched_kw.capitalize()

                            fallback_targets.append(
                                AnalyzedTarget(
                                    class_name=cls_name,
                                    target=m_name,
                                    hook_type="return_override",
                                    return_value=ret_val,
                                    return_type=ret_type,
                                    confidence=(
                                        93
                                        if contextual_value_match and is_bool
                                        else 96
                                        if contextual_value_match
                                        else 90
                                        if direct_match
                                        else 74
                                    ),
                                    reason=(
                                        f"{'Direct goal' if direct_match else 'Indirect domain'} "
                                        f"structural match: {c_label} getter in {cls_name}"
                                    ),
                                    method_rva=(
                                        m.get("rva")
                                        if m.get("address_kind") == "method_rva" and isinstance(m.get("rva"), int)
                                        else None
                                    ),
                                    parameter_types=tuple(m.get("parameter_types", ()))
                                    if isinstance(m.get("parameter_types"), (list, tuple))
                                    else (),
                                    method_descriptor=(str(m["descriptor"]) if m.get("descriptor") else None),
                                    **_method_activation_facts(
                                        engine_type,
                                        m,
                                        "return_override",
                                    ),
                                )
                            )

                # Collision Goal Matching
                if is_collision_goal:
                    for m in cls_methods:
                        m_name = m.get("method_name", m.get("name", ""))
                        m_lower = m_name.lower()
                        if m.get("is_event") or m_lower.startswith(("add_", "remove_", "subscribe", "unsubscribe")):
                            continue
                        matched_collision = next(
                            (keyword for keyword in collision_terms if _match_keyword(keyword, m_name)),
                            None,
                        )
                        direct_collision_match = any(
                            _match_keyword(keyword, m_name) for keyword in direct_collision_terms
                        )
                        collision_confidence = 85 if direct_collision_match else 74
                        if matched_collision and not any(
                            _match_keyword(word, m_name) for word in ("anim", "effect", "particle", "sound", "theme")
                        ):
                            if m_lower.startswith(("get_", "is_", "has_")):
                                fallback_targets.append(
                                    AnalyzedTarget(
                                        class_name=cls_name,
                                        target=m_name,
                                        hook_type="return_override",
                                        return_value="false",
                                        return_type="bool",
                                        confidence=collision_confidence,
                                        reason=(
                                            f"{'Direct goal' if direct_collision_match else 'Indirect domain'} "
                                            f"structural match: Disable {matched_collision} getter "
                                            f"in {cls_name}"
                                        ),
                                        method_rva=(
                                            m.get("rva")
                                            if m.get("address_kind") == "method_rva" and isinstance(m.get("rva"), int)
                                            else None
                                        ),
                                        parameter_types=tuple(m.get("parameter_types", ()))
                                        if isinstance(m.get("parameter_types"), (list, tuple))
                                        else (),
                                        method_descriptor=(str(m["descriptor"]) if m.get("descriptor") else None),
                                        **_method_activation_facts(
                                            engine_type,
                                            m,
                                            "return_override",
                                        ),
                                    )
                                )
                            elif m_lower.startswith("set_"):
                                continue  # Skip setters to avoid breaking internal state
                            else:
                                fallback_targets.append(
                                    AnalyzedTarget(
                                        class_name=cls_name,
                                        target=m_name,
                                        hook_type="skip_call",
                                        return_type="void",
                                        confidence=collision_confidence,
                                        reason=(
                                            f"{'Direct goal' if direct_collision_match else 'Indirect domain'} "
                                            f"structural match: {matched_collision} callback in {cls_name}"
                                        ),
                                        method_rva=(
                                            m.get("rva")
                                            if m.get("address_kind") == "method_rva" and isinstance(m.get("rva"), int)
                                            else None
                                        ),
                                        parameter_types=tuple(m.get("parameter_types", ()))
                                        if isinstance(m.get("parameter_types"), (list, tuple))
                                        else (),
                                        method_descriptor=(str(m["descriptor"]) if m.get("descriptor") else None),
                                    )
                                )

        candidate_targets = list(rank_candidates(llm_targets + fallback_targets + structural_targets))
        matched_offsets_summary: list[str] = []
        discovered_targets: list[tuple[str, str, int]] = []
        class_fields_by_name: dict[str, list[dict[str, Any]]] = {}

        for cls_name, _cls_methods, cls_fields in ranked_candidates:
            class_fields_by_name[cls_name] = cls_fields
            if not cls_fields:
                continue
            # Suffixes/patterns indicating object pointers rather than scalar
            # numeric values.
            pointer_field_hints = {
                "model",
                "manager",
                "ptr",
                "ref",
                "controller",
                "system",
                "adapter",
                "instance",
                "service",
                "handler",
                "provider",
                "context",
            }
            for field in cls_fields:
                field_name = str(field.get("name", ""))
                field_offset = field.get("offset")
                if not isinstance(field_offset, int) or field_offset < 0:
                    continue
                if (
                    identifier_tokens(cls_name) & (NON_RUNTIME_CLASS_HINTS | UI_PENALTY_HINTS)
                    or not _is_scalar_currency_field_type(field.get("type", ""))
                    or not is_balance_value_member(field_name)
                ):
                    continue
                field_name_lower = field_name.lower()
                if any(
                    field_name_lower.endswith(hint) or f"_{hint}" in field_name_lower for hint in pointer_field_hints
                ):
                    continue
                offset_keywords = direct_goal_keywords or goal_keywords
                if offset_keywords and any(
                    _match_candidate_keyword(
                        keyword,
                        cls_name,
                        field_name,
                    )
                    for keyword in offset_keywords
                ):
                    matched_offsets_summary.append(f"  . {cls_name}::{field_name} -> Offset: 0x{field_offset:X}")
                    discovered_targets.append((cls_name, field_name, field_offset))

        raw_targets = [
            AnalyzedTarget(
                class_name=class_name,
                target=field_name,
                offset=offset,
                hook_type="memory_patch",
                return_value="999999",
                return_type="int32_t",
                confidence=30,
                reason="Keyword-matched field offset without semantic verification",
            )
            for class_name, field_name, offset in discovered_targets
        ]
        candidate_targets = list(rank_candidates(candidate_targets + raw_targets))
        print(
            f"[+] Candidate synthesis completed in "
            f"{time.monotonic() - synthesis_started:.1f}s; retained "
            f"{len(candidate_targets)} evidence-ranked target(s).",
            flush=True,
        )

        dumped_count = 0
        if engine_type not in {"android-java-dex", "react-native-hermes"}:
            selected_inventory_classes: list[str] = []
            selected_names: set[str] = set()
            for target in candidate_targets:
                class_name = target.class_name
                if (
                    class_name in class_fields_by_name
                    and class_fields_by_name[class_name]
                    and class_name.casefold() not in selected_names
                ):
                    selected_inventory_classes.append(class_name)
                    selected_names.add(class_name.casefold())
                if len(selected_inventory_classes) >= MAX_OFFSET_INVENTORY_FILES:
                    break

            if selected_inventory_classes:
                print(
                    f"[*] Writing {len(selected_inventory_classes)} relevant "
                    "C++ offset inventories (bounded artifact set)...",
                    flush=True,
                )
            used_filenames: set[str] = set()
            for class_name in selected_inventory_classes:
                header_code = generate_vtable_header(
                    class_name,
                    [],
                    class_fields_by_name[class_name],
                )
                base_name = safe_filename(class_name, suffix=".h")
                header_name = base_name
                collision_index = 2
                while header_name.casefold() in used_filenames:
                    stem = Path(base_name).stem
                    header_name = f"{stem}_{collision_index}.h"
                    collision_index += 1
                used_filenames.add(header_name.casefold())
                header_file = output_dir / header_name
                header_file.write_text(header_code, encoding="utf-8")
                dumped_count += 1
                logger.info(
                    "[+] Dumped evidence-backed offset inventory %s: %s",
                    class_name,
                    header_file,
                )

        if matched_offsets_summary:
            print("\n[+] MATCHED FIELD OFFSETS:")
            for summary_line in matched_offsets_summary[:15]:
                print(summary_line)

        if dumped_count > 0:
            print(f"\n[DONE] Wrote {dumped_count} evidence-backed C++ offset inventories into '{output_dir}'.")
        elif engine_type in {"android-java-dex", "react-native-hermes"}:
            print("\n[DONE] Successfully ingested Android Java/Kotlin class metadata.")
        else:
            print("\n[DONE] Metadata ingestion completed; no relevant per-class offset inventory was required.")

        if not getattr(args, "_suppress_candidate_display", False):
            print("\n[+] UNIVERSAL CANDIDATE SELECTION")
            print_candidate_summary(candidate_targets, stream=sys.stdout)

        if getattr(args, "_return_matches", False):
            return 0, discovered_targets, candidate_targets
        return 0

    # Native pathways can still retain bounded string/symbol evidence, but it
    # is deliberately review-only: strings do not establish code xrefs,
    # callable addresses, signatures, or runtime semantics.
    if binary_arg and goal_keywords and architecture.pathway_id in {3, 4, 5, 7, 8}:
        from re_agent.core.native_scanner import scan_native_evidence

        native_targets = list(scan_native_evidence(binary_arg, goal_keywords))
        if native_targets:
            print(f"[+] Retained {len(native_targets)} bounded native string/symbol evidence candidates (review-only).")
            if not getattr(args, "_suppress_candidate_display", False):
                print("\n[+] UNIVERSAL CANDIDATE SELECTION")
                print_candidate_summary(native_targets, stream=sys.stdout)
            if getattr(args, "_return_matches", False):
                return 0, [], native_targets
            return 0

    # Missing metadata is an explicit insufficient-evidence outcome. Never
    # fabricate class layouts, offsets, or reconstructed method bodies.
    print(
        "[!] INSUFFICIENT_EVIDENCE: no supported metadata or DEX class evidence "
        "was recovered; no source or active target was generated."
    )
    if not getattr(args, "_suppress_candidate_display", False):
        print("\n[+] UNIVERSAL CANDIDATE SELECTION")
        print_candidate_summary([], stream=sys.stdout)
    if getattr(args, "_return_matches", False):
        return 3, [], []
    return 3
