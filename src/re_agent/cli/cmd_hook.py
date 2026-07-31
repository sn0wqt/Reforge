"""CLI command for generating platform-specific C++, Objective-C++, Rust, and dynamic BNM hooks."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from re_agent.config.domain_keywords import is_contextual_currency_match
from re_agent.config.loader import load_config
from re_agent.core.candidates import rank_candidates, split_candidates
from re_agent.utils.address import format_address
from re_agent.utils.paths import safe_identifier
from re_agent.utils.w2s import generate_w2s_cpp_helper

_CPP_TYPES = {"int32_t", "int64_t", "float", "double", "bool", "void", "void*"}
MAX_REVIEW_HOOK_CANDIDATES = 20


def _safe_comment(value: object) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").replace("*/", "* /")[:500]


def _cpp_string(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def _safe_cpp_type(value: object, *, fallback: str = "int32_t") -> str:
    candidate = str(value or fallback).strip()
    return candidate if candidate in _CPP_TYPES else fallback


def _safe_cpp_literal(value: object, return_type: str) -> str:
    text = str(value).strip()
    if return_type == "bool" and text in {"true", "false"}:
        return text
    if return_type in {"int32_t", "int64_t"} and re.fullmatch(r"[-+]?\d+(?:LL)?", text):
        return text
    if return_type in {"float", "double"} and re.fullmatch(
        r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[fF])?",
        text,
    ):
        return text
    if return_type == "void":
        return ""
    return {
        "bool": "false",
        "int32_t": "0",
        "int64_t": "0LL",
        "float": "0.0f",
        "double": "0.0",
        "void*": "nullptr",
    }.get(return_type, "0")


def _is_activation_ready(
    target: Any,
    *,
    generator: str,
    pathway: str = "",
) -> bool:
    """Fail closed unless every activation prerequisite is explicit."""
    if not all(
        getattr(target, attribute, False) is True
        for attribute in (
            "signature_verified",
            "address_verified",
            "implementation_ready",
        )
    ):
        return False

    hook_type = str(getattr(target, "hook_type", ""))
    offset = getattr(target, "offset", None)
    if hook_type in {"memory_patch", "multi_memory_patch"} and (
        not isinstance(offset, int) or isinstance(offset, bool) or offset < 0
    ):
        return False

    if generator == "il2cpp" or (generator == "cpp" and pathway.startswith("unity-il2cpp")):
        return hook_type in {
            "return_override",
            "memory_patch",
            "multi_memory_patch",
            "skip_call",
            "speed_modify",
            "nop",
        }
    if generator == "frida":
        return hook_type in {
            "return_override",
            "memory_patch",
            "multi_memory_patch",
            "skip_call",
            "speed_modify",
            "nop",
        }
    return False


def _partition_for_activation(
    targets: list[Any],
    *,
    generator: str,
    pathway: str = "",
) -> tuple[list[Any], list[Any]]:
    """Rank verified hooks for activation and retain all others for review."""
    ranked = list(rank_candidates(targets))
    ready = [
        target
        for target in ranked
        if _is_activation_ready(
            target,
            generator=generator,
            pathway=pathway,
        )
    ]
    ready_groups = split_candidates(ready)
    active = list(ready_groups.primary)
    active_keys = {
        (
            target.class_name.casefold(),
            target.target.casefold(),
            target.hook_type,
            target.offset,
            target.method_rva,
            target.parameter_types,
        )
        for target in active
    }
    review_only = list(
        rank_candidates(
            target
            for target in ranked
            if (
                target.class_name.casefold(),
                target.target.casefold(),
                target.hook_type,
                target.offset,
                target.method_rva,
                target.parameter_types,
            )
            not in active_keys
        )
    )
    return active, review_only


def generate_universal_hook_for_goal(
    goal_text: str,
    top_matches: list[tuple[str, str, int]] | None = None,
    analyzed_targets: list[Any] | None = None,
) -> str:
    """Generate C++ hooks from LLM-analyzed targets or raw tuples.

    When ``analyzed_targets`` is provided (from Gemini analysis), each
    target gets hook code matching its ``hook_type``.  Falls back to
    raw ``top_matches`` tuples with generic memory-patch behavior.
    """
    from re_agent.llm.analyzed_target import AnalyzedTarget

    # Convert raw tuples to AnalyzedTarget if no LLM results
    targets: list[AnalyzedTarget] = []
    if analyzed_targets:
        for t in analyzed_targets:
            if isinstance(t, AnalyzedTarget):
                targets.append(t)
    elif top_matches:
        for cls, field, off in top_matches:
            targets.append(
                AnalyzedTarget(
                    class_name=cls,
                    target=field,
                    offset=off,
                    hook_type="memory_patch",
                    return_value="999999",
                    confidence=50,
                    reason="Keyword match (no LLM)",
                )
            )
    # Partition individual evidence before consolidating same-class fields. A
    # weak, unresolved, or unverified sibling must never ride into an active
    # block through a stronger field.
    active_individual, review_individual = _partition_for_activation(
        targets,
        generator="il2cpp",
    )
    review_total = len(review_individual)
    review_individual = review_individual[:MAX_REVIEW_HOOK_CANDIDATES]
    review_omitted = review_total - len(review_individual)

    def group_partition(
        partition: list[AnalyzedTarget],
    ) -> tuple[list[AnalyzedTarget], dict[str, list[AnalyzedTarget]]]:
        grouped: list[AnalyzedTarget] = []
        memory: dict[str, list[AnalyzedTarget]] = {}
        for target in partition:
            if target.hook_type == "memory_patch":
                memory.setdefault(target.class_name, []).append(target)
            else:
                grouped.append(target)
        for class_name, patches in memory.items():
            if len(patches) == 1:
                grouped.append(patches[0])
                continue
            grouped.append(
                AnalyzedTarget(
                    class_name=class_name,
                    target=f"MultiPatch_{class_name}",
                    offset=patches[0].offset,
                    hook_type="multi_memory_patch",
                    return_value="999999",
                    confidence=min(patch.confidence for patch in patches),
                    reason="Consolidated same-tier field candidates: " + ", ".join(patch.target for patch in patches),
                    signature_verified=all(patch.signature_verified for patch in patches),
                    address_verified=all(patch.address_verified for patch in patches),
                    implementation_ready=all(patch.implementation_ready for patch in patches),
                )
            )
        return grouped, memory

    active_targets, active_memory_patches = group_partition(active_individual)
    alt_targets, alt_memory_patches = group_partition(review_individual)

    active_hook_blocks: list[str] = []
    active_installs: list[str] = []

    for idx, t in enumerate(active_targets):
        safe = safe_identifier(f"{t.class_name}_{t.target}")
        if t.hook_type == "multi_memory_patch":
            patches = active_memory_patches.get(t.class_name, [])
            block, install = _gen_multi_memory_patch(idx, t.class_name, patches)
        else:
            block, install = _gen_hook_for_target(idx, t, safe)
        active_hook_blocks.append(block)
        active_installs.append(install)

    alt_hook_blocks: list[str] = []
    alt_installs: list[str] = []

    for idx, t in enumerate(alt_targets, start=len(active_targets)):
        safe = safe_identifier(f"{t.class_name}_{t.target}")
        if t.hook_type == "multi_memory_patch":
            patches = alt_memory_patches.get(t.class_name, [])
            block, install = _gen_multi_memory_patch(idx, t.class_name, patches)
        else:
            block, install = _gen_hook_for_target(idx, t, safe)
        alt_hook_blocks.append(block)
        alt_installs.append(install)

    active_hooks_str = "\n\n".join(active_hook_blocks) or "// No candidate has complete verified activation evidence."
    active_installs_str = "\n".join(active_installs) or "    // No verified hook installation selected."
    emitted_targets = active_individual + review_individual
    w2s_section = (
        generate_w2s_cpp_helper() if any(target.hook_type == "esp_overlay" for target in emitted_targets) else ""
    )

    alt_section = ""
    alt_install_section = ""
    if alt_hook_blocks:
        alt_hooks_code = "\n\n".join(alt_hook_blocks)
        omitted_note = (
            f"\n// {review_omitted} additional review candidates are retained in patch_diff_summary.txt.\n"
            if review_omitted
            else ""
        )
        alt_section = f"""
// ============================================================================
// TARGET GROUP B (REVIEW-ONLY / UNVERIFIED - COMMENTED OUT)
// Verify ABI, address/selector, and implementation readiness before enabling.
// Emitting {len(review_individual)} of {review_total} review candidates.
// ============================================================================
/*
{alt_hooks_code}
*/{omitted_note}"""
        alt_installs_code = "\n".join(alt_installs)
        alt_install_section = f"""
    /*
    // --- Review-only installation calls (verification required) ---
{alt_installs_code}
    */"""

    return f"""// Auto-generated candidate hooks for goal: {_safe_comment(goal_text)}
// Generated by re-agent from evidence-ranked candidate analysis
#include "Il2CppResolver.h"
#include <cstdint>
#include <cmath>

{w2s_section}

// ============================================================================
// TARGET GROUP A (VERIFIED ACTIVE TARGETS - >=85% CONFIDENCE)
// ============================================================================

{active_hooks_str}
{alt_section}

// ============================================================================
// HOOK INSTALLATION PROCEDURES
// ============================================================================

void install_universal_mod_hooks() {{
    Il2Cpp::Thread::Attach();

{active_installs_str}
{alt_install_section}
}}
"""


def generate_cpp_hook_for_pathway(
    goal_text: str,
    analyzed_targets: list[Any],
    *,
    pathway: str,
) -> str:
    """Generate modular Unity or native C++ candidate scaffolding."""
    if pathway.startswith("unity-il2cpp"):
        return generate_universal_hook_for_goal(
            goal_text,
            analyzed_targets=analyzed_targets,
        )

    from re_agent.llm.analyzed_target import AnalyzedTarget

    typed_targets = [target for target in analyzed_targets if isinstance(target, AnalyzedTarget)]
    active_targets, review_targets = _partition_for_activation(
        typed_targets,
        generator="native",
        pathway=pathway,
    )
    review_total = len(review_targets)
    review_targets = review_targets[:MAX_REVIEW_HOOK_CANDIDATES]
    review_omitted = review_total - len(review_targets)

    from re_agent.parity.sigscan import generate_signature

    def _native_block(index: int, target: AnalyzedTarget) -> str:
        safe = re.sub(
            r"[^a-zA-Z0-9_]",
            "_",
            f"{target.class_name}_{target.target}",
        ).strip("_")
        sig_comment = ""
        instructions = getattr(target, "instructions", None)
        if instructions:
            sig = generate_signature(instructions)
            if sig:
                sig_comment = f"\n// Pattern signature: {sig}"

        if target.method_rva is not None:
            address_evidence = f"method RVA 0x{target.method_rva:X}"
        elif target.offset is not None:
            address_evidence = f"field offset +0x{target.offset:X} (not executable)"
        else:
            address_evidence = "unresolved"
        return f"""// [{target.confidence}%] {_safe_comment(target.class_name)}::{_safe_comment(target.target)}
// {_safe_comment(target.reason)}
// Address evidence: {address_evidence}{sig_comment}

static void candidate_{index}_{safe}(void* self) {{
    // TODO: declare the verified ABI before changing arguments or return values.
    (void)self;
}}

static void install_candidate_{index}() {{
    // TODO: resolve the owning module, apply ASLR slide, and install Dobby/MinHook.
    // Address evidence above is informational until the ABI is verified.
}}"""

    primary_blocks = [_native_block(index, target) for index, target in enumerate(active_targets, 1)]
    secondary_blocks = [
        _native_block(index, target)
        for index, target in enumerate(
            review_targets,
            len(active_targets) + 1,
        )
    ]
    installs = "\n".join(f"    install_candidate_{index}();" for index in range(1, len(active_targets) + 1))
    secondary_installs = "\n".join(
        f"    install_candidate_{index}();"
        for index in range(
            len(active_targets) + 1,
            len(active_targets) + len(review_targets) + 1,
        )
    )
    primary_code = (
        "\n\n".join(primary_blocks) or "// No native candidate has a complete resolver, ABI, and implementation."
    )
    secondary_code = "\n\n".join(secondary_blocks) or "// No review-only candidates."

    return f"""// Auto-generated native C++ candidate scaffolding
// Goal: {_safe_comment(goal_text)}
// Pathway: {_safe_comment(pathway)}
#include <cstdint>

// ============================================================================
// TARGET GROUP A (VERIFIED ACTIVE TARGETS - >=85% CONFIDENCE)
// ============================================================================
{primary_code}

/*
// ============================================================================
// TARGET GROUP B (REVIEW-ONLY / UNVERIFIED - DO NOT ENABLE WITHOUT VERIFICATION)
// Emitting {len(review_targets)} of {review_total} review candidates.
// ============================================================================
{secondary_code}
*/

// {review_omitted} additional review candidates are retained in
// patch_diff_summary.txt.

void install_goal_hooks() {{
{installs or "    // No primary candidate installation selected."}

    /*
    // Review-only candidate installation calls:
{secondary_installs or "    // No secondary candidates."}
    */
}}
"""


def generate_frida_java_script(
    goal_text: str,
    active_targets: list[Any],
    alt_targets: list[Any] | None = None,
    *,
    pathway: str = "android-java-kotlin-dex",
) -> str:
    """Generate modular Frida scaffolding for Java, Hermes, native Android, or iOS."""
    from re_agent.llm.analyzed_target import AnalyzedTarget

    supplied_targets = list(active_targets)
    if alt_targets is not None:
        supplied_targets.extend(alt_targets)
    typed_targets = [target for target in supplied_targets if isinstance(target, AnalyzedTarget)]
    active_targets, alt_targets = _partition_for_activation(
        typed_targets,
        generator="frida",
        pathway=pathway,
    )
    review_total = len(alt_targets)
    alt_targets = alt_targets[:MAX_REVIEW_HOOK_CANDIDATES]
    review_omitted = review_total - len(alt_targets)

    def _js_literal(value: Any, return_type: str, method_name: str) -> str:
        if value is None:
            if "bool" in return_type.lower() or method_name.lower().startswith(("is", "has")):
                return "true"
            return "999999999"
        text = str(value).strip()
        if text.lower() in {"true", "false", "null"}:
            return text.lower()
        numeric = re.fullmatch(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:f|ll)?", text, re.IGNORECASE)
        if numeric:
            return re.sub(r"(?:f|ll)$", "", text, flags=re.IGNORECASE)
        return json.dumps(text)

    def _build_js_block(target: Any) -> str:
        cls_name = str(getattr(target, "class_name", ""))
        method_name = str(getattr(target, "target", ""))
        reason = _safe_comment(getattr(target, "reason", ""))
        confidence = int(getattr(target, "confidence", 0))
        hook_type = str(getattr(target, "hook_type", ""))
        return_type = str(getattr(target, "return_type", ""))
        parameter_types = tuple(getattr(target, "parameter_types", ()))
        method_descriptor = getattr(target, "method_descriptor", None)
        method_rva = getattr(target, "method_rva", None)
        return_value = _js_literal(
            getattr(target, "return_value", None),
            return_type,
            method_name,
        )
        if not cls_name or not method_name:
            return ""

        cls_js = json.dumps(cls_name)
        method_js = json.dumps(method_name)
        label_js = json.dumps(f"{cls_name}::{method_name}")
        header = (
            f"    // [{confidence}%] {_safe_comment(cls_name)}::"
            f"{_safe_comment(method_name)} ({_safe_comment(hook_type)}) | {reason}"
        )

        if cls_name == "HermesBundle" or hook_type == "js_property_patch":
            return f"""{header}
    try {{
        const candidate = {{
            property: {method_js},
            replacement: {return_value},
            pathway: {json.dumps(pathway)}
        }};
        console.log("[re-agent] Hermes property candidate: " + JSON.stringify(candidate));
        // Runtime binding is app-specific. Attach this candidate at the JS/native
        // persistence bridge instead of compiling decompiler pseudo-JS.
    }} catch (error) {{
        console.log("[!] Hermes candidate failed: " + error);
    }}"""

        if pathway in {
            "android-java-kotlin-dex",
            "react-native-hermes-android",
        }:
            if method_descriptor and all(isinstance(parameter, str) and parameter for parameter in parameter_types):
                overload_args = ", ".join(json.dumps(parameter) for parameter in parameter_types)
                fn_params = ", ".join(f"arg{i}" for i in range(len(parameter_types)))
                return f"""{header}
    try {{
        const TargetClass = Java.use({cls_js});
        const overload = TargetClass[{method_js}].overload({overload_args});
                console.log("[re-agent] Installing verified return override for "
                    + {label_js} + " " + {json.dumps(method_descriptor)});
                overload.implementation = function ({fn_params}) {{
                    console.log("[re-agent] Entered " + {label_js});
                    return {return_value};
                }};
    }} catch (error) {{
        console.log("[!] Failed to hook " + {label_js} + ": " + error);
    }}"""
            return f"""{header}
    try {{
        const TargetClass = Java.use({cls_js});
        const overloads = TargetClass[{method_js}].overloads;
        overloads.forEach(function (overload) {{
            console.log("[re-agent] Candidate overload (disabled pending signature review): "
                + overload.toString());
        }});
    }} catch (error) {{
        console.log("[!] Failed to hook " + {label_js} + ": " + error);
    }}"""

        if pathway.startswith("unity-il2cpp") and isinstance(method_rva, int):
            module_name = {
                "unity-il2cpp-android": "libil2cpp.so",
                "unity-il2cpp-ios": "UnityFramework",
                "unity-il2cpp-windows": "GameAssembly.dll",
            }.get(pathway, "libil2cpp.so")
            return f"""{header}
    try {{
        const module = Process.getModuleByName({json.dumps(module_name)});
        const address = module.base.add(0x{method_rva:X});
        console.log("[re-agent] Attaching RVA interceptor at " + address
            + " in " + module.name);
        Interceptor.attach(address, {{
            onEnter(args) {{ console.log("[re-agent] Entered " + {label_js}); }},
            onLeave(retval) {{
                retval.replace(ptr({return_value}));
            }}
        }});
    }} catch (error) {{
        console.log("[!] Failed to attach " + {label_js} + ": " + error);
    }}"""

        if pathway in {"react-native-hermes-ios", "native-ios-swift-objc"}:
            return f"""{header}
    try {{
        if (!ObjC.available) throw new Error("Objective-C runtime unavailable");
        const TargetClass = ObjC.classes[{cls_js}];
        if (!TargetClass) throw new Error("class not loaded");
        const method = TargetClass["- " + {method_js}] || TargetClass["+ " + {method_js}];
        if (!method) throw new Error("selector not found");
        Interceptor.attach(method.implementation, {{
            onEnter(args) {{ console.log("[re-agent] Entered " + {label_js}); }},
            onLeave(retval) {{
                // Review the real ABI before enabling a return replacement.
            }}
        }});
    }} catch (error) {{
        console.log("[!] Failed to attach " + {label_js} + ": " + error);
    }}"""

        return f"""{header}
    try {{
        const exported = Module.findGlobalExportByName({method_js});
        const address = exported;
        if (address === null || address.isNull()) throw new Error("address unresolved");
        Interceptor.attach(address, {{
            onEnter(args) {{ console.log("[re-agent] Entered " + {label_js}); }},
            onLeave(retval) {{
                // Review the real ABI before changing arguments or return values.
            }}
        }});
    }} catch (error) {{
        console.log("[!] Failed to attach " + {label_js} + ": " + error);
    }}"""

    active_blocks = [block for target in active_targets if (block := _build_js_block(target))]
    secondary_blocks = [block for target in (alt_targets or []) if (block := _build_js_block(target))]
    active_js = "\n\n".join(active_blocks) or "    // No candidate has complete verified activation evidence."
    secondary_js = "\n\n".join(secondary_blocks) or "    // No review-only candidates."
    uses_java = pathway in {"android-java-kotlin-dex", "react-native-hermes-android"}
    wrapper_start = "Java.perform(function () {" if uses_java else "setImmediate(function () {"

    return f"""// Auto-generated Frida candidate scaffolding for goal: {json.dumps(goal_text)}
// Pathway: {pathway}
// Only candidates with verified signature, address/selector, and completed
// implementation are active. Every other candidate is review-only and commented.
// Run with: frida -U -f <bundle-or-package-id> -l Hook_Frida.js

{wrapper_start}
    console.log("[+] re-agent Frida candidate scaffolding loaded");

    // ============================================================================
    // TARGET GROUP A (VERIFIED ACTIVE TARGETS - >=85% CONFIDENCE)
    // ============================================================================
{active_js}

    /*
    // ============================================================================
    // TARGET GROUP B (REVIEW-ONLY / UNVERIFIED - VERIFICATION REQUIRED)
    // Emitting {len(alt_targets)} of {review_total} review candidates.
    // ============================================================================
{secondary_js}
    */

    // {review_omitted} additional review candidates are retained in
    // patch_diff_summary.txt.
}});
"""


def _gen_hook_for_target(
    idx: int,
    t: Any,
    safe_name: str,
) -> tuple[str, str]:
    """Generate a single hook block + install call for one target."""
    header = (
        f"// [{int(t.confidence)}% confidence] {_safe_comment(t.class_name)}::"
        f"{_safe_comment(t.target)} | {_safe_comment(t.hook_type)} | "
        f"{_safe_comment(t.reason)}"
    )
    if t.method_rva is not None:
        header += f"\n// Verified metadata kind: method RVA 0x{t.method_rva:X}"

    if t.hook_type == "return_override":
        return _gen_return_override(idx, t, safe_name, header)
    if t.hook_type == "memory_patch":
        return _gen_memory_patch(idx, t, safe_name, header)
    if t.hook_type == "skip_call":
        return _gen_skip_call(idx, t, safe_name, header)
    if t.hook_type == "esp_overlay":
        return _gen_esp_overlay(idx, t, safe_name, header)
    if t.hook_type == "speed_modify":
        return _gen_speed_modify(idx, t, safe_name, header)
    if t.hook_type == "nop":
        return _gen_nop(idx, t, safe_name, header)

    # Fallback to memory_patch
    return _gen_memory_patch(idx, t, safe_name, header)


def _gen_return_override(
    idx: int,
    t: Any,
    safe: str,
    header: str,
) -> tuple[str, str]:
    """Hook a getter method to return a modified value."""
    ret_t = _safe_cpp_type(t.return_type)
    if t.return_value is not None:
        ret_v = _safe_cpp_literal(t.return_value, ret_t)
    elif ret_t == "bool":
        ret_v = "true"
    elif ret_t in ("float", "double"):
        ret_v = "999999.0f"
    elif ret_t in ("int64_t", "long", "int64"):
        ret_v = "999999999LL"
    else:
        ret_t = "int32_t"
        ret_v = _safe_cpp_literal(t.return_value or "999999999", ret_t)
    class_literal = _cpp_string(t.class_name)
    target_literal = _cpp_string(t.target)
    param_types = tuple(getattr(t, "parameter_types", ()))
    if param_types:
        param_decl = ", ".join(["void* self", *[f"int32_t arg{i}" for i in range(len(param_types))]])
    else:
        param_decl = "void* self"

    block = f"""{header}
typedef {ret_t} (*orig_{safe}_t)({param_decl});
static orig_{safe}_t orig_{safe} = nullptr;

{ret_t} hk_{safe}({param_decl}) {{
    return {ret_v}; // Overridden by re-agent
}}"""

    install = f"""    // Hook {_safe_comment(t.class_name)}::{_safe_comment(t.target)} (return_override)
    auto klass_{idx} = Il2Cpp::Class::Find({class_literal});
    if (klass_{idx}) {{
        auto m = klass_{idx}->GetMethod({target_literal});
        if (m) {{
            orig_{safe} = (orig_{safe}_t)m->methodPointer;
            m->methodPointer = (void*)&hk_{safe};
        }}
    }}"""
    return block, install


def _gen_memory_patch(
    idx: int,
    t: Any,
    safe: str,
    header: str,
) -> tuple[str, str]:
    """Write directly to a field offset on the object instance."""
    if t.offset is None:
        return (
            f"""{header}
// Candidate has no verified field offset. Resolve the offset before enabling.""",
            f"    // Skipped unresolved memory patch {_safe_comment(t.class_name)}::{_safe_comment(t.target)}",
        )
    off = int(t.offset)
    if not 0 <= off <= 0x7FFF_FFFF:
        return (f"{header}\n// Invalid field offset; candidate disabled.", "    // Invalid offset")
    c_type = _safe_cpp_type(t.return_type)
    val = _safe_cpp_literal(t.return_value or "999999", c_type)
    class_literal = _cpp_string(t.class_name)

    # Find a suitable method to hook that will give us `self`
    block = f"""{header}
typedef void (*orig_{safe}_t)(void* self);
static orig_{safe}_t orig_{safe} = nullptr;

void hk_{safe}(void* self) {{
    if (self) {{
        *({c_type}*)((uintptr_t)self + 0x{off:X}) = {val};
    }}
    if (orig_{safe}) orig_{safe}(self);
}}"""

    install = f"""    // Patch {_safe_comment(t.class_name)}::{_safe_comment(t.target)} @ 0x{off:X}
    auto klass_{idx} = Il2Cpp::Class::Find({class_literal});
    if (klass_{idx}) {{
        auto m = klass_{idx}->GetMethod("Update");
        if (!m) m = klass_{idx}->GetMethod(".ctor");
        if (m) {{
            orig_{safe} = (orig_{safe}_t)m->methodPointer;
            m->methodPointer = (void*)&hk_{safe};
        }}
    }}"""
    return block, install


def _gen_multi_memory_patch(
    idx: int,
    class_name: str,
    patches: list[Any],
) -> tuple[str, str]:
    """Write directly to multiple field offsets on a single object instance."""
    patch_lines: list[str] = []
    comments: list[str] = []

    for p in patches:
        if p.offset is None:
            comments.append(
                f"// [{int(p.confidence)}% confidence] {_safe_comment(class_name)}::"
                f"{_safe_comment(p.target)} has no verified offset"
            )
            continue
        off = int(p.offset)
        if not 0 <= off <= 0x7FFF_FFFF:
            comments.append(f"// Invalid field offset for {_safe_comment(p.target)}")
            continue
        c_type = _safe_cpp_type(p.return_type)
        val = _safe_cpp_literal(p.return_value or "999999", c_type)
        patch_lines.append(f"        *({c_type}*)((uintptr_t)self + 0x{off:X}) = {val}; // {_safe_comment(p.target)}")
        comments.append(
            f"// [{int(p.confidence)}% confidence] {_safe_comment(class_name)}::{_safe_comment(p.target)} @ 0x{off:X}"
        )

    header = "\n".join(comments)
    safe = safe_identifier(f"MultiPatch_{class_name}")
    class_literal = _cpp_string(class_name)
    patches_code = "\n".join(patch_lines)
    if not patch_lines:
        return (
            f"{header}\n// No verified field offsets were available for this candidate group.",
            f"    // Skipped unresolved multi-patch for {_safe_comment(class_name)}",
        )

    block = f"""{header}
typedef void (*orig_{safe}_t)(void* self);
static orig_{safe}_t orig_{safe} = nullptr;

void hk_{safe}(void* self) {{
    if (self) {{
{patches_code}
    }}
    if (orig_{safe}) orig_{safe}(self);
}}"""

    install = f"""    // Multi-patch {_safe_comment(class_name)} ({len(patches)} fields)
    auto klass_{idx} = Il2Cpp::Class::Find({class_literal});
    if (klass_{idx}) {{
        auto m = klass_{idx}->GetMethod("Update");
        if (!m) m = klass_{idx}->GetMethod(".ctor");
        if (m) {{
            orig_{safe} = (orig_{safe}_t)m->methodPointer;
            m->methodPointer = (void*)&hk_{safe};
        }}
    }}"""
    return block, install


def _gen_skip_call(
    idx: int,
    t: Any,
    safe: str,
    header: str,
) -> tuple[str, str]:
    """Make a check/collision/death function return early."""
    ret_t = _safe_cpp_type(t.return_type or "bool", fallback="bool")
    if ret_t == "bool":
        ret_v = _safe_cpp_literal(t.return_value or "false", ret_t)
    elif ret_t == "void":
        ret_v = None
    else:
        ret_v = _safe_cpp_literal(t.return_value or "0", ret_t)
    class_literal = _cpp_string(t.class_name)
    target_literal = _cpp_string(t.target)

    if ret_v is not None:
        body = f"    return {ret_v}; // Skipped by re-agent"
        sig_ret = ret_t
    else:
        body = "    return; // Skipped by re-agent"
        sig_ret = "void"

    block = f"""{header}
typedef {sig_ret} (*orig_{safe}_t)(void* self);
static orig_{safe}_t orig_{safe} = nullptr;

{sig_ret} hk_{safe}(void* self) {{
{body}
}}"""

    install = f"""    // Skip {_safe_comment(t.class_name)}::{_safe_comment(t.target)}
    auto klass_{idx} = Il2Cpp::Class::Find({class_literal});
    if (klass_{idx}) {{
        auto m = klass_{idx}->GetMethod({target_literal});
        if (m) {{
            orig_{safe} = (orig_{safe}_t)m->methodPointer;
            m->methodPointer = (void*)&hk_{safe};
        }}
    }}"""
    return block, install


def _gen_esp_overlay(
    idx: int,
    t: Any,
    safe: str,
    header: str,
) -> tuple[str, str]:
    """Inject W2S projection for ESP / wallhack overlay."""
    class_literal = _cpp_string(t.class_name)
    target_literal = _cpp_string(t.target)
    block = f"""{header}
typedef void (*orig_{safe}_t)(void* self);
static orig_{safe}_t orig_{safe} = nullptr;

void hk_{safe}(void* self) {{
    if (self) {{
        // Read entity world position from Transform
        Vector3 worldPos;
        // worldPos = GetTransformPosition(self);
        // TODO: Read from {_safe_comment(t.class_name)}::{_safe_comment(t.target)}

        Matrix4x4 viewMatrix{{}}; // TODO: Read from Camera
        Vector2 screenPos;
        int screenW = 1920, screenH = 1080;

        if (WorldToScreen(worldPos, viewMatrix, screenW, screenH, screenPos)) {{
            // Draw ESP box at screenPos.x, screenPos.y
        }}
    }}
    if (orig_{safe}) orig_{safe}(self);
}}"""

    install = f"""    // ESP hook {_safe_comment(t.class_name)}::{_safe_comment(t.target)}
    auto klass_{idx} = Il2Cpp::Class::Find({class_literal});
    if (klass_{idx}) {{
        auto m = klass_{idx}->GetMethod({target_literal});
        if (m) {{
            orig_{safe} = (orig_{safe}_t)m->methodPointer;
            m->methodPointer = (void*)&hk_{safe};
        }}
    }}"""
    return block, install


def _gen_speed_modify(
    idx: int,
    t: Any,
    safe: str,
    header: str,
) -> tuple[str, str]:
    """Multiply speed/time/velocity values."""
    candidate_type = _safe_cpp_type(t.return_type or "float", fallback="float")
    ret_t = candidate_type if candidate_type in {"float", "double"} else "float"
    multiplier = _safe_cpp_literal(t.return_value or "3.0f", ret_t)
    class_literal = _cpp_string(t.class_name)
    target_literal = _cpp_string(t.target)

    block = f"""{header}
typedef {ret_t} (*orig_{safe}_t)(void* self);
static orig_{safe}_t orig_{safe} = nullptr;

{ret_t} hk_{safe}(void* self) {{
    {ret_t} original = orig_{safe} ? orig_{safe}(self) : 0;
    return original * {multiplier}; // Speed multiplied by re-agent
}}"""

    install = f"""    // Speed hook {_safe_comment(t.class_name)}::{_safe_comment(t.target)}
    auto klass_{idx} = Il2Cpp::Class::Find({class_literal});
    if (klass_{idx}) {{
        auto m = klass_{idx}->GetMethod({target_literal});
        if (m) {{
            orig_{safe} = (orig_{safe}_t)m->methodPointer;
            m->methodPointer = (void*)&hk_{safe};
        }}
    }}"""
    return block, install


def _gen_nop(
    idx: int,
    t: Any,
    safe: str,
    header: str,
) -> tuple[str, str]:
    """No-op a function entirely (anti-cheat, ads, validation)."""
    class_literal = _cpp_string(t.class_name)
    target_literal = _cpp_string(t.target)
    block = f"""{header}
typedef void (*orig_{safe}_t)(void* self);
static orig_{safe}_t orig_{safe} = nullptr;

void hk_{safe}(void* self) {{
    // Function disabled by re-agent (original call removed)
    return;
}}"""

    install = f"""    // NOP {_safe_comment(t.class_name)}::{_safe_comment(t.target)}
    auto klass_{idx} = Il2Cpp::Class::Find({class_literal});
    if (klass_{idx}) {{
        auto m = klass_{idx}->GetMethod({target_literal});
        if (m) {{
            orig_{safe} = (orig_{safe}_t)m->methodPointer;
            m->methodPointer = (void*)&hk_{safe};
        }}
    }}"""
    return block, install


def generate_dynamic_resolver_hook(
    symbol: str,
    class_name: str | None = None,
    return_type: str | None = None,
) -> str:
    cls = class_name or "TargetClass"
    sym_lower = symbol.lower()
    safe_symbol = safe_identifier(symbol)
    class_literal = _cpp_string(cls)
    symbol_literal = _cpp_string(symbol)

    if return_type:
        ret_t = _safe_cpp_type(return_type)
    elif sym_lower.startswith(("get", "get_")) and is_contextual_currency_match(symbol, cls, symbol):
        ret_t = "int32_t"
    elif sym_lower.startswith(("is", "is_", "check", "can")):
        ret_t = "bool"
    else:
        ret_t = "int32_t"

    if ret_t == "bool":
        mod_return = "return true;"
    elif ret_t == "int32_t":
        mod_return = "return 999999999; // Infinite value mod"
    else:
        mod_return = f"if (orig_{safe_symbol}) return orig_{safe_symbol}(self, type);\n    return 0;"

    return f"""// Auto-generated Dynamic BNM / Il2CppResolver candidate scaffold
#include "Il2CppResolver.h"

typedef {ret_t} (*{safe_symbol}_t)(void* self, int32_t type);
static {safe_symbol}_t orig_{safe_symbol} = nullptr;

{ret_t} hk_{safe_symbol}(void* self, int32_t type) {{
    // Custom mod logic (Overrides original return value)
    {mod_return}
}}

void install_dynamic_hook() {{
    Il2Cpp::Thread::Attach();
    auto klass = Il2Cpp::Class::Find({class_literal});
    if (klass) {{
        auto method = klass->GetMethod({symbol_literal});
        if (method) {{
            // Disabled until the real signature and ABI are verified:
            // orig_{safe_symbol} = ({safe_symbol}_t)method->methodPointer;
            // method->methodPointer = (void*)&hk_{safe_symbol};
        }}
    }}
}}
"""


def generate_ios_hook(address: str, symbol: str) -> str:
    safe_symbol = safe_identifier(symbol)
    safe_address = format_address(address)
    return f"""// Auto-generated MobileSubstrate / Dobby hook for iOS ARM64
#import <Foundation/Foundation.h>
#include <mach-o/dyld.h>

static uintptr_t get_target_offset() {{
    uintptr_t base = (uintptr_t)_dyld_get_image_header(0);
    return base + {safe_address}; // Target: {_safe_comment(symbol)}
}}

typedef void (*orig_func_t)(void* self);
static orig_func_t orig_{safe_symbol} = NULL;

void custom_{safe_symbol}(void* self) {{
    if (orig_{safe_symbol}) {{
        orig_{safe_symbol}(self);
    }}
}}
"""


def generate_android_hook(address: str, symbol: str) -> str:
    safe_address = format_address(address)
    symbol_literal = _cpp_string(symbol)
    return f"""// Auto-generated Android NDK Dobby inline hook
#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "ReAgentHook", __VA_ARGS__)

static uintptr_t get_lib_base(const char* libname) {{
    return 0;
}}

void setup_hook() {{
    uintptr_t target_addr = get_lib_base("libil2cpp.so") + {safe_address};
    LOGI("Candidate %s at %p (installation disabled pending ABI review)",
         {symbol_literal}, (void*)target_addr);
}}
"""


def generate_windows_hook(address: str, symbol: str) -> str:
    safe_symbol = safe_identifier(symbol)
    safe_address = format_address(address)
    return f"""// Auto-generated Windows MinHook / Detour C++ template
#include <windows.h>

// Candidate address: {safe_address} ({_safe_comment(symbol)})
typedef void (__fastcall* {safe_symbol}_t)(void* self);
static {safe_symbol}_t orig_{safe_symbol} = nullptr;

void __fastcall hk_{safe_symbol}(void* self) {{
    if (orig_{safe_symbol}) {{
        orig_{safe_symbol}(self);
    }}
}}
"""


def generate_rust_hook(address: str, symbol: str) -> str:
    safe_symbol = safe_identifier(symbol)
    safe_address = format_address(address)
    return f"""// Auto-generated cydia-substrate-rs / kittymemory-rs Rust hook template
use std::ffi::c_void;

extern "C" {{
    fn MSHookFunction(symbol: *mut c_void, replace: *mut c_void, result: *mut *mut c_void);
}}

pub unsafe fn install_rust_hook(target_ptr: *mut c_void) {{
    // Candidate address: {safe_address} ({_safe_comment(symbol)})
    let mut original: *mut c_void = std::ptr::null_mut();
    MSHookFunction(target_ptr, hk_{safe_symbol} as *mut c_void, &mut original);
}}

unsafe extern "C" fn hk_{safe_symbol}(_self: *mut c_void) {{
    // Custom Rust hook logic for {_safe_comment(symbol)}
}}
"""


def cmd_hook(args: argparse.Namespace) -> int:
    """Execute platform-specific hook generation command."""
    config_path = Path(args.config)
    config = load_config(config_path) if config_path.exists() else load_config(None)

    symbol = args.symbol or "Update"
    address = args.address or "0x1000"
    try:
        address = format_address(address)
    except ValueError as exc:
        print(f"[!] {exc}")
        return 2
    output_path = Path(args.output) if args.output else Path("output") / f"Hook_{safe_identifier(symbol)}.cpp"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    target_lang = getattr(args, "language", "cpp")
    is_dynamic = getattr(args, "dynamic", False)

    if is_dynamic:
        code = generate_dynamic_resolver_hook(symbol, args.class_name)
    elif target_lang == "rust":
        output_path = output_path.with_suffix(".rs")
        code = generate_rust_hook(address, symbol)
    else:
        platform_name = (getattr(args, "platform", None) or config.project_profile.name).lower()
        if "ios" in platform_name:
            code = generate_ios_hook(address, symbol)
        elif "android" in platform_name:
            code = generate_android_hook(address, symbol)
        else:
            code = generate_windows_hook(address, symbol)

    output_path.write_text(code, encoding="utf-8")
    print(f"[+] Generated Hook File: {output_path}")
    return 0
