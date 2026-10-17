"""Cross-platform analysis, candidate generation, and optional packaging pipeline."""

from __future__ import annotations

import argparse
import bisect
import copy
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from reforge.config.domain_keywords import (
    MAXIMUM_TIER_ENTITY_KEYWORDS,
    NAMED_TIER_ENTITY_KEYWORDS,
    UI_PENALTY_HINTS,
    identifier_tokens,
    is_named_tier_match_contextual,
    matches_identifier_keyword,
)
from reforge.core.app_identity import default_pipeline_output_dir
from reforge.core.candidates import (
    print_candidate_summary,
    rank_candidates,
    render_candidate_summary,
)
from reforge.core.engine_detector import (
    ArchitectureDetection,
    detect_architecture_from_path,
    iter_directory_files_bounded,
)
from reforge.llm.analyzed_target import AnalyzedTarget
from reforge.packaging.frida_gadget import (
    GadgetEmbedding,
    GadgetPackagingError,
    embed_frida_gadget,
    verify_gadget_archive,
    write_gadget_deployment_notes,
)
from reforge.packaging.split_apks import (
    AndroidPackageSet,
    SplitApkError,
    copy_unique_apks,
    resolve_android_package_set,
    validate_installer_package,
    write_split_deployment_artifacts,
)
from reforge.utils.archives import (
    ArchiveSafetyError,
    extract_member_bounded,
    inspect_archive,
    normalized_member_name,
    read_member_bounded,
)
from reforge.utils.goal_parser import expand_goal_terms, extract_entity_keywords
from reforge.utils.mutation_intent import (
    infer_primitive_replacement,
    primitive_literal_kind,
    replacement_matches_literal,
)
from reforge.utils.toolchain import (
    resolve_apk_signer,
    resolve_apktool,
    resolve_frida_gadget_path,
)

MAX_TEXT_BUNDLE_BYTES = 268_435_456
_JS_PRIMITIVE_LITERAL = r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null"
_JS_PROPERTY_OR_IGNORED_TOKEN = re.compile(
    rf"""
    (?P<double_property>
        "(?P<double_name>[^"\\\r\n]{{1,512}})"
        \s*:\s*
        (?P<double_value>{_JS_PRIMITIVE_LITERAL})
        (?![A-Za-z0-9_$.-])
    )
    |
    (?P<single_property>
        '(?P<single_name>[^'\\\r\n]{{1,512}})'
        \s*:\s*
        (?P<single_value>{_JS_PRIMITIVE_LITERAL})
        (?![A-Za-z0-9_$.-])
    )
    |
    //[^\r\n]*(?:\r\n|\r|\n|\Z)
    |
    /\*[\s\S]*?(?:\*/|\Z)
    |
    "(?:\\[\s\S]|[^"\\])*(?:"|\Z)
    |
    '(?:\\[\s\S]|[^'\\])*(?:'|\Z)
    |
    `(?:\\[\s\S]|[^`\\])*(?:`|\Z)
    """,
    re.IGNORECASE | re.VERBOSE,
)


@dataclass(frozen=True)
class PipelineStage:
    """Truthful outcome for one pipeline stage."""

    name: str
    status: str
    detail: str
    artifacts: tuple[str, ...] = ()


def _write_pipeline_manifest(
    output_dir: Path,
    architecture: ArchitectureDetection,
    stages: list[PipelineStage],
    *,
    exit_code: int,
    candidate_count: int,
    modified_bundle: Path | None,
    package_artifact: str | None = None,
) -> Path:
    """Persist machine-readable capability state without claiming runtime proof."""
    manifest = output_dir / "pipeline_manifest.json"
    payload = {
        "schema_version": 1,
        "pathway": {
            "id": architecture.pathway_id,
            "name": architecture.pathway,
            "display_name": architecture.display_name,
            "platform": architecture.platform,
            "engine_type": architecture.engine_type,
            "detection_notes": list(architecture.detection_notes),
        },
        "exit_code": exit_code,
        "candidate_count": candidate_count,
        "stages": [asdict(stage) for stage in stages],
        "capabilities": {
            "analysis_complete": exit_code == 0 and candidate_count > 0,
            "static_patch_created": modified_bundle is not None,
            "runtime_hook_installed": False,
            "runtime_behavior_verified": False,
            "package_artifact": package_artifact,
        },
    }
    temporary = manifest.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, manifest)
    return manifest


def _read_text_bundle(path: Path) -> str | None:
    """Return textual JavaScript while refusing opaque Hermes bytecode."""
    try:
        if path.stat().st_size > MAX_TEXT_BUNDLE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if not data:
        return ""
    if b"\x00" in data[:4096]:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(character.isprintable() or character.isspace() for character in text)
    return text if printable / max(1, len(text)) >= 0.95 else None


def _extract_hermes_bundle(
    binary_path: Path,
    architecture: ArchitectureDetection,
    output_dir: Path,
) -> Path | None:
    member = architecture.bundle_member
    if not member:
        return None
    destination = output_dir / Path(member).name
    try:
        if binary_path.is_file() and zipfile.is_zipfile(binary_path):
            with zipfile.ZipFile(binary_path, "r") as archive:
                extract_member_bounded(archive, member, destination)
        elif binary_path.is_dir():
            source_path = (binary_path / Path(normalized_member_name(member))).resolve()
            source_path.relative_to(binary_path.resolve())
            shutil.copy2(source_path, destination)
        elif binary_path.is_file():
            shutil.copy2(binary_path, destination)
        else:
            return None
    except (ArchiveSafetyError, OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        print(f"[!] Hermes bundle extraction failed: {exc}")
        return None
    print(f"[+] Extracted {member} -> {destination}")
    return destination


def _decompile_hermes_bundle(bundle_path: Path, output_dir: Path) -> Path | None:
    """Decompile Hermes bytecode for analysis without attempting pseudo-JS recompilation."""
    textual_bundle = _read_text_bundle(bundle_path)
    decompiled = output_dir / "decompiled_bundle.js"
    if textual_bundle is not None:
        decompiled.write_text(textual_bundle, encoding="utf-8")
        print(f"[+] Bundle is textual JavaScript; analysis copy saved to {decompiled}")
        return decompiled

    command = [
        sys.executable,
        "-m",
        "hermes_dec.decompilation.hbc_decompiler",
        str(bundle_path),
        str(decompiled),
    ]
    try:
        subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        tail = "\n".join((exc.stderr or exc.stdout or "").splitlines()[-5:])
        print(f"[!] Hermes decompilation failed (exit {exc.returncode}).")
        if tail:
            print(tail)
        return None
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[!] Hermes decompiler unavailable: {exc}")
        return None
    if not decompiled.exists():
        print("[!] Hermes decompilation failed: Output file not created.")
        return None
        return None
    print(f"[+] Decompiled Hermes analysis view: {decompiled}")
    return decompiled


def _prepare_il2cpp_sidecars(
    binary_path: Path,
    metadata_path: Path | None,
    output_dir: Path,
    dumper_path: str,
) -> tuple[Path | None, str]:
    """Extract Unity inputs and run an explicitly selected IL2CPP dumper."""
    work_dir = output_dir / "il2cpp_dumper_output"
    work_dir.mkdir(parents=True, exist_ok=True)
    native_binary = binary_path
    global_metadata = metadata_path
    try:
        if binary_path.is_file() and zipfile.is_zipfile(binary_path):
            with zipfile.ZipFile(binary_path, "r") as archive:
                infos = inspect_archive(archive)
                binary_infos = [
                    info
                    for info in infos
                    if info.filename.casefold().endswith(("libil2cpp.so", "gameassembly.dll", "unityframework"))
                ]
                metadata_infos = [info for info in infos if info.filename.casefold().endswith("global-metadata.dat")]
                if not binary_infos or not metadata_infos:
                    return None, "Unity package lacks a binary/metadata member pair"
                binary_info = sorted(
                    binary_infos,
                    key=lambda info: (
                        "arm64-v8a" not in info.filename.casefold()
                        and "unityframework" not in info.filename.casefold(),
                        info.filename.casefold(),
                    ),
                )[0]
                metadata_info = sorted(
                    metadata_infos,
                    key=lambda info: info.filename.casefold(),
                )[0]
                native_binary = work_dir / Path(binary_info.filename).name
                global_metadata = work_dir / "global-metadata.dat"
                extract_member_bounded(archive, binary_info.filename, native_binary)
                extract_member_bounded(archive, metadata_info.filename, global_metadata)
        elif binary_path.is_dir():
            directory_files = list(iter_directory_files_bounded(binary_path))
            binaries = sorted(
                candidate
                for candidate in directory_files
                if candidate.name.casefold() in {"libil2cpp.so", "gameassembly.dll", "unityframework"}
            )
            metadata_files = sorted(
                candidate for candidate in directory_files if candidate.name.casefold() == "global-metadata.dat"
            )
            if not binaries or (global_metadata is None and not metadata_files):
                return None, "Unity directory lacks a binary/metadata pair"
            native_binary = binaries[0]
            global_metadata = global_metadata or metadata_files[0]
        if global_metadata is None or not global_metadata.is_file():
            return None, "A global-metadata.dat input is required for the Unity dumper"
    except (ArchiveSafetyError, OSError, zipfile.BadZipFile) as exc:
        return None, f"Could not prepare IL2CPP inputs: {exc}"

    from reforge.core.il2cpp_parser import run_il2cpp_dumper_cli

    result = run_il2cpp_dumper_cli(
        native_binary,
        global_metadata,
        work_dir,
        dumper_path=dumper_path,
    )
    if not result.get("success"):
        detail = result.get("error") or result.get("stderr") or "unknown dumper error"
        return None, f"Il2CppDumper failed: {str(detail)[-2000:]}"
    return work_dir, "IL2CPP metadata sidecars generated"


def _discover_hermes_candidates(
    source_text: str,
    goal: str,
    bundle_name: str,
    *,
    source_is_deployable: bool = True,
) -> list[AnalyzedTarget]:
    """Find JS property candidates and assign evidence-based confidence scores.

    A property in deployable textual JavaScript can be patched and validated.
    A similarly named property in decompiler pseudo-JavaScript is only an
    analysis lead: it has no stable source location or runtime binding.  The
    two evidence classes must never receive the same confidence.
    """
    direct_terms = extract_entity_keywords(goal)
    terms = expand_goal_terms(goal)
    properties = _scan_js_primitive_properties(source_text)
    occurrence_counts = Counter(name for name, _start, _end in properties)
    property_positions: dict[str, list[int]] = {}
    all_property_positions: list[int] = []
    for name, start, _end in properties:
        property_positions.setdefault(name, []).append(start)
        all_property_positions.append(start)
    all_property_positions.sort()
    targets: list[AnalyzedTarget] = []

    for property_name in sorted(occurrence_counts):
        direct_matching_terms = [term for term in direct_terms if matches_identifier_keyword(term, property_name)]
        matching_terms = [term for term in terms if matches_identifier_keyword(term, property_name)]
        if not matching_terms:
            continue
        tier_matches = [term for term in direct_matching_terms if term in NAMED_TIER_ENTITY_KEYWORDS]
        tier_contextual = not tier_matches or any(
            is_named_tier_match_contextual(term, "", property_name) for term in tier_matches
        )
        # A named tier such as ``maxPlan`` is meaningful, while bare ALL_CAPS
        # MAX constants are framework implementation details. Use identifier
        # shape rather than any application-specific class or product list.
        if (
            set(direct_matching_terms) <= MAXIMUM_TIER_ENTITY_KEYWORDS
            and direct_matching_terms
            and property_name == property_name.upper()
        ):
            continue
        if tier_matches and not tier_contextual:
            # A bare magnitude/product word is not a discovered behavior.
            # Keep ``subscriptionMax``/``ProEntitlement`` through the
            # contextual rule above, but discard layout limits and device
            # model suffixes entirely instead of padding the review list.
            continue
        current_literals = {source_text[start:end] for name, start, end in properties if name == property_name}
        replacements = {
            replacement
            for literal in current_literals
            for replacement in [infer_primitive_replacement(goal, current_literal=literal)]
            if replacement is not None and replacement_matches_literal(replacement, literal)
        }
        replacement = next(iter(replacements)) if len(replacements) == 1 else None
        replacement_kind = primitive_literal_kind(replacement) if replacement is not None else None
        if direct_matching_terms:
            exact = any(property_name.casefold() == term.casefold() for term in direct_matching_terms)
            confidence = (95 if exact else 90) if source_is_deployable else 74 if exact else 70
            relevance = "direct goal entity"
        else:
            exact = any(property_name.casefold() == term.casefold() for term in matching_terms)
            confidence = (78 if exact else 70) if source_is_deployable else 58 if exact else 54
            relevance = "domain expansion"

        candidate_tokens = identifier_tokens(property_name)
        direct_tokens = frozenset().union(*(identifier_tokens(term) for term in direct_terms))
        ui_tokens = candidate_tokens & UI_PENALTY_HINTS
        if "badge" in candidate_tokens and "badge" not in direct_tokens:
            ui_tokens = ui_tokens | {"badge"}
        framework_literal = "/" in property_name or property_name.casefold().startswith(
            ("application.", "application/")
        )
        penalty_reason = ""
        if framework_literal:
            confidence = min(confidence, 40)
            penalty_reason += "; framework/resource literal"
        elif ui_tokens:
            confidence = min(confidence, 74)
            penalty_reason += f"; UI/display token(s): {', '.join(sorted(ui_tokens))}"

        if not source_is_deployable:
            table_shaped_context = False
            module_export_context = False
            for position in property_positions[property_name]:
                left = bisect.bisect_left(all_property_positions, position - 1_500)
                right = bisect.bisect_right(all_property_positions, position + 1_500)
                if right - left >= 8:
                    table_shaped_context = True
                context = source_text[max(0, position - 3_000) : position + 3_000]
                if "__esModule" in context and ("defineProperty" in context or "exportAll" in context):
                    module_export_context = True
            if module_export_context:
                confidence = min(confidence, 48)
                penalty_reason += "; module/library export registry context"
            elif table_shaped_context:
                confidence = min(
                    confidence,
                    62 if direct_matching_terms else 55,
                )
                penalty_reason += "; aggregate/table-shaped context"

        occurrences = occurrence_counts[property_name]
        if occurrences != 1:
            confidence = min(confidence, 84 if source_is_deployable else 62)
        if replacement is None:
            confidence = min(confidence, 84)
            penalty_reason += "; requested mutation is ambiguous for the recovered primitive value"
        evidence_kind = (
            "deployable textual property"
            if source_is_deployable
            else "analysis-only decompiler property without a stable runtime binding"
        )
        targets.append(
            AnalyzedTarget(
                class_name="HermesBundle",
                target=property_name,
                hook_type="js_property_patch",
                return_value=replacement,
                return_type=(
                    "bool"
                    if replacement_kind == "bool"
                    else "double"
                    if replacement_kind == "float"
                    else "int64_t"
                    if replacement_kind == "integer"
                    else "unknown"
                ),
                confidence=confidence,
                reason=(
                    f"{evidence_kind.capitalize()} matched {', '.join(matching_terms)} as {relevance} "
                    f"in {bundle_name} ({occurrences} syntax-aware "
                    f"occurrence{'s' if occurrences != 1 else ''}{penalty_reason})"
                ),
            )
        )
    return list(rank_candidates(targets))


def _write_hermes_candidate_evidence(
    output_dir: Path,
    source_text: str,
    candidates: list[AnalyzedTarget],
    *,
    max_candidates: int = 50,
) -> Path:
    """Write bounded source locations for Hermes review candidates.

    The decompiled file may exceed 100 MiB and individual localization objects
    may occupy a single enormous line.  Snippets are therefore character-
    bounded and are evidence only, never presented as executable JavaScript.
    """
    evidence_path = output_dir / "Hermes_Candidate_Evidence.txt"
    lines = [
        "Hermes Candidate Evidence",
        "=========================",
        "Decompiler output is analysis-only and cannot be loaded as a Frida script or recompiled as-is.",
        "Locations below help identify app-owned state logic versus framework/library export tables.",
        "",
    ]
    for index, candidate in enumerate(candidates[:max_candidates], 1):
        property_name = candidate.target
        patterns = (f"'{property_name}'", f'"{property_name}"')
        positions = sorted(
            position for pattern in patterns for position in [source_text.find(pattern)] if position >= 0
        )
        lines.append(f"{index}. [{candidate.confidence}%] {property_name}")
        lines.append(f"   Evidence: {candidate.reason}")
        if not positions:
            lines.append("   Location: not recovered")
            lines.append("")
            continue
        position = positions[0]
        line_number = source_text.count("\n", 0, position) + 1
        function_window_start = max(0, position - 120_000)
        function_window = source_text[function_window_start:position]
        function_matches = list(re.finditer(r"_fun\d+", function_window))
        function_name = function_matches[-1].group(0) if function_matches else "unknown"
        snippet_start = max(0, position - 220)
        snippet_end = min(len(source_text), position + len(patterns[0]) + 280)
        snippet = " ".join(source_text[snippet_start:snippet_end].split())
        if len(snippet) > 520:
            snippet = snippet[:517] + "..."
        lines.append(f"   Location: line {line_number}, nearest decompiler function {function_name}")
        lines.append(f"   Context: {snippet}")
        lines.append("")
    evidence_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return evidence_path


def _scan_js_primitive_properties(source: str) -> list[tuple[str, int, int]]:
    """Return unescaped quoted object keys and primitive value spans.

    This intentionally recognizes a conservative JavaScript subset. It skips
    comments, quoted strings, and template literals, and refuses escaped keys
    or non-primitive values instead of risking a textual false positive. A
    compiled token lexer performs the scan in the regex engine so large Hermes
    decompiler outputs do not require a Python-level loop over every character.
    """
    properties: list[tuple[str, int, int]] = []
    for token in _JS_PROPERTY_OR_IGNORED_TOKEN.finditer(source):
        if token.lastgroup == "double_property":
            name_group = "double_name"
            value_group = "double_value"
        elif token.lastgroup == "single_property":
            name_group = "single_name"
            value_group = "single_value"
        else:
            continue
        properties.append(
            (
                token.group(name_group),
                token.start(value_group),
                token.end(value_group),
            )
        )
    return properties


def _patch_textual_bundle(
    bundle_path: Path,
    candidates: list[AnalyzedTarget],
    output_dir: Path,
    max_patches: int,
) -> tuple[Path | None, list[str]]:
    """Patch plain JavaScript properties only; never compile decompiler pseudo-JS."""
    original = _read_text_bundle(bundle_path)
    if original is None:
        return None, [
            "Bundle is Hermes bytecode or another opaque format.",
            "No static bundle was produced; use Hook_Frida.js or an app-specific Hermes compiler.",
        ]

    properties = _scan_js_primitive_properties(original)
    notes: list[str] = []
    replacements: list[tuple[int, int, str, AnalyzedTarget]] = []
    for target in candidates:
        if len(replacements) >= max(0, max_patches):
            break
        if target.return_value is None:
            notes.append(f"Skipped {target.target}: no unambiguous primitive mutation was inferred.")
            continue
        value = str(target.return_value)
        if not re.fullmatch(
            r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null",
            value,
            re.IGNORECASE,
        ):
            notes.append(f"Skipped {target.target}: replacement is not a safe primitive literal.")
            continue
        matches = [(start, end) for name, start, end in properties if name == target.target]
        if len(matches) != 1:
            notes.append(f"Skipped {target.target}: expected one syntax-aware property, found {len(matches)}.")
            continue
        start, end = matches[0]
        current_literal = original[start:end]
        if not replacement_matches_literal(value, current_literal):
            notes.append(
                f"Skipped {target.target}: replacement type does not match recovered literal {current_literal!r}."
            )
            continue
        replacements.append((start, end, value, target))

    patched = original
    for start, end, value, target in sorted(replacements, reverse=True):
        patched = patched[:start] + value + patched[end:]
        notes.append(f"Patched {target.target} -> {value} ({target.confidence}% candidate)")

    if not replacements:
        notes.append("No eligible plain-JavaScript property values matched.")
        return None, notes

    modified = output_dir / f"modified_{bundle_path.name}"
    modified.write_bytes(patched.encode("utf-8"))
    node = shutil.which("node")
    if node:
        try:
            subprocess.run(
                [node, "--check", "-"],
                input=patched,
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            modified.unlink(missing_ok=True)
            syntax_output = exc.stderr or exc.stdout or ""
            return None, [f"Patched JavaScript failed syntax validation: {syntax_output[-1000:]}"]
        except (OSError, subprocess.TimeoutExpired) as exc:
            modified.unlink(missing_ok=True)
            return None, [f"Could not validate patched JavaScript syntax: {exc}"]
        notes.append("JavaScript syntax validated with node --check.")
    else:
        notes.append("Node.js was unavailable; runtime syntax validation was not performed.")
    diff_path = output_dir / "bundle_patch.diff"
    diff = difflib.unified_diff(
        original.splitlines(),
        patched.splitlines(),
        fromfile=bundle_path.name,
        tofile=modified.name,
        lineterm="",
    )
    diff_path.write_text("\n".join(diff) + "\n", encoding="utf-8")
    notes.append(f"Modified textual bundle (runtime behavior unverified): {modified}")
    notes.append(f"Unified diff: {diff_path}")
    return modified, notes


def _write_ios_notes(
    output_dir: Path,
    architecture: ArchitectureDetection,
    modified_bundle: Path | None,
) -> Path:
    bundle_note = (
        f"A modified textual bundle is available at: {modified_bundle.name}"
        if modified_bundle
        else "No deployable bundle was created; use Hook_Frida.js for runtime injection."
    )
    notes = output_dir / "IOS_DEPLOYMENT_NOTES.txt"
    if sys.platform == "darwin":
        platform_signing_note = (
            "Apple IPA code signing on macOS requires a valid provisioning profile and certificate.\n"
            "Sign manually using codesign:\n"
            '  codesign --force --sign "<identity>" --entitlements Entitlements.plist Payload/<App>.app'
        )
    else:
        platform_signing_note = (
            f"Apple IPA code signing requires macOS codesign, a provisioning profile,\n"
            f"and an Apple Developer certificate. Reforge does not claim to sign\n"
            f"an IPA from non-macOS platforms ({sys.platform})."
        )
    notes.write_text(
        "\n".join(
            [
                f"Pathway: {architecture.display_name}",
                "",
                platform_signing_note,
                "",
                bundle_note,
                "Deploy Hook_Frida.js on a jailbroken or tethered test device using Frida.",
                "Review every candidate ABI/selector before enabling a secondary block.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return notes


def _run_tool(command: list[str], *, cwd: Path | None = None) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=600,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        return False, exc.stdout or ""
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return True, result.stdout


def _find_apktool() -> str | None:
    resolved = resolve_apktool()
    return str(resolved) if resolved is not None else None


def _local_frida_version() -> str | None:
    executable = shutil.which("frida")
    if not executable:
        return None
    ok, output = _run_tool([executable, "--version"])
    if not ok:
        return None
    version = output.strip().splitlines()[0] if output.strip() else ""
    return version or None


def _rewrite_apk_member(
    source_apk: Path,
    output_apk: Path,
    member: str,
    replacement: bytes,
) -> tuple[bool, str]:
    """Copy an APK while replacing exactly one validated archive member."""
    safe_member = normalized_member_name(member)
    replaced = 0
    try:
        with (
            zipfile.ZipFile(source_apk, "r") as source,
            zipfile.ZipFile(output_apk, "w", allowZip64=True) as destination,
        ):
            infos = inspect_archive(source)
            for info in infos:
                if info.filename == safe_member:
                    destination.writestr(info, replacement)
                    replaced += 1
                    continue
                if info.is_dir():
                    destination.writestr(info, b"")
                    continue
                with (
                    source.open(info, "r") as input_stream,
                    destination.open(
                        info,
                        "w",
                    ) as output_stream,
                ):
                    shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
    except (ArchiveSafetyError, OSError, ValueError, zipfile.BadZipFile) as exc:
        output_apk.unlink(missing_ok=True)
        return False, f"Direct APK asset replacement failed: {exc}"
    if replaced != 1:
        output_apk.unlink(missing_ok=True)
        return False, (f"Expected exactly one deployable member {safe_member!r}; found {replaced}.")
    return True, "APK asset member replaced without resource/manifest decoding."


def _repackage_android(
    binary_path: Path,
    output_dir: Path,
    architecture: ArchitectureDetection,
    generated_files: list[Path],
    modified_bundle: Path | None,
    *,
    gadget_path: Path | None = None,
    gadget_expected_sha256: str | None = None,
    gadget_on_load: str = "resume",
    gadget_port: int = 27042,
    gadget_version: str | None = None,
    split_apks: tuple[Path, ...] = (),
    installer_package: str | None = None,
) -> tuple[bool, str]:
    """Apply a verified APK modification, sign it, and verify exact bytes."""
    apktool = _find_apktool()
    java = shutil.which("java")
    signer = resolve_apk_signer()
    if not java:
        return False, "Java was not found on PATH."
    if signer is None:
        setup_script = (
            "scripts/setup_android_tools.ps1"
            if sys.platform == "win32"
            else "scripts/setup_android_tools.sh"
        )
        return (
            False,
            f"No trusted uber-apk-signer JAR was found. Run {setup_script} "
            "or set REFORGE_APK_SIGNER_JAR / RE_AGENT_APK_SIGNER_JAR.",
        )

    signed_apk = output_dir / "modded_app-aligned-signed.apk"
    with tempfile.TemporaryDirectory(
        prefix="reforge-apktool-",
        dir=str(output_dir),
    ) as temporary:
        temporary_path = Path(temporary)
        decoded = temporary_path / "decoded"
        unsigned_apk = temporary_path / "modded_app.apk"
        gadget_embedding: GadgetEmbedding | None = None
        direct_asset_replacement = (
            gadget_path is None and modified_bundle is not None and architecture.bundle_member is not None
        )
        if direct_asset_replacement:
            assert modified_bundle is not None
            assert architecture.bundle_member is not None
            ok, output = _rewrite_apk_member(
                binary_path,
                unsigned_apk,
                architecture.bundle_member,
                modified_bundle.read_bytes(),
            )
            if not ok:
                return False, output
        else:
            if not apktool:
                return (
                    False,
                    "apktool is required for manifest/native structural changes, but "
                    "was not found on PATH and neither REFORGE_APKTOOL nor RE_AGENT_APKTOOL is a valid launcher.",
                )
            ok, output = _run_tool([apktool, "d", "-f", str(binary_path), "-o", str(decoded)])
            if not ok:
                return False, f"apktool decode failed:\n{output[-2000:]}"

            artifact_dir = decoded / "assets" / "reforge"
            artifact_dir.mkdir(parents=True, exist_ok=True)
            for artifact in generated_files:
                if artifact.exists():
                    shutil.copy2(artifact, artifact_dir / artifact.name)

            if modified_bundle and architecture.bundle_member:
                safe_member = normalized_member_name(architecture.bundle_member)
                bundle_target = (decoded / Path(safe_member)).resolve()
                bundle_target.relative_to(decoded.resolve())
                bundle_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(modified_bundle, bundle_target)

        if gadget_path is not None:
            try:
                gadget_embedding = embed_frida_gadget(
                    decoded,
                    gadget_path,
                    expected_sha256=gadget_expected_sha256,
                    on_load=gadget_on_load,
                    port=gadget_port,
                    declared_version=gadget_version,
                )
            except GadgetPackagingError as exc:
                return False, f"Frida Gadget embedding failed: {exc}"
            assert apktool is not None
            ok, output = _run_tool([apktool, "b", str(decoded), "-o", str(unsigned_apk)])
            if not ok or not unsigned_apk.exists():
                return False, f"apktool build failed:\n{output[-2000:]}"

        signing_input = unsigned_apk
        signed_set_output: Path | None = None
        unsigned_set_inputs: tuple[Path, ...] = ()
        signing_command = [java, "-jar", str(signer.resolve()), "--apks"]
        if split_apks:
            unsigned_set = temporary_path / "unsigned-split-set"
            unsigned_set_inputs = copy_unique_apks(
                (unsigned_apk, *split_apks),
                unsigned_set,
            )
            base_input = unsigned_set_inputs[0]
            canonical_base = unsigned_set / "base.apk"
            if base_input != canonical_base:
                base_input.replace(canonical_base)
                unsigned_set_inputs = (canonical_base, *unsigned_set_inputs[1:])
            signed_set_output = temporary_path / "signed-split-set"
            signing_input = unsigned_set
            signing_command.extend(
                [
                    str(signing_input),
                    "--out",
                    str(signed_set_output),
                    "--allowResign",
                ]
            )
        else:
            signing_command.append(str(signing_input))
        ok, output = _run_tool(signing_command)
        if not ok:
            return False, f"APK signing failed:\n{output[-2000:]}"
        if split_apks:
            assert signed_set_output is not None
            signed_outputs = tuple(sorted(signed_set_output.glob("*.apk")))
            if len(signed_outputs) != len(unsigned_set_inputs):
                return (
                    False,
                    "Signer did not produce exactly one output for every APK in the split set "
                    f"({len(signed_outputs)} produced, {len(unsigned_set_inputs)} expected).",
                )
            base_matches = tuple(
                path
                for path in signed_outputs
                if path.stem.casefold() == "base" or path.stem.casefold().startswith("base-")
            )
            if len(base_matches) != 1:
                return False, "Signer output did not identify exactly one signed base APK."
            if modified_bundle and architecture.bundle_member:
                member = normalized_member_name(architecture.bundle_member)
                try:
                    with zipfile.ZipFile(base_matches[0], "r") as signed_archive:
                        infos = inspect_archive(signed_archive)
                        matching_infos = [info for info in infos if info.filename == member]
                        if len(matching_infos) != 1:
                            return (
                                False,
                                f"Signed base APK is missing the modified bundle member: {member}",
                            )
                        signed_bytes = read_member_bounded(
                            signed_archive,
                            matching_infos[0],
                            max_bytes=max(1, modified_bundle.stat().st_size),
                        )
                except (ArchiveSafetyError, OSError, zipfile.BadZipFile) as exc:
                    return False, f"Signed base APK validation failed: {exc}"
                if signed_bytes != modified_bundle.read_bytes():
                    return False, "Signed base APK bundle does not match the generated patch."
            ok, verification_output = _run_tool(
                [
                    java,
                    "-jar",
                    str(signer.resolve()),
                    "--apks",
                    str(signed_set_output),
                    "--onlyVerify",
                ]
            )
            if not ok:
                return (
                    False,
                    "Split APK signature/alignment verification failed:\n" + verification_output[-2000:],
                )
            final_set = output_dir / "modded_split_apks"
            suffix = 2
            while final_set.exists():
                final_set = output_dir / f"modded_split_apks_{suffix}"
                suffix += 1
            final_set.mkdir(parents=True)
            ordered_outputs = (
                base_matches[0],
                *(path for path in signed_outputs if path != base_matches[0]),
            )
            deployed: list[Path] = []
            for index, source in enumerate(ordered_outputs):
                name = "base.apk" if index == 0 else f"split-{index:03d}.apk"
                target = final_set / name
                shutil.copy2(source, target)
                deployed.append(target)
            notes, split_archive = write_split_deployment_artifacts(
                output_dir,
                tuple(deployed),
                base_apk=deployed[0],
                installer_package=installer_package,
            )
            if notes not in generated_files:
                generated_files.append(notes)
            return True, str(split_archive)
        matches = sorted(
            (
                candidate
                for candidate in temporary_path.glob("modded_app*.apk")
                if candidate != unsigned_apk and "sign" in candidate.name.casefold()
            ),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
        if not matches:
            return False, "Signer returned success but created no fresh signed APK."
        signer_output = matches[0]
        if not zipfile.is_zipfile(signer_output):
            return False, "Signer output is not a valid APK/ZIP archive."
        if modified_bundle and architecture.bundle_member:
            member = normalized_member_name(architecture.bundle_member)
            with zipfile.ZipFile(signer_output, "r") as signed_archive:
                infos = inspect_archive(signed_archive)
                matching_infos = [info for info in infos if info.filename == member]
                if len(matching_infos) != 1:
                    return False, f"Signed APK is missing the modified bundle member: {member}"
                signed_bytes = read_member_bounded(
                    signed_archive,
                    matching_infos[0],
                    max_bytes=max(1, modified_bundle.stat().st_size),
                )
            if signed_bytes != modified_bundle.read_bytes():
                return False, "Signed APK bundle content does not match the generated patch."
        if gadget_embedding is not None:
            try:
                verify_gadget_archive(signer_output, gadget_embedding)
            except (GadgetPackagingError, ArchiveSafetyError, zipfile.BadZipFile) as exc:
                return False, f"Signed APK Gadget verification failed: {exc}"
        ok, verification_output = _run_tool(
            [
                java,
                "-jar",
                str(signer.resolve()),
                "--apks",
                str(signer_output),
                "--onlyVerify",
            ]
        )
        if not ok:
            return (
                False,
                "APK signature/alignment verification failed:\n" + verification_output[-2000:],
            )
        shutil.copy2(signer_output, signed_apk)
        if gadget_embedding is not None:
            notes = write_gadget_deployment_notes(output_dir, gadget_embedding)
            if notes not in generated_files:
                generated_files.append(notes)

    return True, str(signed_apk)


def _prepare_windows_package(
    binary_path: Path,
    output_dir: Path,
    generated_files: list[Path],
) -> Path:
    package_dir = output_dir / "windows_candidate_package"
    package_dir.mkdir(parents=True, exist_ok=True)
    if binary_path.exists() and binary_path.is_file():
        shutil.copy2(binary_path, package_dir / binary_path.name)
    for generated_file in generated_files:
        if generated_file.exists():
            shutil.copy2(generated_file, package_dir / generated_file.name)
    (package_dir / "SIGNING_NOTES.txt").write_text(
        "Windows Authenticode signing requires your code-signing certificate.\n"
        "Review and compile Hook_Goal.cpp, inject it using your chosen framework,\n"
        "then sign the resulting executable with signtool on Windows or osslsigncode on Linux/macOS.\n",
        encoding="utf-8",
    )
    return package_dir


def _repack_choice(
    args: argparse.Namespace,
    architecture: ArchitectureDetection,
    *,
    android_repackage_available: bool = True,
    unavailable_reason: str | None = None,
) -> bool:
    if bool(getattr(args, "no_repack", False)):
        return False
    if not (architecture.is_android or architecture.is_windows):
        return False
    if architecture.is_android and not android_repackage_available:
        detail = unavailable_reason or "no deployable Android modification was produced"
        print(f"[*] Android repackaging unavailable: {detail}.")
        print("[+] Keeping analysis and review-hook artifacts only.")
        return False
    if bool(getattr(args, "repack_apk", False)):
        return True
    if bool(getattr(args, "embed_frida_gadget", False)):
        return True
    if not sys.stdin.isatty():
        print("[*] Non-interactive input detected; defaulting to hook/report output only.")
        return False

    if architecture.is_android:
        print("\nChoose Android output:")
        print("[1] Repackage and digitally sign modded_app-aligned-signed.apk")
        print("[2] Output analysis report and hook files only")
    else:
        print("\nChoose Windows output:")
        print("[1] Prepare a Windows mod package for user-managed Authenticode signing")
        print("[2] Output analysis report and hook files only")
    try:
        for _attempt in range(3):
            selection = input("Selection [1/2]: ").strip()
            if selection == "1":
                return True
            if selection == "2":
                return False
            print("[!] Enter exactly 1 or 2.")
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Repackaging skipped.")
        return False
    print("[!] Too many invalid selections; repackaging skipped.")
    return False


def _write_patch_summary(
    output_dir: Path,
    architecture: ArchitectureDetection,
    candidates: list[AnalyzedTarget],
    bundle_path: Path | None,
    modified_bundle: Path | None,
    patch_notes: list[str],
    goal_prompt: str = "",
) -> Path:
    summary = output_dir / "patch_diff_summary.txt"
    lines = [
        "Reforge Analysis and Patch Summary",
        "===================================",
        f"Pathway {architecture.pathway_id}: {architecture.display_name}",
        f"Platform: {architecture.platform}",
        f"Engine: {architecture.engine_type}",
        "Detection evidence: "
        + ("; ".join(architecture.detection_notes) if architecture.detection_notes else "(none recorded)"),
        f"Bundle member: {architecture.bundle_member or '(none)'}",
        f"Extracted bundle: {bundle_path or '(none)'}",
        f"Modified deployable bundle: {modified_bundle or '(none)'}",
        "Runtime hook installed: NO",
        "Runtime behavior verified: NO",
        "",
        render_candidate_summary(candidates, goal_prompt=goal_prompt),
        "",
        "PATCH NOTES",
    ]
    lines.extend(f"- {note}" for note in patch_notes or ["No static patch requested or produced."])
    summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def _cmd_pipeline_impl(args: argparse.Namespace) -> int:
    """Execute the eight-pathway analysis and artifact-generation pipeline."""
    binary_value = getattr(args, "binary", None)
    metadata_dir = getattr(args, "metadata_dir", None) or "."
    detection_target = binary_value or metadata_dir
    binary_path = Path(binary_value) if binary_value else None
    if binary_path is not None and not binary_path.exists():
        print(f"[!] Binary path does not exist: {binary_path}")
        return 2

    architecture = detect_architecture_from_path(
        detection_target,
        platform_hint=getattr(args, "platform", None),
    )
    split_package: AndroidPackageSet | None = getattr(args, "_android_package_set", None)
    try:
        installer_package = validate_installer_package(getattr(args, "installer_package", None))
    except SplitApkError as exc:
        print(f"[!] {exc}")
        return 2
    gadget_requested = bool(getattr(args, "embed_frida_gadget", False))
    gadget_cli_value = getattr(args, "frida_gadget_path", None)
    gadget_hash = getattr(args, "frida_gadget_sha256", None)
    gadget_cli_version = getattr(args, "frida_gadget_version", None)
    gadget_on_load = getattr(args, "frida_gadget_on_load", None)
    gadget_port = getattr(args, "frida_gadget_port", None)
    if not gadget_requested and any(
        (
            gadget_cli_value,
            gadget_hash,
            gadget_cli_version,
            gadget_on_load,
            gadget_port,
        )
    ):
        print("[!] Frida Gadget options require --embed-frida-gadget.")
        return 2
    gadget_value: str | None = None
    gadget_version: str | None = None
    if gadget_requested:
        if bool(getattr(args, "no_repack", False)):
            print("[!] --embed-frida-gadget cannot be combined with --no-repack.")
            return 2
        if split_package is not None:
            print(
                "[!] Frida Gadget embedding for split-required packages is not yet "
                "supported; use a static patch or a standalone APK."
            )
            return 2
        if binary_path is None or binary_path.suffix.casefold() != ".apk" or not architecture.is_android:
            print("[!] Frida Gadget embedding currently supports a single Android APK input only.")
            return 2
        local_frida = _local_frida_version()
        configured_version = (
            gadget_cli_version
            or os.environ.get("REFORGE_FRIDA_GADGET_VERSION")
            or os.environ.get("RE_AGENT_FRIDA_GADGET_VERSION")
        )
        resolved_gadget = resolve_frida_gadget_path(
            gadget_cli_value,
            version=str(configured_version or local_frida or "") or None,
        )
        if resolved_gadget is None:
            setup_script = (
                "scripts/setup_android_tools.ps1"
                if sys.platform == "win32"
                else "scripts/setup_android_tools.sh"
            )
            print(
                f"[!] No matching local Frida Gadget installation was found. "
                f"Run {setup_script} or pass --frida-gadget-path."
            )
            return 2
        gadget_input = resolved_gadget
        gadget_value = str(gadget_input)
        gadget_version = str(configured_version) if configured_version else None
        if (
            gadget_version is None
            and gadget_input.is_dir()
            and re.fullmatch(
                r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?",
                gadget_input.name,
            )
        ):
            gadget_version = gadget_input.name
        if gadget_version and not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", str(gadget_version)):
            print("[!] --frida-gadget-version must be a semantic version such as 17.15.2.")
            return 2
        if gadget_version and local_frida and local_frida != gadget_version:
            print(f"[!] Frida host/Gadget version mismatch: host={local_frida}, declared Gadget={gadget_version}.")
            return 2
        if not gadget_version:
            print(
                "[!] Gadget version was not declared. Embedding will record hashes, "
                "but host compatibility remains unverified."
            )
    configured_output_dir = getattr(args, "output_dir", None)
    output_dir = Path(configured_output_dir) if configured_output_dir else default_pipeline_output_dir(detection_target)
    output_dir.mkdir(parents=True, exist_ok=True)
    goal = getattr(args, "goal", None) or ""
    effective_metadata_dir = metadata_dir
    stages: list[PipelineStage] = [
        PipelineStage(
            "detection",
            "SUCCEEDED",
            f"Selected pathway {architecture.pathway_id}: {architecture.display_name}",
        )
    ]

    print("==========================================================")
    print("[*] Reforge Universal Analysis Pipeline")
    print("==========================================================")
    if not configured_output_dir:
        print(f"[+] Default output directory: {output_dir.resolve()}")
    if architecture.pathway_id:
        print(f"[+] Pathway {architecture.pathway_id}/8: {architecture.display_name} ({architecture.pathway})")
    else:
        print(f"[!] Pathway unresolved: {architecture.display_name} ({architecture.pathway})")
    if architecture.detected_components:
        print(f"[+] Detected components: {', '.join(architecture.detected_components)}")
    if split_package is not None:
        print(
            f"[+] Split package set: 1 base + {len(split_package.split_apks)} "
            f"split APK(s) from {split_package.source_kind} input"
        )
    for note in architecture.detection_notes:
        print(f"[+] Detection evidence: {note}")
    if len(architecture.detected_components) > 1:
        print(
            "[!] Hybrid package detected. The selected pathway is the primary "
            "route; all additional components remain explicit evidence."
        )

    if architecture.engine_type == "unity-il2cpp" and binary_path is not None:
        from reforge.core.il2cpp_parser import find_il2cpp_dumper

        dumper_value = find_il2cpp_dumper(getattr(args, "il2cpp_dumper", None))
        if not dumper_value:
            print(
                "[!] Warning: Unity IL2CPP target detected, but Il2CppDumper / il2dump was not found."
            )
            print(
                "[!] To enable automatic C# metadata dumping (dump.cs / script.json), "
                "install il2dump (cargo install il2dump) or pass --il2cpp-dumper <path>"
            )
        else:
            print(f"[+] Found Il2CppDumper executable: {dumper_value}")
            metadata_value = getattr(args, "metadata", None)
            metadata_path = Path(metadata_value) if metadata_value else None
            if metadata_path is not None and not metadata_path.is_file():
                print(f"[!] IL2CPP metadata path does not exist or is not a file: {metadata_path}")
                return 2
            prepared_dir, detail = _prepare_il2cpp_sidecars(
                binary_path,
                metadata_path,
                output_dir,
                str(dumper_value),
            )
            if prepared_dir:
                effective_metadata_dir = str(prepared_dir)
                print(f"[+] {detail}: {prepared_dir}")
            else:
                print(f"[!] IL2CPP metadata extraction failed: {detail}")
                return 2

    bundle_path: Path | None = None
    decompiled_path: Path | None = None
    hermes_targets: list[AnalyzedTarget] = []
    web_targets: list[AnalyzedTarget] = []
    web_evidence_path: Path | None = None
    source_text = ""
    if architecture.engine_type == "android-webview-js" and binary_path is not None:
        print("\n[*] Step 1/5: Preparing packaged WebView JavaScript analysis input...")
        bundle_path = _extract_hermes_bundle(binary_path, architecture, output_dir)
        if bundle_path is None or _read_text_bundle(bundle_path) is None:
            stages.append(
                PipelineStage(
                    "input_preparation",
                    "FAILED",
                    "Packaged WebView entry JavaScript could not be extracted as text.",
                )
            )
            _write_pipeline_manifest(
                output_dir,
                architecture,
                stages,
                exit_code=3,
                candidate_count=0,
                modified_bundle=None,
            )
            print("[!] INSUFFICIENT_EVIDENCE: packaged web entry extraction failed.")
            return 3
        from reforge.core.web_asset_analyzer import discover_web_asset_candidates

        print("[*] Recovering original application sources from packaged JavaScript source maps...")
        web_started = time.perf_counter()
        web_targets, web_evidence_path, recovered_source_count = discover_web_asset_candidates(
            binary_path, goal, output_dir
        )
        print(
            f"[+] Web source-map analysis completed in {time.perf_counter() - web_started:.1f}s; "
            f"recovered {recovered_source_count} original source file(s) and retained "
            f"{len(web_targets)} evidence-ranked candidate(s)."
        )
        stages.append(
            PipelineStage(
                "input_preparation",
                "SUCCEEDED",
                "Textual WebView entry and original source-map evidence recovered.",
                (str(bundle_path), str(web_evidence_path)),
            )
        )
    elif architecture.pathway_id in {1, 2} and binary_path is not None:
        print("\n[*] Step 1/5: Preparing React Native Hermes analysis input...")
        bundle_path = _extract_hermes_bundle(binary_path, architecture, output_dir)
        if bundle_path:
            decompiled_path = _decompile_hermes_bundle(bundle_path, output_dir)
        if bundle_path is None or decompiled_path is None:
            stages.append(
                PipelineStage(
                    "input_preparation",
                    "FAILED",
                    "Selected Hermes pathway requires successful bundle extraction and analysis.",
                )
            )
            summary = _write_patch_summary(
                output_dir,
                architecture,
                [],
                bundle_path,
                None,
                ["Hermes bundle extraction or decompilation failed."],
            )
            stages.append(
                PipelineStage(
                    "report",
                    "SUCCEEDED",
                    "Failure report written.",
                    (str(summary),),
                )
            )
            _write_pipeline_manifest(
                output_dir,
                architecture,
                stages,
                exit_code=3,
                candidate_count=0,
                modified_bundle=None,
            )
            print("[!] INSUFFICIENT_EVIDENCE: the selected Hermes pathway could not be analyzed.")
            return 3
        stages.append(
            PipelineStage(
                "input_preparation",
                "SUCCEEDED",
                "Platform-specific bundle extracted and converted to an analysis view.",
                (str(bundle_path), str(decompiled_path)),
            )
        )
        if decompiled_path and goal:
            analysis_size_mib = decompiled_path.stat().st_size / (1024 * 1024)
            print(
                f"[*] Scanning {analysis_size_mib:.1f} MiB Hermes analysis view "
                "for goal-matched primitive properties (local CPU)...",
                flush=True,
            )
            scan_started = time.perf_counter()
            source_text = decompiled_path.read_text(encoding="utf-8", errors="ignore")
            source_is_deployable = bool(bundle_path and _read_text_bundle(bundle_path) is not None)
            hermes_targets = _discover_hermes_candidates(
                source_text,
                goal,
                architecture.bundle_member or (bundle_path.name if bundle_path else decompiled_path.name),
                source_is_deployable=source_is_deployable,
            )
            print(
                f"[+] Hermes candidate scan completed in "
                f"{time.perf_counter() - scan_started:.1f}s; "
                f"retained {len(hermes_targets)} goal-matched candidate(s).",
                flush=True,
            )
    else:
        print("\n[*] Step 1/5: Preparing pathway-specific analysis inputs...")
        if architecture.package_type == "metadata-directory":
            print("[+] Using pre-extracted IL2CPP dump directory directly; no archive extraction needed.")
        else:
            print("[+] Extracting target binary and metadata components directly from application package archive...")
        stages.append(
            PipelineStage(
                "input_preparation",
                "SUCCEEDED",
                "Extracted binary and metadata components from application archive.",
            )
        )

    if architecture.pathway_id == 0:
        print(
            "[!] The metadata proves Unity IL2CPP but does not prove its target "
            "platform. Re-run with --platform ios, --platform android, or "
            "--platform windows."
        )
        stages.append(
            PipelineStage(
                "platform_resolution",
                "FAILED",
                "Metadata-only IL2CPP platform remained unresolved.",
            )
        )
        _write_pipeline_manifest(
            output_dir,
            architecture,
            stages,
            exit_code=2,
            candidate_count=0,
            modified_bundle=None,
        )
        return 2

    discovered_targets: list[tuple[str, str, int]] = []
    batch_targets: list[AnalyzedTarget] = []
    if architecture.engine_type == "android-webview-js":
        print("\n[*] Step 2/5: Resolving endpoint and client-state mutation evidence...")
        print(
            "[+] Skipping Android shell DEX ranking because deployed application "
            "behavior is provided by packaged web assets."
        )
        batch_exit = 0
    else:
        print("\n[*] Step 2/5: Loading metadata and discovering candidates...")
        from reforge.cli.cmd_batch import cmd_batch

        batch_args = argparse.Namespace(
            config=getattr(args, "config", None),
            auto_discover=True,
            goal=goal or None,
            symbol=None,
            string=None,
            class_name=None,
            binary=str(binary_path) if binary_path else None,
            metadata=getattr(args, "metadata", None),
            metadata_dir=effective_metadata_dir,
            platform=getattr(args, "platform", None),
            output_dir=str(output_dir),
            limit=50,
            _return_matches=True,
            _suppress_candidate_display=True,
        )
        batch_result = cmd_batch(batch_args)
        batch_exit = batch_result if isinstance(batch_result, int) else batch_result[0]
        if isinstance(batch_result, tuple):
            discovered_targets = batch_result[1]
            batch_targets = batch_result[2]
    if batch_exit != 0 and not hermes_targets:
        print(f"[!] Candidate discovery failed with exit code {batch_exit}.")
        stages.append(
            PipelineStage(
                "candidate_discovery",
                "FAILED",
                f"Discovery exited with code {batch_exit}.",
            )
        )
        _write_pipeline_manifest(
            output_dir,
            architecture,
            stages,
            exit_code=batch_exit,
            candidate_count=0,
            modified_bundle=None,
        )
        return batch_exit
    if batch_exit != 0:
        print("[*] Native/metadata discovery was insufficient; using Hermes evidence only.")

    # For Unity IL2CPP, avoid flooding raw DEX string fallbacks when no C# symbols are produced.
    if architecture.engine_type == "unity-il2cpp" and not any(
        t.signature_verified or t.method_rva is not None for t in batch_targets
    ):
        print(
            "[!] Unity IL2CPP metadata extraction was missing or yielded no C# symbols. "
            "Discarding ungrounded string fallbacks."
        )
        discovered_targets = []

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
    candidates = list(rank_candidates(web_targets + hermes_targets + batch_targets + raw_targets))
    if not candidates:
        print(
            "[!] INSUFFICIENT_EVIDENCE: no grounded candidates were discovered. "
            "No active hook or package will be generated."
        )
        summary = _write_patch_summary(
            output_dir,
            architecture,
            [],
            bundle_path,
            None,
            ["No grounded candidates were discovered."],
        )
        stages.extend(
            [
                PipelineStage(
                    "candidate_discovery",
                    "FAILED",
                    "No grounded candidate survived ranking.",
                ),
                PipelineStage(
                    "report",
                    "SUCCEEDED",
                    "Insufficient-evidence report written.",
                    (str(summary),),
                ),
            ]
        )
        _write_pipeline_manifest(
            output_dir,
            architecture,
            stages,
            exit_code=3,
            candidate_count=0,
            modified_bundle=None,
        )
        return 3
    print("\n[*] Step 3/5: Universal confidence-ranked candidate selection...")
    groups = print_candidate_summary(candidates, stream=sys.stdout, goal_prompt=goal)
    if groups.primary:
        stages.append(
            PipelineStage(
                "candidate_discovery",
                "SUCCEEDED",
                (
                    f"Retained {len(candidates)} evidence-ranked candidates, "
                    f"including {len(groups.primary)} high-confidence target(s)."
                ),
            )
        )
    else:
        stages.append(
            PipelineStage(
                "candidate_discovery",
                "PARTIAL",
                (
                    f"Retained {len(candidates)} review-only candidates, but none "
                    "met the high-confidence activation threshold."
                ),
            )
        )

    modified_bundle: Path | None = None
    patch_notes: list[str] = []
    if bool(getattr(args, "patch_bundle", False)):
        if bundle_path:
            if architecture.engine_type == "android-webview-js":
                from reforge.core.web_asset_analyzer import patch_web_entry_bundle

                modified_bundle, patch_notes = patch_web_entry_bundle(
                    bundle_path,
                    list(groups.primary),
                    output_dir,
                )
            else:
                modified_bundle, patch_notes = _patch_textual_bundle(
                    bundle_path,
                    list(groups.primary),
                    output_dir,
                    int(getattr(args, "max_patches", 5)),
                )
        else:
            patch_notes.append("Static patch requested, but this pathway has no JavaScript bundle.")
        stages.append(
            PipelineStage(
                "static_patch",
                "SUCCEEDED" if modified_bundle is not None else "FAILED",
                (
                    "A textual bundle patch was created and syntax-checked where Node.js was available."
                    if modified_bundle is not None
                    else "A static patch was requested but no unambiguous patch was produced."
                ),
                (str(modified_bundle),) if modified_bundle is not None else (),
            )
        )
    else:
        stages.append(
            PipelineStage(
                "static_patch",
                "SKIPPED",
                "Static bundle patching was not requested.",
            )
        )

    print("\n[*] Step 4/5: Generating modular hook artifacts...")
    from reforge.cli.cmd_hook import (
        generate_cpp_hook_for_pathway,
        generate_frida_java_script,
    )

    generated_files: list[Path] = []
    if web_evidence_path is not None:
        generated_files.append(web_evidence_path)
        print(f"[+] Generated {web_evidence_path}")
    if decompiled_path is not None and hermes_targets:
        hermes_evidence_path = _write_hermes_candidate_evidence(
            output_dir,
            source_text,
            list(rank_candidates(hermes_targets)),
        )
        generated_files.append(hermes_evidence_path)
        print(f"[+] Generated {hermes_evidence_path}")
    if architecture.engine_type == "android-webview-js":
        from reforge.core.web_asset_analyzer import render_web_response_interceptor

        web_hook_path = output_dir / "Hook_Web.js"
        web_hook_path.write_text(
            render_web_response_interceptor(list(groups.primary)),
            encoding="utf-8",
        )
        generated_files.append(web_hook_path)
        print(f"[+] Generated {web_hook_path}")
    elif architecture.uses_frida_javascript:
        frida_path = output_dir / "Hook_Frida.js"
        frida_path.write_text(
            generate_frida_java_script(
                goal,
                list(groups.primary),
                list(groups.secondary),
                pathway=architecture.pathway,
            ),
            encoding="utf-8",
        )
        generated_files.append(frida_path)
        print(f"[+] Generated {frida_path}")

    if architecture.uses_cpp_hook:
        cpp_path = output_dir / "Hook_Goal.cpp"
        cpp_path.write_text(
            generate_cpp_hook_for_pathway(
                goal,
                candidates,
                pathway=architecture.pathway,
            ),
            encoding="utf-8",
        )
        generated_files.append(cpp_path)
        print(f"[+] Generated {cpp_path}")

    summary_path = _write_patch_summary(
        output_dir,
        architecture,
        candidates,
        bundle_path,
        modified_bundle,
        patch_notes,
        goal_prompt=goal,
    )
    generated_files.append(summary_path)
    print(f"[+] Generated {summary_path}")

    if architecture.is_ios:
        ios_notes = _write_ios_notes(output_dir, architecture, modified_bundle)
        generated_files.append(ios_notes)
        print(f"[+] Generated {ios_notes}")
    stages.append(
        PipelineStage(
            "artifact_generation",
            "SUCCEEDED",
            ("Generated review artifacts. Hook files are not proof of installation or runtime behavior."),
            tuple(str(path) for path in generated_files),
        )
    )

    if bool(getattr(args, "patch_bundle", False)) and modified_bundle is None:
        manifest = _write_pipeline_manifest(
            output_dir,
            architecture,
            stages,
            exit_code=4,
            candidate_count=len(candidates),
            modified_bundle=None,
        )
        print(f"[!] Static patch request was not fulfilled; see {manifest}.")
        return 4

    if not groups.primary and not gadget_requested:
        print(
            "\n[!] INSUFFICIENT_EVIDENCE: no candidate met the >=85% "
            "high-confidence threshold. Generated hooks are review-only; "
            "no modification can be truthfully packaged."
        )
        stages.append(
            PipelineStage(
                "packaging",
                "SKIPPED",
                "No high-confidence deployable target was available.",
            )
        )
        manifest = _write_pipeline_manifest(
            output_dir,
            architecture,
            stages,
            exit_code=3,
            candidate_count=len(candidates),
            modified_bundle=modified_bundle,
        )
        print(f"[+] Review artifacts retained in: {output_dir.resolve()}")
        print(f"[+] Capability manifest: {manifest}")
        return 3
    if not groups.primary and gadget_requested:
        print(
            "\n[!] No candidate met the active threshold. Continuing only because "
            "explicit Gadget embedding was requested; generated hooks remain review-only."
        )

    print("\n[*] Step 5/5: Packaging decision...")
    can_attempt_textual_patch = (
        architecture.is_android
        and bundle_path is not None
        and _read_text_bundle(bundle_path) is not None
        and bool(groups.primary)
    )
    android_repackage_available = gadget_requested or modified_bundle is not None or can_attempt_textual_patch
    if architecture.is_android and not android_repackage_available:
        if bundle_path is not None and _read_text_bundle(bundle_path) is None:
            unavailable_reason = (
                "the Hermes bundle is compiled bytecode and Frida Gadget embedding was not requested "
                "(use --embed-frida-gadget for a signed instrumentation APK)"
            )
        else:
            unavailable_reason = "no verified static or runtime modification was produced"
    else:
        unavailable_reason = None
    should_repack = _repack_choice(
        args,
        architecture,
        android_repackage_available=android_repackage_available,
        unavailable_reason=unavailable_reason,
    )
    package_artifact: str | None = None
    if should_repack and architecture.is_android:
        if binary_path is None or binary_path.suffix.lower() != ".apk":
            print("[!] Android repackaging requires an APK input.")
            stages.append(PipelineStage("packaging", "FAILED", "Android packaging requires an APK input."))
            _write_pipeline_manifest(
                output_dir,
                architecture,
                stages,
                exit_code=2,
                candidate_count=len(candidates),
                modified_bundle=modified_bundle,
            )
            return 2
        if modified_bundle is None and can_attempt_textual_patch and not gadget_requested:
            assert bundle_path is not None
            if architecture.engine_type == "android-webview-js":
                from reforge.core.web_asset_analyzer import patch_web_entry_bundle

                modified_bundle, patch_notes = patch_web_entry_bundle(
                    bundle_path,
                    list(groups.primary),
                    output_dir,
                )
            else:
                modified_bundle, patch_notes = _patch_textual_bundle(
                    bundle_path,
                    list(groups.primary),
                    output_dir,
                    int(getattr(args, "max_patches", 5)),
                )
            replacement_stage = PipelineStage(
                "static_patch",
                "SUCCEEDED" if modified_bundle is not None else "FAILED",
                (
                    "Interactive repackaging selected; a textual bundle patch "
                    "was created and syntax-checked where Node.js was available."
                    if modified_bundle is not None
                    else "Interactive repackaging selected, but no unambiguous patch was produced."
                ),
                (str(modified_bundle),) if modified_bundle is not None else (),
            )
            for stage_index, stage in enumerate(stages):
                if stage.name == "static_patch":
                    stages[stage_index] = replacement_stage
                    break
            _write_patch_summary(
                output_dir,
                architecture,
                candidates,
                bundle_path,
                modified_bundle,
                patch_notes,
                goal_prompt=goal,
            )
            if modified_bundle is None:
                print("[!] Repackaging was selected, but no verified static bundle modification could be produced.")
                manifest = _write_pipeline_manifest(
                    output_dir,
                    architecture,
                    stages,
                    exit_code=4,
                    candidate_count=len(candidates),
                    modified_bundle=None,
                )
                print(f"[+] Capability manifest: {manifest}")
                return 4
            print(f"[+] Created deployable bundle patch: {modified_bundle}")
        if modified_bundle is None and not gadget_requested:
            print(
                "[!] Refusing to label an APK as modded: no verified static bundle "
                "patch or installed runtime injection strategy is available."
            )
            stages.append(
                PipelineStage(
                    "packaging",
                    "FAILED",
                    "No static patch or installed runtime injection was available.",
                )
            )
            _write_pipeline_manifest(
                output_dir,
                architecture,
                stages,
                exit_code=2,
                candidate_count=len(candidates),
                modified_bundle=modified_bundle,
            )
            return 2
        if gadget_requested:
            assert gadget_value is not None
            ok, result = _repackage_android(
                binary_path,
                output_dir,
                architecture,
                generated_files,
                modified_bundle,
                gadget_path=Path(gadget_value).expanduser(),
                gadget_expected_sha256=str(gadget_hash) if gadget_hash else None,
                gadget_on_load=str(gadget_on_load or "resume"),
                gadget_port=int(gadget_port or 27042),
                gadget_version=str(gadget_version) if gadget_version else None,
                split_apks=split_package.split_apks if split_package else (),
                installer_package=installer_package,
            )
        else:
            ok, result = _repackage_android(
                binary_path,
                output_dir,
                architecture,
                generated_files,
                modified_bundle,
                split_apks=split_package.split_apks if split_package else (),
                installer_package=installer_package,
            )
        if not ok:
            print(f"[!] Repackaging failed: {result}")
            stages.append(PipelineStage("packaging", "FAILED", result))
            _write_pipeline_manifest(
                output_dir,
                architecture,
                stages,
                exit_code=1,
                candidate_count=len(candidates),
                modified_bundle=modified_bundle,
            )
            return 1
        package_artifact = result
        stages.append(
            PipelineStage(
                "packaging",
                "SUCCEEDED",
                (
                    "APK rebuilt, signed, and Frida Gadget payload/loader verified."
                    if gadget_requested
                    else "APK rebuilt, signed, and its modified bundle bytes verified."
                ),
                (result,),
            )
        )
        if split_package is not None:
            print(f"[+] Rebuilt and consistently signed split-APK set: {result}")
        else:
            print(f"[+] Rebuilt and signed APK: {result}")
    elif should_repack and architecture.is_windows:
        if binary_path is None:
            print("[!] Windows packaging requires a binary input.")
            return 2
        package_dir = _prepare_windows_package(binary_path, output_dir, generated_files)
        package_artifact = str(package_dir)
        stages.append(
            PipelineStage(
                "packaging",
                "SUCCEEDED",
                "Prepared an unsigned review package; no injection or Authenticode signing is claimed.",
                (str(package_dir),),
            )
        )
        print(f"[+] Prepared Windows package: {package_dir}")
    elif bool(getattr(args, "repack_apk", False)) and architecture.is_ios:
        if sys.platform == "darwin":
            print(
                "[!] iOS IPA automated repackaging requires valid Apple Developer certificates; "
                "see IOS_DEPLOYMENT_NOTES.txt for macOS codesign instructions."
            )
        else:
            print(f"[!] iOS IPA signing is unavailable on {sys.platform}; see IOS_DEPLOYMENT_NOTES.txt.")
        stages.append(
            PipelineStage(
                "packaging",
                "FAILED",
                "iOS signing requires Apple Developer certificates; see deployment notes."
                if sys.platform == "darwin"
                else "iOS signing is unavailable on this platform.",
            )
        )
        _write_pipeline_manifest(
            output_dir,
            architecture,
            stages,
            exit_code=2,
            candidate_count=len(candidates),
            modified_bundle=modified_bundle,
        )
        return 2
    else:
        stages.append(
            PipelineStage(
                "packaging",
                "SKIPPED",
                "Report/hook output only was selected.",
            )
        )
        print("[+] Analysis report and hook files retained; repackaging skipped.")

    manifest = _write_pipeline_manifest(
        output_dir,
        architecture,
        stages,
        exit_code=0,
        candidate_count=len(candidates),
        modified_bundle=modified_bundle,
        package_artifact=package_artifact,
    )

    print("\n==========================================================")
    print("[+] Pipeline completed with evidence-ranked candidate artifacts.")
    print(f"[+] Output directory: {output_dir.resolve()}")
    print(f"[+] Capability manifest: {manifest}")
    print("==========================================================")
    return 0


def cmd_pipeline(args: argparse.Namespace) -> int:
    """Normalize split-package inputs before running the regular pipeline."""

    binary_value = getattr(args, "binary", None)
    if not binary_value:
        return _cmd_pipeline_impl(args)
    source = Path(binary_value)
    if not source.exists() or (source.is_file() and source.suffix.casefold() == ".apk"):
        return _cmd_pipeline_impl(args)

    with tempfile.TemporaryDirectory(prefix="reforge-split-input-") as temporary:
        try:
            package_set = resolve_android_package_set(
                source,
                Path(temporary) / "apks",
            )
        except SplitApkError as exc:
            print(f"[!] Split-APK input rejected: {exc}")
            return 2
        if package_set is None:
            return _cmd_pipeline_impl(args)
        normalized_args = copy.copy(args)
        normalized_args.binary = str(package_set.base_apk)
        normalized_args._android_package_set = package_set
        return _cmd_pipeline_impl(normalized_args)
