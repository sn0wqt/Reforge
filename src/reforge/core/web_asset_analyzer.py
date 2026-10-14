"""Source-map-aware discovery for packaged WebView/Capacitor applications."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from reforge.config.domain_keywords import (
    CORE_CURRENCY_VALUE_KEYWORDS,
    SUBSCRIPTION_KEYWORDS,
    UI_PENALTY_HINTS,
    canonical_entity_token,
    identifier_tokens,
    is_balance_value_member,
    matches_identifier_keyword,
)
from reforge.core.candidates import rank_candidates
from reforge.llm.analyzed_target import AnalyzedTarget
from reforge.utils.archives import (
    ArchiveSafetyError,
    inspect_archive,
    read_member_bounded,
)
from reforge.utils.goal_parser import expand_goal_terms, extract_entity_keywords
from reforge.utils.mutation_intent import infer_primitive_replacement

MAX_SOURCE_MAP_BYTES: Final[int] = 64 * 1024 * 1024
MAX_TOTAL_SOURCE_MAP_BYTES: Final[int] = 192 * 1024 * 1024
MAX_SOURCE_RECORDS: Final[int] = 20_000
MAX_EVIDENCE_SOURCES: Final[int] = 40
JAVASCRIPT_MAX_SAFE_INTEGER: Final[int] = 9_007_199_254_740_991
_FEATURE_PATH = re.compile(r"(?:^|/)features/([^/]+)/", re.IGNORECASE)
_ENDPOINT_LITERAL = re.compile(r"['\"]((?!https?://)[A-Za-z0-9_@.-]+(?:/[A-Za-z0-9_@{}:?.=&-]+)+)['\"]")
_PROPERTY_PATH = re.compile(
    r"\b[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:(?:\?\.)|\.)[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:(?:(?:\?\.)|\.)[A-Za-z_$][A-Za-z0-9_$]*){0,3}"
)
_NESTED_OBJECT_PATH = re.compile(
    r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*\{\s*"
    r"([A-Za-z_$][A-Za-z0-9_$]*)\s*:",
    re.MULTILINE,
)


@dataclass(frozen=True)
class WebSourceRecord:
    source_name: str
    content: str
    map_member: str

    @property
    def feature(self) -> str | None:
        match = _FEATURE_PATH.search(self.source_name.replace("\\", "/"))
        return match.group(1).casefold() if match else None


def _load_source_records(target: Path) -> list[WebSourceRecord]:
    records: list[WebSourceRecord] = []
    seen: set[tuple[str, int]] = set()

    def consume(raw: bytes, member_name: str) -> None:
        if len(records) >= MAX_SOURCE_RECORDS:
            return
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            return
        if not isinstance(payload, dict):
            return
        sources = payload.get("sources")
        contents = payload.get("sourcesContent")
        if not isinstance(sources, list) or not isinstance(contents, list):
            return
        for source, content in zip(sources, contents, strict=False):
            if len(records) >= MAX_SOURCE_RECORDS:
                break
            if not isinstance(source, str) or not isinstance(content, str) or not content:
                continue
            key = (source.casefold(), hash(content))
            if key in seen:
                continue
            seen.add(key)
            records.append(WebSourceRecord(source, content, member_name))

    if target.is_file() and zipfile.is_zipfile(target):
        total = 0
        try:
            with zipfile.ZipFile(target, "r") as archive:
                for info in inspect_archive(archive):
                    normalized = info.filename.replace("\\", "/").casefold()
                    if not normalized.endswith(".js.map") or "/assets/" not in normalized:
                        continue
                    if info.file_size > MAX_SOURCE_MAP_BYTES:
                        continue
                    total += info.file_size
                    if total > MAX_TOTAL_SOURCE_MAP_BYTES:
                        break
                    consume(
                        read_member_bounded(
                            archive,
                            info,
                            max_bytes=MAX_SOURCE_MAP_BYTES,
                        ),
                        info.filename,
                    )
        except (ArchiveSafetyError, OSError, zipfile.BadZipFile):
            return records
    elif target.is_dir():
        total = 0
        for map_path in sorted(target.rglob("*.js.map")):
            try:
                size = map_path.stat().st_size
                if size > MAX_SOURCE_MAP_BYTES:
                    continue
                total += size
                if total > MAX_TOTAL_SOURCE_MAP_BYTES:
                    break
                consume(map_path.read_bytes(), str(map_path.relative_to(target)))
            except (OSError, ValueError):
                continue
    return records


def _term_in_text(term: str, value: str) -> bool:
    # Identifier tokenization is useful for paths/names but quadratic on a
    # multi-megabyte sourcesContent blob when repeated for every goal term.
    if len(value) <= 2_048 and matches_identifier_keyword(term, value):
        return True
    return bool(
        re.search(
            rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])",
            value,
            re.IGNORECASE,
        )
    )


def _record_score(
    record: WebSourceRecord,
    direct_terms: list[str],
    expanded_terms: list[str],
) -> int:
    score = 0
    for term in direct_terms:
        if _term_in_text(term, record.source_name):
            score += 160
        if _term_in_text(term, record.content):
            score += 40
    for term in expanded_terms:
        if term in direct_terms:
            continue
        if _term_in_text(term, record.source_name):
            score += 30
        elif _term_in_text(term, record.content):
            score += 8
    return score


def _normalize_property_path(value: str) -> str:
    return value.replace("?.", ".")


def _endpoint_for_path(
    json_path: str,
    feature: str | None,
    endpoints: list[tuple[str, str | None]],
) -> str | None:
    # Split camel/snake identifiers before comparing them with URL segments.
    # Treating ``sparkWallet`` as one opaque token made ``sparkWallet.balance``
    # incorrectly prefer an unrelated ``duo/balance`` endpoint over
    # ``spark/wallet``.
    path_tokens = [canonical_entity_token(token) for part in json_path.split(".") for token in identifier_tokens(part)]
    non_identity_tokens = {
        "amount",
        "available",
        "balance",
        "count",
        "current",
        "data",
        "insufficient",
        "new",
        "res",
        "response",
        "result",
        "total",
        "value",
    }
    identity_path_tokens = {token for token in path_tokens if token not in non_identity_tokens}
    ranked: list[tuple[int, int, str]] = []
    for endpoint, endpoint_feature in endpoints:
        endpoint_tokens = [
            canonical_entity_token(token) for token in re.findall(r"[A-Za-z0-9]+", endpoint) if token not in {"me"}
        ]
        identity_overlap = identity_path_tokens & set(endpoint_tokens)
        overlap = len(identity_overlap)
        root_match = int(bool(identity_overlap))
        feature_match = int(bool(feature and endpoint_feature == feature))
        ranked.append(
            (
                root_match * 60 + overlap * 12 + feature_match * 4,
                -len(endpoint),
                endpoint,
            )
        )
    if not ranked:
        return None
    best = max(ranked)
    return best[2] if best[0] >= 60 else None


def _replacement_for_path(goal: str, json_path: str) -> tuple[str | None, str]:
    final = json_path.rsplit(".", 1)[-1]
    final_tokens = identifier_tokens(final)
    boolean_shape = bool(
        final.casefold().startswith(("is", "has", "can", "enabled", "active")) or final_tokens & SUBSCRIPTION_KEYWORDS
    )
    type_name = "bool" if boolean_shape else "int64_t"
    replacement = infer_primitive_replacement(goal, type_name=type_name)
    if replacement is not None and type_name == "int64_t":
        try:
            numeric = int(replacement)
        except ValueError:
            pass
        else:
            # JSON numbers are JavaScript doubles. Values above MAX_SAFE_INTEGER
            # silently round and can break equality/cache logic in the client.
            replacement = str(max(-JAVASCRIPT_MAX_SAFE_INTEGER, min(JAVASCRIPT_MAX_SAFE_INTEGER, numeric)))
    return replacement, type_name


def _trim_expression_prefix(json_path: str, endpoint: str | None) -> str:
    """Drop local variable prefixes when an endpoint proves the response root."""
    if not endpoint:
        return json_path
    endpoint_tokens = {canonical_entity_token(token) for token in re.findall(r"[A-Za-z0-9]+", endpoint)}
    parts = json_path.split(".")
    for index, part in enumerate(parts):
        if canonical_entity_token(part) in endpoint_tokens:
            return ".".join(parts[index:])
    return json_path


def discover_web_asset_candidates(
    target: str | Path,
    goal: str,
    output_dir: Path,
) -> tuple[list[AnalyzedTarget], Path, int]:
    """Recover behavior candidates from original sources embedded in source maps."""
    records = _load_source_records(Path(target))
    direct_terms = extract_entity_keywords(goal)
    expanded_terms = list(dict.fromkeys(expand_goal_terms(goal)))
    scored = [
        (score, record)
        for record in records
        if "node_modules" not in record.source_name.replace("\\", "/").casefold()
        and (score := _record_score(record, direct_terms, expanded_terms)) > 0
    ]
    scored.sort(key=lambda item: (-item[0], item[1].source_name.casefold()))

    endpoints: list[tuple[str, str | None]] = []
    for record in records:
        for match in _ENDPOINT_LITERAL.finditer(record.content):
            endpoint = match.group(1)
            if endpoint.startswith((".", "@", "/")) or re.search(
                r"\.(?:js|ts|tsx|svg|png|json|mjs|css)$",
                endpoint,
                re.IGNORECASE,
            ):
                continue
            if endpoint.split("/", 1)[0].casefold() in {
                "application",
                "audio",
                "font",
                "image",
                "multipart",
                "text",
                "video",
            }:
                continue
            context = record.content[max(0, match.start() - 180) : min(len(record.content), match.end() + 180)]
            if not re.search(
                r"(?:\burl\b|Url\b|PrivateApi|\.(?:get|post|put|patch|delete)\s*\()",
                context,
            ):
                continue
            endpoints.append((endpoint, record.feature))
    endpoints = list(dict.fromkeys(endpoints))

    direct_features = {
        record.feature
        for record in records
        if record.feature is not None
        and any(canonical_entity_token(record.feature) == canonical_entity_token(term) for term in direct_terms)
    }
    value_terms = {
        canonical_entity_token(term)
        for term in (set(CORE_CURRENCY_VALUE_KEYWORDS) | {"active", "enabled", "ispremium", "premium", "value"})
    }
    direct_canonical = {canonical_entity_token(term) for term in direct_terms}
    expanded_canonical = {canonical_entity_token(term) for term in expanded_terms}
    subscription_goal = bool(
        (direct_canonical | expanded_canonical) & {canonical_entity_token(term) for term in SUBSCRIPTION_KEYWORDS}
    )
    if subscription_goal:
        value_terms = {
            "active",
            "enabled",
            "entitlement",
            "ispremium",
            "premium",
            "subscribed",
            "subscription",
        }
    else:
        value_terms -= {"active", "enabled", "ispremium", "premium"}
    targets: list[AnalyzedTarget] = []

    for score, record in scored:
        if score < 40:
            continue
        seen_paths: set[str] = set()
        path_occurrences = [
            (_normalize_property_path(match.group(0)), match.end()) for match in _PROPERTY_PATH.finditer(record.content)
        ]
        path_occurrences.extend(
            (f"{match.group(1)}.{match.group(2)}", -1) for match in _NESTED_OBJECT_PATH.finditer(record.content)
        )
        for json_path, expression_end in path_occurrences:
            if expression_end >= 0 and expression_end < len(record.content) and record.content[expression_end] == "(":
                continue
            if json_path in seen_paths:
                continue
            seen_paths.add(json_path)
            path_parts = json_path.split(".")
            if path_parts[0][:1].isupper() or path_parts[0].startswith(("use", "get")):
                continue
            tokens = {
                canonical_entity_token(token) for part in json_path.split(".") for token in identifier_tokens(part)
            }
            direct_path = bool(tokens & direct_canonical)
            expanded_path = bool(tokens & expanded_canonical)
            generic_value_path = bool(tokens & value_terms)
            feature_grounded = record.feature in direct_features
            final_member = json_path.rsplit(".", 1)[-1]
            if final_member.casefold() in {
                "current",
                "map",
                "find",
                "filter",
                "getquerykey",
                "key",
                "length",
                "options",
                "svg",
                "values",
                "tostring",
                "tolocalestring",
            }:
                continue
            if not subscription_goal and not is_balance_value_member(json_path):
                continue
            ui_tokens = tokens & UI_PENALTY_HINTS
            if ui_tokens and not ui_tokens & direct_canonical:
                continue
            if not direct_path and not expanded_path and not (feature_grounded and generic_value_path):
                continue
            endpoint = _endpoint_for_path(json_path, record.feature, endpoints)
            response_path = _trim_expression_prefix(json_path, endpoint)
            endpoint_direct = bool(endpoint and any(_term_in_text(term, endpoint) for term in direct_terms))
            if (
                not subscription_goal
                and not direct_path
                and generic_value_path
                and not feature_grounded
                and not endpoint_direct
            ):
                continue
            replacement, return_type = _replacement_for_path(goal, response_path)
            if replacement is None:
                continue
            response_final_tokens = identifier_tokens(response_path.rsplit(".", 1)[-1])
            state_value_path = bool(response_final_tokens & {"amount", "balance", "count", "current", "total", "value"})
            confidence = (
                98
                if endpoint and feature_grounded and state_value_path
                else 96
                if endpoint and feature_grounded and (direct_path or generic_value_path)
                else 92
                if endpoint and (direct_path or expanded_path)
                else 82
            )
            reason = (
                f"Original source recovered from {record.map_member} uses JSON path "
                f"{response_path!r} in goal-relevant source {record.source_name!r}"
            )
            if endpoint:
                reason += f"; packaged source also proves request endpoint {endpoint!r}"
            else:
                reason += "; no unique request endpoint was recovered"
            targets.append(
                AnalyzedTarget(
                    class_name=record.source_name,
                    target=response_path,
                    hook_type="web_response_patch",
                    return_value=replacement,
                    return_type=return_type,
                    confidence=confidence,
                    reason=reason,
                    source_file=record.source_name,
                    endpoint_pattern=endpoint,
                    json_path=response_path,
                    signature_verified=endpoint is not None,
                    address_verified=endpoint is not None,
                    implementation_ready=endpoint is not None,
                )
            )

    # Multiple UI consumers commonly read the same response field. Preserve
    # the strongest proof once instead of presenting the same executable rule
    # repeatedly under every component that consumes it.
    unique_targets: dict[tuple[str | None, str | None, str], AnalyzedTarget] = {}
    for target_candidate in targets:
        key = (
            target_candidate.endpoint_pattern,
            target_candidate.json_path,
            target_candidate.return_value or "",
        )
        existing = unique_targets.get(key)
        if existing is None or target_candidate.confidence > existing.confidence:
            unique_targets[key] = target_candidate
    ranked = list(rank_candidates(unique_targets.values()))
    evidence_path = output_dir / "Web_Source_Evidence.txt"
    lines = [
        "Packaged Web Source Evidence",
        "============================",
        f"Recovered original sources from source maps: {len(records)}",
        f"Goal-matched original sources: {len(scored)}",
        "Source maps are analysis evidence; deployed patches target the textual entry bundle.",
        "Client-side response mutation cannot bypass independent server-side authorization.",
        "",
    ]
    for index, (score, record) in enumerate(scored[:MAX_EVIDENCE_SOURCES], 1):
        matching_lines = [
            line.strip()
            for line in record.content.splitlines()
            if any(_term_in_text(term, line) for term in direct_terms + expanded_terms)
        ][:8]
        lines.append(f"{index}. score={score} source={record.source_name}")
        lines.append(f"   map={record.map_member}")
        for line in matching_lines:
            compact = " ".join(line.split())
            lines.append(f"   {compact[:500]}")
        lines.append("")
    evidence_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return ranked, evidence_path, len(records)


def _primitive_json_value(value: str | None) -> object | None:
    if value is None:
        return None
    text = value.strip()
    if text.casefold() == "true":
        return True
    if text.casefold() == "false":
        return False
    if re.fullmatch(r"[-+]?\d+", text):
        return int(text)
    if re.fullmatch(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)", text):
        return float(text)
    return None


def render_web_response_interceptor(
    candidates: list[AnalyzedTarget],
) -> str:
    """Render an early fetch-response transformer from verified web rules."""
    rules: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        if (
            candidate.hook_type != "web_response_patch"
            or not candidate.endpoint_pattern
            or not candidate.json_path
            or not candidate.implementation_ready
        ):
            continue
        replacement = _primitive_json_value(candidate.return_value)
        if replacement is None:
            continue
        key = (candidate.endpoint_pattern, candidate.json_path)
        if key in seen:
            continue
        seen.add(key)
        rules.append(
            {
                "endpoint": candidate.endpoint_pattern,
                "path": candidate.json_path.split("."),
                "value": replacement,
            }
        )
    encoded_rules = json.dumps(rules, ensure_ascii=True, separators=(",", ":"))
    return rf"""// reforge packaged-WebView response interceptor
// Client-side state only: independent server authorization remains authoritative.
(() => {{
  "use strict";
  if (globalThis.__reforgeWebPatchInstalled) return;
  globalThis.__reforgeWebPatchInstalled = true;
  const rules = {encoded_rules};
  const endpointMatches = (url, pattern) => {{
    const targetPath = `/${{String(pattern).replace(/^\/+|\/+$/g, "")}}`;
    try {{
      const parsed = new URL(String(url), globalThis.location?.href || "https://localhost/");
      const requestPath = parsed.pathname.replace(/\/+$/g, "");
      return requestPath === targetPath || requestPath.endsWith(targetPath);
    }} catch {{
      const requestPath = String(url).split(/[?#]/, 1)[0].replace(/\/+$/g, "");
      return requestPath === targetPath || requestPath.endsWith(targetPath);
    }}
  }};
  const applyPath = (payload, path, value) => {{
    let cursor = payload;
    for (let index = 0; index < path.length - 1; index += 1) {{
      if (cursor === null || typeof cursor !== "object" || !(path[index] in cursor)) return false;
      cursor = cursor[path[index]];
    }}
    if (cursor === null || typeof cursor !== "object") return false;
    const leaf = path[path.length - 1];
    if (!(leaf in cursor)) return false;
    cursor[leaf] = value;
    return true;
  }};
  const originalFetch = globalThis.fetch?.bind(globalThis);
  if (!originalFetch || rules.length === 0) return;
  globalThis.fetch = async (...args) => {{
    const response = await originalFetch(...args);
    const requestUrl = typeof args[0] === "string" || args[0] instanceof URL
      ? String(args[0])
      : String(args[0]?.url || response.url || "");
    const applicable = rules.filter(rule => endpointMatches(requestUrl, rule.endpoint));
    if (applicable.length === 0) return response;
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.toLowerCase().includes("json")) return response;
    try {{
      const payload = await response.clone().json();
      let changed = false;
      for (const rule of applicable) changed = applyPath(payload, rule.path, rule.value) || changed;
      if (!changed) return response;
      const headers = new Headers(response.headers);
      headers.delete("content-length");
      headers.delete("content-encoding");
      return new Response(JSON.stringify(payload), {{
        status: response.status,
        statusText: response.statusText,
        headers,
      }});
    }} catch (error) {{
      console.warn("[reforge] response patch skipped", error);
      return response;
    }}
  }};
  console.info("[reforge] installed packaged-WebView rules", rules);
}})();
"""


def patch_web_entry_bundle(
    bundle_path: Path,
    candidates: list[AnalyzedTarget],
    output_dir: Path,
) -> tuple[Path | None, list[str]]:
    """Prepend a verified response interceptor to a textual web entry module."""
    try:
        original = bundle_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, [f"Web entry bundle is not readable UTF-8 JavaScript: {exc}"]
    interceptor = render_web_response_interceptor(candidates)
    if "const rules = [];" in interceptor:
        return None, ["No verified endpoint/JSON-path response rule was available."]
    patched = interceptor + "\n" + original
    modified = output_dir / f"modified_{bundle_path.name}"
    modified.write_text(patched, encoding="utf-8")
    notes = [
        f"Prepended {len(candidates)} selected packaged-WebView candidate(s) to {bundle_path.name}.",
        "Patch mutates matching client-side JSON responses; server-side authorization is unchanged.",
    ]
    node = shutil.which("node")
    if node:
        try:
            subprocess.run(
                [node, "--input-type=module", "--check", "-"],
                input=patched,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            modified.unlink(missing_ok=True)
            detail = getattr(exc, "stderr", None) or str(exc)
            return None, [f"Patched web entry failed JavaScript syntax validation: {detail[-1000:]}"]
        notes.append("Patched JavaScript syntax validated as an ES module with Node.js.")
    else:
        notes.append("Node.js unavailable; patched JavaScript syntax was not runtime-validated.")
    return modified, notes
