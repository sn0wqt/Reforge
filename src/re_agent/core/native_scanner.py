"""Bounded native string/symbol evidence discovery for review-only candidates."""

from __future__ import annotations

import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from re_agent.config.domain_keywords import IGNORED_SDK_PREFIXES, matches_identifier_keyword
from re_agent.core.candidates import rank_candidates
from re_agent.core.engine_detector import iter_directory_files_bounded
from re_agent.llm.analyzed_target import AnalyzedTarget
from re_agent.utils.archives import ArchiveSafetyError, inspect_archive

MAX_NATIVE_SCAN_FILE_BYTES = 268_435_456
MAX_NATIVE_SCAN_TOTAL_BYTES = 536_870_912
MAX_NATIVE_ARCHIVE_MEMBERS = 256
MAX_NATIVE_RESULTS = 5_000
MAX_NATIVE_STRING_BYTES = 512
_NATIVE_SUFFIXES = {".dll", ".dylib", ".exe", ".so"}


class _BinaryReader(Protocol):
    def read(self, size: int = -1) -> bytes: ...


def _looks_like_native_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    lowered = normalized.casefold()
    if any(sdk in lowered for sdk in IGNORED_SDK_PREFIXES):
        return False
    # Preserve UnityFramework.framework for Unity IL2CPP IPA analysis
    if "frameworks/" in lowered and "unityframework.framework" not in lowered:
        return False
    suffix = Path(normalized).suffix.casefold()
    if suffix in _NATIVE_SUFFIXES:
        return True
    return (
        lowered.startswith("payload/")
        and ".app/" in lowered
        and suffix not in {".bundle", ".json", ".metallib", ".plist", ".strings"}
    )


def _matched_terms(value: str, terms: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(term for term in terms if matches_identifier_keyword(term, value))


def _candidate_from_string(
    *,
    module: str,
    value: str,
    offset: int,
    terms: tuple[str, ...],
) -> AnalyzedTarget | None:
    matches = _matched_terms(value, terms)
    if not matches:
        return None
    symbol_like = "::" in value or value.startswith(("$s", "_$s", "_Z", "Java_")) or "objc" in value.casefold()
    confidence = 35 if symbol_like else 30
    safe_value = value[:240]
    return AnalyzedTarget(
        class_name=Path(module).name or "NativeBinary",
        target=safe_value,
        hook_type="return_override",
        return_value=None,
        return_type="void",
        confidence=confidence,
        reason=(
            f"Native string/symbol evidence in {module} at file offset 0x{offset:X}; "
            f"matched {', '.join(matches)}. No code xref, callable address, or ABI is resolved."
        ),
    )


def _scan_stream(
    stream: _BinaryReader,
    *,
    module: str,
    terms: tuple[str, ...],
    max_bytes: int,
    remaining_results: int,
) -> list[AnalyzedTarget]:
    results: list[AnalyzedTarget] = []
    current = bytearray()
    current_start = 0
    absolute = 0

    def flush() -> None:
        nonlocal current
        if len(current) < 4 or len(results) >= remaining_results:
            current = bytearray()
            return
        value = current.decode("ascii", errors="ignore").strip()
        candidate = _candidate_from_string(
            module=module,
            value=value,
            offset=current_start,
            terms=terms,
        )
        if candidate is not None:
            results.append(candidate)
        current = bytearray()

    while absolute < max_bytes and len(results) < remaining_results:
        chunk = stream.read(min(1024 * 1024, max_bytes - absolute))
        if not chunk:
            break
        for byte in chunk:
            if 0x20 <= byte <= 0x7E:
                if not current:
                    current_start = absolute
                current.append(byte)
                if len(current) >= MAX_NATIVE_STRING_BYTES:
                    flush()
            else:
                flush()
            absolute += 1
            if absolute >= max_bytes or len(results) >= remaining_results:
                break
    flush()
    return results


def _normalized_terms(terms: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(term.strip().casefold() for term in terms if len(term.strip()) >= 3))


def scan_native_evidence(
    target: str | Path,
    terms: Iterable[str],
    *,
    max_results: int = MAX_NATIVE_RESULTS,
) -> tuple[AnalyzedTarget, ...]:
    """Scan bounded native members and retain only review-level evidence."""
    path = Path(target)
    normalized_terms = _normalized_terms(terms)
    if not path.exists() or not normalized_terms or max_results <= 0:
        return ()

    results: list[AnalyzedTarget] = []
    total_budget = MAX_NATIVE_SCAN_TOTAL_BYTES
    try:
        if path.is_file() and zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as archive:
                infos = [
                    info
                    for info in inspect_archive(archive)
                    if not info.is_dir() and _looks_like_native_member(info.filename)
                ][:MAX_NATIVE_ARCHIVE_MEMBERS]
                for info in infos:
                    if len(results) >= max_results or total_budget <= 0:
                        break
                    budget = min(
                        info.file_size,
                        MAX_NATIVE_SCAN_FILE_BYTES,
                        total_budget,
                    )
                    with archive.open(info, "r") as stream:
                        results.extend(
                            _scan_stream(
                                stream,
                                module=info.filename,
                                terms=normalized_terms,
                                max_bytes=budget,
                                remaining_results=max_results - len(results),
                            )
                        )
                    total_budget -= budget
        elif path.is_file():
            budget = min(path.stat().st_size, MAX_NATIVE_SCAN_FILE_BYTES)
            with path.open("rb") as stream:
                results.extend(
                    _scan_stream(
                        stream,
                        module=path.name,
                        terms=normalized_terms,
                        max_bytes=budget,
                        remaining_results=max_results,
                    )
                )
        elif path.is_dir():
            root = path.resolve()
            files_seen = 0
            for candidate_path in iter_directory_files_bounded(root):
                if files_seen >= MAX_NATIVE_ARCHIVE_MEMBERS:
                    break
                relative = candidate_path.relative_to(root).as_posix()
                if not _looks_like_native_member(relative):
                    continue
                try:
                    size = candidate_path.stat().st_size
                except OSError:
                    continue
                files_seen += 1
                budget = min(size, MAX_NATIVE_SCAN_FILE_BYTES, total_budget)
                if budget <= 0:
                    break
                with candidate_path.open("rb") as stream:
                    results.extend(
                        _scan_stream(
                            stream,
                            module=relative,
                            terms=normalized_terms,
                            max_bytes=budget,
                            remaining_results=max_results - len(results),
                        )
                    )
                total_budget -= budget
                if total_budget <= 0 or len(results) >= max_results:
                    break
    except (ArchiveSafetyError, OSError, zipfile.BadZipFile):
        return ()
    return rank_candidates(results)
