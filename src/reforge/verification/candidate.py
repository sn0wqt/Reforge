"""Candidate overlays and configurable build/test validation gates."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from reforge.config.schema import ValidationConfig
from reforge.core.models import FunctionTarget, SourceMatch, ValidationVerdict, Verdict
from reforge.utils.paths import safe_filename
from reforge.utils.process import run_process

_PROJECT_COPY_IGNORE = shutil.ignore_patterns(
    ".cache",
    ".env",
    ".env.*",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "credentials",
    "decompiled_bundle.js",
    "dist",
    "output",
    "reports",
    "scratch",
    "*.apk",
    "*.egg",
    "*.ipa",
    "*.jar",
    "*.json.bak",
    "*.pyc",
    "*.zip",
)


def validation_preflight_error(config: ValidationConfig) -> str | None:
    """Return why the configured acceptance gate can never produce PASS."""
    if not config.enabled or not config.require_verified:
        return None
    commands: list[str | list[str]] = (
        list(config.build_commands) + list(config.test_commands) + list(config.runtime_commands)
    )
    has_gates = bool(commands or getattr(config, "differential_cases_file", None))
    if not has_gates:
        return "validation.require_verified is true but no build/test/runtime commands are configured"
    if config.require_build and not config.build_commands:
        return "validation.require_build is true but build_commands is empty"
    if config.require_tests and not config.test_commands:
        return "validation.require_tests is true but test_commands is empty"
    if config.require_runtime and not config.runtime_commands:
        return "validation.require_runtime is true but runtime_commands is empty"
    if not config.allow_host_commands and any(isinstance(c, str) for c in commands):
        return "verified validation requires validation.allow_host_commands=true in a trusted execution environment"
    if not config.trust_configured_commands:
        return "verified validation requires validation.trust_configured_commands=true after reviewing the commands"
    return None


def extract_candidate_body(code: str) -> str:
    """Extract exactly one top-level C++ braced body.

    Braces inside comments and quoted literals are ignored. Multiple top-level
    definitions are rejected instead of being spliced together into one source
    function.
    """
    spans: list[tuple[int, int]] = []
    depth = 0
    start: int | None = None
    index = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False

    while index < len(code):
        character = code[index]
        following = code[index + 1] if index + 1 < len(code) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if character == "*" and following == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character == "/" and following == "/":
            line_comment = True
            index += 2
            continue
        if character == "/" and following == "*":
            block_comment = True
            index += 2
            continue
        if character in {'"', "'"}:
            quote = character
            index += 1
            continue
        if character == "{":
            if depth == 0:
                start = index
            depth += 1
        elif character == "}":
            if depth == 0:
                raise ValueError("Candidate contains an unmatched closing brace")
            depth -= 1
            if depth == 0 and start is not None:
                spans.append((start, index + 1))
                start = None
        index += 1

    if depth != 0 or quote is not None or block_comment:
        raise ValueError("Candidate contains an unterminated body, comment, or string")
    if not spans:
        return code.strip()
    if len(spans) != 1:
        raise ValueError(f"Candidate must contain exactly one top-level braced definition; found {len(spans)}")
    body_start, body_end = spans[0]
    return code[body_start:body_end].strip()


def create_candidate_overlay(
    target: FunctionTarget,
    code: str,
    source: SourceMatch | None,
    source_root: Path,
    report_dir: Path,
    project_root: Path | None = None,
    copy_project: bool = False,
) -> Path:
    """Write a source overlay with the original function body replaced."""
    safe_address = _sanitize_path_component(target.address)
    overlay_root: Path | None = None
    try:
        if copy_project:
            if project_root is None:
                raise ValueError("project_root is required when copy_project is enabled")
            overlay_root = Path(tempfile.mkdtemp(prefix=f"reforge-{safe_address}-"))
            shutil.copytree(
                project_root,
                overlay_root,
                dirs_exist_ok=True,
                symlinks=True,
                ignore=_PROJECT_COPY_IGNORE,
            )
            _remap_links(overlay_root, project_root)
        else:
            overlay_root = report_dir / "candidates" / safe_address
        overlay_root.mkdir(parents=True, exist_ok=True)
        (overlay_root / ".reforge-overlay").write_text("schema_version=1\n", encoding="utf-8")
        if source is None:
            safe_class_name = _sanitize_path_component(target.class_name)
            safe_function_name = _sanitize_path_component(target.function_name)
            candidate_file = overlay_root / f"{safe_class_name}_{safe_function_name}.cpp"
            candidate_file.parent.mkdir(parents=True, exist_ok=True)
            candidate_file.write_text(code.rstrip() + "\n", encoding="utf-8")
            return candidate_file

        original_path = Path(source.path)
        relative_root = project_root if copy_project and project_root is not None else source_root
        try:
            relative = original_path.resolve().relative_to(relative_root.resolve())
        except ValueError:
            if copy_project:
                raise ValueError(
                    f"Source file {original_path} is outside validation.project_root {relative_root}"
                ) from None
            relative = Path(original_path.name)
        candidate_file = overlay_root / relative
        candidate_file.parent.mkdir(parents=True, exist_ok=True)

        original = original_path.read_text(encoding="utf-8", errors="ignore")
        if not 0 <= source.body_start < source.body_end <= len(original):
            raise ValueError(f"Source body offsets unavailable for {source.path}")
        body = extract_candidate_body(code)
        overlaid = original[: source.body_start] + body + original[source.body_end :]
        candidate_file.write_text(overlaid, encoding="utf-8")
        return candidate_file
    except Exception:
        if copy_project and overlay_root is not None:
            shutil.rmtree(overlay_root, ignore_errors=True)
        raise


def validate_candidate(
    config: ValidationConfig,
    candidate_file: Path,
    source_file: str | None,
) -> ValidationVerdict:
    """Run configured build and test commands against the candidate overlay."""
    commands: list[tuple[str, str | list[str]]] = [("build", command) for command in config.build_commands]
    commands.extend(("test", command) for command in config.test_commands)
    commands.extend(("runtime", command) for command in config.runtime_commands)
    if not config.enabled:
        return ValidationVerdict(
            verdict=Verdict.UNKNOWN,
            summary="Candidate validation disabled",
            overlay_file=str(candidate_file),
        )
    if config.require_build and not config.build_commands:
        return _failed("Build validation is required but no build_commands are configured", candidate_file)
    if config.require_tests and not config.test_commands:
        return _failed("Test validation is required but no test_commands are configured", candidate_file)
    if config.require_runtime and not config.runtime_commands:
        return _failed("Runtime validation is required but no runtime_commands are configured", candidate_file)
    if (
        source_file is None
        and config.copy_project
        and commands
        and not any(
            "{candidate_file}" in part
            for _, command in commands
            for part in ([command] if isinstance(command, str) else command)
        )
    ):
        return _failed(
            "Candidate has no source location; isolated project commands must explicitly use {candidate_file}",
            candidate_file,
        )
    if not commands and not config.differential_cases_file:
        return ValidationVerdict(
            verdict=Verdict.UNKNOWN,
            summary="Candidate overlay created; no build or test commands configured",
            overlay_file=str(candidate_file),
        )
    if (
        config.require_verified
        and any(isinstance(command, str) for _, command in commands)
        and not config.allow_host_commands
        and config.trust_configured_commands
    ):
        return _failed(
            "Validation commands are configured but host execution is disabled; "
            "set validation.allow_host_commands only in a trusted isolated environment",
            candidate_file,
        )
    if not config.copy_project:
        unsafe = [command for _, command in commands if not _consumes_candidate(command)]
        if unsafe:
            return _failed(
                "Non-isolated validation commands must explicitly consume "
                "{candidate_file}, {overlay_root}, REFORGE_CANDIDATE_FILE, or "
                "REFORGE_OVERLAY_ROOT",
                candidate_file,
                [f"does not consume candidate: {command}" for command in unsafe],
            )

    allowed_environment = {name.casefold() for name in config.environment_allowlist}
    env = {name: value for name, value in os.environ.items() if name.casefold() in allowed_environment}
    env.update(
        {
            "REFORGE_CANDIDATE_FILE": str(candidate_file.resolve()),
            "REFORGE_OVERLAY_ROOT": str(_overlay_root(candidate_file).resolve()),
            "REFORGE_SOURCE_FILE": source_file or "",
        }
    )
    findings: list[str] = []
    checks: list[dict[str, str]] = []
    working_directory = _working_directory(config, candidate_file)

    for kind, command in commands:
        if isinstance(command, str):
            if os.name == "nt":
                shell_bin = os.environ.get("COMSPEC", "cmd.exe")
                expanded = [shell_bin, "/d", "/c", _expand_shell(command)]
            else:
                shell_bin = os.environ.get("SHELL", "/bin/sh")
                expanded = [shell_bin, "-lc", _expand_shell(command)]
        else:
            expanded = [_expand_argument(arg, env) for arg in command]
        try:
            proc = run_process(
                expanded,
                cwd=working_directory,
                env=env,
                timeout_s=config.command_timeout_s,
            )
        except OSError as exc:
            checks.append({"kind": kind, "verdict": "FAIL", "detail": str(exc)})
            return _failed(
                f"{kind} command could not start: {exc}",
                candidate_file,
                findings + [str(exc)],
                checks,
            )
        except subprocess.TimeoutExpired:
            checks.append({"kind": kind, "verdict": "FAIL", "detail": "timed out"})
            return _failed(
                f"{kind} command timed out: {command}",
                candidate_file,
                findings,
                checks,
            )
        tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-20:])
        findings.append(f"{kind}: {command} -> exit {proc.returncode}\n{tail}".rstrip())
        checks.append(
            {
                "kind": kind,
                "verdict": "PASS" if proc.returncode == 0 else "FAIL",
                "detail": f"exit {proc.returncode}",
            }
        )
        if proc.returncode != 0:
            return _failed(f"Candidate {kind} gate failed", candidate_file, findings, checks)

    if config.differential_cases_file:
        from reforge.verification.differential import compare_commands

        try:
            cases = json.loads(Path(config.differential_cases_file).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            checks.append({"kind": "differential", "verdict": "FAIL", "detail": str(exc)})
            return _failed("Could not read differential cases", candidate_file, findings, checks)
        if not isinstance(cases, list):
            checks.append({"kind": "differential", "verdict": "FAIL", "detail": "Cases must be a JSON array"})
            return _failed("Differential cases must be a JSON array", candidate_file, findings, checks)

        def expand_args(args: list[str]) -> list[str]:
            values = {
                "{candidate_file}": str(candidate_file.resolve()),
                "{overlay_root}": str(_overlay_root(candidate_file).resolve()),
            }
            result = []
            for arg in args:
                for key, value in values.items():
                    arg = arg.replace(key, value)
                result.append(arg)
            return result

        comparison = compare_commands(
            expand_args(config.differential_reference),
            expand_args(config.differential_candidate),
            cases,
            Path(working_directory),
            config.command_timeout_s,
        )
        checks.append(
            {
                "kind": "differential",
                "verdict": "PASS" if comparison.passed else "FAIL",
                "detail": f"{comparison.cases_run} cases",
            }
        )
        findings.extend(comparison.findings)
        if not comparison.passed:
            return _failed("Candidate differential gate failed", candidate_file, findings, checks)

    if not config.trust_configured_commands:
        return ValidationVerdict(
            verdict=Verdict.UNKNOWN,
            summary=(
                "Configured commands passed but are not accepted as proof until "
                "validation.trust_configured_commands is explicitly enabled"
            ),
            findings=findings,
            checks=checks,
            overlay_file=str(candidate_file),
        )

    return ValidationVerdict(
        verdict=Verdict.PASS,
        summary="All configured candidate validation gates passed",
        findings=findings,
        checks=checks,
        overlay_file=str(candidate_file),
    )


def cleanup_candidate_overlay(candidate_file: Path) -> None:
    """Remove a temporary full-project overlay created for isolated validation."""
    root = _overlay_root(candidate_file)
    if root.name.startswith("reforge-") and (root / ".reforge-overlay").exists():
        shutil.rmtree(root, ignore_errors=True)


def _sanitize_path_component(value: str) -> str:
    """Replace characters that are illegal in host filesystem names."""
    return safe_filename(value, max_length=120)


def _expand_argument(argument: str, env: dict[str, str]) -> str:
    # Single pass: replacement values are data, never additional placeholders.
    return re.sub(
        r"\{(candidate_file|overlay_root|source_file)\}",
        lambda match: env["REFORGE_" + match[1].upper()],
        argument,
    )


def _consumes_candidate(command: str | list[str]) -> bool:
    if isinstance(command, list):
        return any(marker in arg for arg in command for marker in ("{candidate_file}", "{overlay_root}"))
    markers = (
        "{candidate_file}",
        "{overlay_root}",
        "$REFORGE_CANDIDATE_FILE",
        "${REFORGE_CANDIDATE_FILE}",
        "$REFORGE_OVERLAY_ROOT",
        "${REFORGE_OVERLAY_ROOT}",
    )
    return any(marker in command for marker in markers)


def _overlay_root(candidate_file: Path) -> Path:
    for parent in (candidate_file.parent, *candidate_file.parents):
        if (parent / ".reforge-overlay").exists():
            return parent
    parts = candidate_file.parts
    if "candidates" in parts:
        idx = parts.index("candidates")
        if idx + 1 < len(parts):
            return Path(*parts[: idx + 2])
    return candidate_file.parent


def _working_directory(config: ValidationConfig, candidate_file: Path) -> str:
    overlay_root = _overlay_root(candidate_file).resolve()
    value = config.working_directory.replace("{overlay_root}", str(overlay_root))
    candidate = Path(value)
    if config.copy_project:
        resolved = candidate.resolve() if candidate.is_absolute() else (overlay_root / candidate).resolve()
        try:
            resolved.relative_to(overlay_root)
        except ValueError:
            raise ValueError("validation.working_directory must stay inside the isolated project overlay") from None
        if not resolved.is_dir():
            raise ValueError(f"validation.working_directory does not exist: {resolved}")
        return str(resolved)
    return value


def _remap_links(overlay: Path, project: Path) -> None:
    """Keep internal links inside the copy; reject external and broken links."""
    root = project.resolve()
    for directory, dirs, files in os.walk(overlay, followlinks=False):
        for name in [*dirs, *files]:
            link = Path(directory) / name
            if not link.is_symlink():
                continue
            original = root / link.relative_to(overlay)
            try:
                target = original.resolve(strict=True).relative_to(root)
            except (ValueError, OSError, RuntimeError) as exc:
                raise ValueError(
                    "Symbolic links and junctions pointing outside the project root are not allowed "
                    f"(symlink: {original})"
                ) from exc
            link.unlink()
            try:
                link.symlink_to(os.path.relpath(overlay / target, link.parent), target_is_directory=original.is_dir())
            except OSError:
                target_resolved = (overlay / target).resolve()
                if original.is_dir():
                    shutil.copytree(target_resolved, link)
                else:
                    shutil.copy2(target_resolved, link)


def _expand_shell(command: str) -> str:
    """Expand placeholders via environment values, respecting existing quotes."""
    markers = {
        "{candidate_file}": "REFORGE_CANDIDATE_FILE",
        "{overlay_root}": "REFORGE_OVERLAY_ROOT",
        "{source_file}": "REFORGE_SOURCE_FILE",
    }
    quote = ""
    output = ""
    index = 0
    while index < len(command):
        marker = next((m for m in markers if command.startswith(m, index)), None)
        if marker:
            variable = "${" + markers[marker] + "}"
            if quote == "'":
                output += "'\"" + variable + "\"'"
            elif quote == '"':
                output += variable
            else:
                output += '"' + variable + '"'
            index += len(marker)
            continue
        char = command[index]
        if char == "\\" and quote != "'" and index + 1 < len(command):
            output += command[index : index + 2]
            index += 2
            continue
        if char in {"'", '"'}:
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
        output += char
        index += 1
    return output


def _failed(
    summary: str,
    candidate_file: Path,
    findings: list[str] | None = None,
    checks: list[dict[str, str]] | None = None,
) -> ValidationVerdict:
    return ValidationVerdict(
        verdict=Verdict.FAIL,
        summary=summary,
        findings=findings or [],
        checks=checks or [],
        overlay_file=str(candidate_file),
    )
