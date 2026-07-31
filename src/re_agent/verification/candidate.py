"""Candidate overlays and configurable build/test validation gates."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from re_agent.config.schema import ValidationConfig
from re_agent.core.models import FunctionTarget, SourceMatch, ValidationVerdict, Verdict
from re_agent.utils.paths import safe_filename

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
    if not (config.build_commands or config.test_commands or config.runtime_commands):
        return "validation.require_verified is true but no build/test/runtime commands are configured"
    if config.require_build and not config.build_commands:
        return "validation.require_build is true but build_commands is empty"
    if config.require_tests and not config.test_commands:
        return "validation.require_tests is true but test_commands is empty"
    if config.require_runtime and not config.runtime_commands:
        return "validation.require_runtime is true but runtime_commands is empty"
    if not config.allow_host_commands:
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
            _reject_project_symlinks(project_root)
            overlay_root = Path(tempfile.mkdtemp(prefix=f"re-agent-{safe_address}-"))
            shutil.copytree(
                project_root,
                overlay_root,
                dirs_exist_ok=True,
                symlinks=False,
                ignore=_PROJECT_COPY_IGNORE,
            )
        else:
            overlay_root = report_dir / "candidates" / safe_address
        overlay_root.mkdir(parents=True, exist_ok=True)
        (overlay_root / ".re-agent-overlay").write_text("schema_version=1\n", encoding="utf-8")
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


def _find_windows_shell() -> tuple[list[str], bool]:
    """Return a Windows shell command and whether it expects MSYS paths."""
    for candidate_path in [
        r"C:\Program Files\Git\bin\sh.exe",
        r"C:\Program Files\Git\usr\bin\sh.exe",
        r"C:\Program Files (x86)\Git\bin\sh.exe",
        shutil.which("sh"),
        shutil.which("bash"),
    ]:
        if candidate_path and os.path.exists(candidate_path):
            return [candidate_path, "-c"], True
    return [shutil.which("cmd.exe") or "cmd.exe", "/d", "/s", "/c"], False


def validate_candidate(
    config: ValidationConfig,
    candidate_file: Path,
    source_file: str | None,
) -> ValidationVerdict:
    """Run configured build and test commands against the candidate overlay."""
    commands = [("build", command) for command in config.build_commands]
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
        and not any("{candidate_file}" in command for _, command in commands)
    ):
        return _failed(
            "Candidate has no source location; isolated project commands must explicitly use {candidate_file}",
            candidate_file,
        )
    if not commands:
        return ValidationVerdict(
            verdict=Verdict.UNKNOWN,
            summary="Candidate overlay created; no build or test commands configured",
            overlay_file=str(candidate_file),
        )
    if not config.allow_host_commands:
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
                "{candidate_file}, {overlay_root}, RE_AGENT_CANDIDATE_FILE, or "
                "RE_AGENT_OVERLAY_ROOT",
                candidate_file,
                [f"does not consume candidate: {command}" for command in unsafe],
            )

    allowed_environment = {name.casefold() for name in config.environment_allowlist}
    env = {name: value for name, value in os.environ.items() if name.casefold() in allowed_environment}
    env.update(
        {
            "RE_AGENT_CANDIDATE_FILE": str(candidate_file.resolve()),
            "RE_AGENT_OVERLAY_ROOT": str(_overlay_root(candidate_file).resolve()),
            "RE_AGENT_SOURCE_FILE": source_file or "",
        }
    )
    findings: list[str] = []
    try:
        working_directory = _working_directory(config, candidate_file)
    except ValueError as exc:
        return _failed(str(exc), candidate_file)

    windows_shell: list[str] = []
    use_msys_paths = False
    if sys.platform == "win32":
        windows_shell, use_msys_paths = _find_windows_shell()

    for kind, command in commands:
        expanded = command
        cand_path = str(candidate_file.resolve())
        overlay_path = str(_overlay_root(candidate_file).resolve())
        src_path = source_file or ""
        if sys.platform != "win32" or use_msys_paths:
            cand_path = cand_path.replace("\\", "/")
            overlay_path = overlay_path.replace("\\", "/")
            src_path = src_path.replace("\\", "/")
        if sys.platform == "win32" and use_msys_paths:
            cand_path = re.sub(r"^([a-zA-Z]):", lambda m: "/" + m.group(1).lower(), cand_path)
            overlay_path = re.sub(r"^([a-zA-Z]):", lambda m: "/" + m.group(1).lower(), overlay_path)
            src_path = re.sub(r"^([a-zA-Z]):", lambda m: "/" + m.group(1).lower(), src_path)
        replacements = {
            "{candidate_file}": cand_path,
            "{overlay_root}": overlay_path,
            "{source_file}": src_path,
        }
        for placeholder, value in replacements.items():
            expanded = expanded.replace(placeholder, value)
        if sys.platform == "win32":
            cmd_args = windows_shell + [expanded]
        else:
            cmd_args = ["/bin/sh", "-lc", expanded]
        try:
            proc = subprocess.run(
                cmd_args,
                cwd=working_directory,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=config.command_timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return _failed(f"{kind} command timed out: {command}", candidate_file, findings)
        except OSError as exc:
            return _failed(
                f"{kind} command could not be started: {command}",
                candidate_file,
                findings + [str(exc)],
            )
        tail = "\n".join(proc.stdout.splitlines()[-20:])
        findings.append(f"{kind}: {command} -> exit {proc.returncode}\n{tail}".rstrip())
        if proc.returncode != 0:
            return _failed(f"Candidate {kind} gate failed", candidate_file, findings)

    if not config.trust_configured_commands:
        return ValidationVerdict(
            verdict=Verdict.UNKNOWN,
            summary=(
                "Configured commands passed but are not accepted as proof until "
                "validation.trust_configured_commands is explicitly enabled"
            ),
            findings=findings,
            overlay_file=str(candidate_file),
        )

    return ValidationVerdict(
        verdict=Verdict.PASS,
        summary="All configured candidate build/test gates passed",
        findings=findings,
        overlay_file=str(candidate_file),
    )


def cleanup_candidate_overlay(candidate_file: Path) -> None:
    """Remove a temporary full-project overlay created for isolated validation."""
    root = _overlay_root(candidate_file)
    if root.name.startswith("re-agent-") and (root / ".re-agent-overlay").exists():
        shutil.rmtree(root)


def _sanitize_path_component(value: str) -> str:
    """Replace characters that are illegal in host filesystem names."""
    return safe_filename(value, max_length=120)


def _consumes_candidate(command: str) -> bool:
    markers = (
        "{candidate_file}",
        "{overlay_root}",
        "$RE_AGENT_CANDIDATE_FILE",
        "${RE_AGENT_CANDIDATE_FILE}",
        "$RE_AGENT_OVERLAY_ROOT",
        "${RE_AGENT_OVERLAY_ROOT}",
    )
    return any(marker in command for marker in markers)


def _overlay_root(candidate_file: Path) -> Path:
    for parent in (candidate_file.parent, *candidate_file.parents):
        if (parent / ".re-agent-overlay").exists():
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


def _reject_project_symlinks(project_root: Path) -> None:
    """Reject project copies that could escape through symbolic links."""
    root = project_root.resolve()
    if not root.is_dir():
        raise ValueError(f"validation.project_root is not a directory: {project_root}")

    def is_link_like(value: Path) -> bool:
        junction_check = getattr(value, "is_junction", None)
        return value.is_symlink() or (callable(junction_check) and bool(junction_check()))

    if is_link_like(project_root):
        raise ValueError(f"validation.project_root must not be a symbolic link or junction: {project_root}")

    for directory, dir_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        names = dir_names + file_names
        ignored = set(_PROJECT_COPY_IGNORE(directory, names))
        for name in names:
            if name in ignored:
                continue
            candidate = directory_path / name
            if is_link_like(candidate):
                raise ValueError(
                    f"Symbolic links and junctions are not allowed in isolated validation copies: {candidate}"
                )
        dir_names[:] = [name for name in dir_names if name not in ignored]


def _failed(
    summary: str,
    candidate_file: Path,
    findings: list[str] | None = None,
) -> ValidationVerdict:
    return ValidationVerdict(
        verdict=Verdict.FAIL,
        summary=summary,
        findings=findings or [],
        overlay_file=str(candidate_file),
    )
