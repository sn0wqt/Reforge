"""Subprocess execution utilities."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence

_CLI_ENVIRONMENT_KEYS = frozenset(
    {
        "APPDATA",
        "CODEX_CA_CERTIFICATE",
        "CODEX_HOME",
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "NO_COLOR",
        "PATH",
        "PATHEXT",
        "PROGRAMDATA",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    }
)


def sanitized_cli_environment() -> dict[str, str]:
    """Return path/locale state needed by login-backed CLIs without API secrets."""
    allowed = {name.casefold() for name in _CLI_ENVIRONMENT_KEYS}
    return {name: value for name, value in os.environ.items() if name.casefold() in allowed}


def run_cmd(args: Sequence[str], timeout_s: int = 45) -> tuple[bool, str]:
    """Run a command and return ``(success, combined_output)``.

    Args:
        args: Command and arguments to execute.
        timeout_s: Maximum wall-clock seconds before the process is killed.

    Returns:
        A tuple of ``(ok, output)`` where *ok* is ``True`` when the process
        exits with return code 0 and *output* contains combined stdout/stderr.
    """
    try:
        proc = subprocess.run(
            list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return proc.returncode == 0, proc.stdout
    except subprocess.TimeoutExpired as e:
        return False, f"TIMEOUT after {timeout_s}s: {' '.join(str(a) for a in args)}\n{e}"
    except FileNotFoundError:
        return False, f"Command not found: {args[0]}"
    except OSError as exc:
        return False, f"Command could not be started: {args[0]}: {exc}"


def run_cmd_split(args: Sequence[str], timeout_s: int = 45) -> tuple[int, str, str]:
    """Run a command and return ``(returncode, stdout, stderr)`` separately.

    Unlike :func:`run_cmd`, this keeps stdout and stderr in separate streams
    so callers can inspect error messages independently of normal output.

    Returns ``(-1, "", error_message)`` on timeout or missing executable.
    """
    try:
        proc = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return -1, "", f"TIMEOUT after {timeout_s}s: {e}"
    except FileNotFoundError:
        return -1, "", f"Command not found: {args[0]}"
    except OSError as exc:
        return -1, "", f"Command could not be started: {args[0]}: {exc}"
