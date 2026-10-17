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
        "CURL_CA_BUNDLE",
        "DEVELOPER_DIR",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "LOGNAME",
        "NO_COLOR",
        "PATH",
        "PATHEXT",
        "PROGRAMDATA",
        "SDKROOT",
        "SHELL",
        "SSH_AUTH_SOCK",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USER",
        "USERPROFILE",
        "WINDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
    }
)


def _prepare_args(args: Sequence[str]) -> list[str]:
    """Ensure batch scripts on Windows are wrapped with cmd.exe /c for shell=False execution."""
    cmd_args = [str(a) for a in args]
    if os.name == "nt" and cmd_args and cmd_args[0].lower().endswith((".bat", ".cmd")):
        cmd_args = ["cmd.exe", "/c", *cmd_args]
    return cmd_args


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
    cmd_args = _prepare_args(args)
    try:
        proc = subprocess.run(
            cmd_args,
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
    cmd_args = _prepare_args(args)
    try:
        proc = subprocess.run(
            cmd_args,
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


def run_process(
    args: Sequence[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    timeout_s: float = 45,
    max_output_bytes: int = 1_048_576,
) -> subprocess.CompletedProcess[str]:
    """Bound captured output and terminate the entire process group on timeout."""
    import contextlib
    import signal
    import tempfile
    import typing

    cmd_args = _prepare_args(args)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen(
            cmd_args,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=stderr,
            text=True,
            start_new_session=os.name != "nt",
        )
        try:
            proc.communicate(input_text, timeout=timeout_s)
        except BaseException:
            if os.name == "nt":
                if proc.poll() is None:
                    with contextlib.suppress(Exception):
                        subprocess.run(
                            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                            capture_output=True,
                            check=False,
                            timeout=5.0,
                        )
                    if proc.poll() is None:
                        with contextlib.suppress(Exception):
                            proc.kill()
            else:
                killpg = getattr(os, "killpg", None)
                sigkill = getattr(signal, "SIGKILL", signal.SIGTERM)
                if callable(killpg):
                    with contextlib.suppress(ProcessLookupError, PermissionError):
                        killpg(proc.pid, sigkill)
                if proc.poll() is None:
                    with contextlib.suppress(ProcessLookupError, PermissionError):
                        proc.kill()

            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5.0)
            raise

        def read_tail(handle: object) -> str:
            # Temporary files bound memory even when a build emits a large log.
            stream = typing.cast(typing.BinaryIO, handle)
            size = stream.seek(0, 2)
            stream.seek(max(0, size - max_output_bytes))
            text = stream.read().decode("utf-8", errors="replace")
            return ("[output truncated]\n" if size > max_output_bytes else "") + text

        returncode = proc.returncode if proc.returncode is not None else proc.wait()
        return subprocess.CompletedProcess(
            list(args),
            returncode,
            read_tail(stdout),
            read_tail(stderr),
        )
