"""Live Frida instrumentation session runner for Reforge.

Provides lifecycle management, spawn vs attach handling, circular FIFO message
buffering, credential and error sanitization, and orphaned process prevention
modeled on REA (Reverse Engineering Agent) Frida instrumentation patterns.
"""

from __future__ import annotations

import collections
import contextlib
import json
import logging
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, cast

if TYPE_CHECKING:
    import frida

logger = logging.getLogger(__name__)

DEFAULT_MAX_CAPTURE_BYTES = 16 * 1024 * 1024  # 16 MiB session ceiling matching REA
DEFAULT_MAX_MESSAGES = 10_000
DEFAULT_MAX_MESSAGE_BYTES = 32 * 1024  # 32 KiB
DEFAULT_MAX_ERROR_BYTES = 4096


# -----------------------------------------------------------------------------
# Lazy Frida Loader
# -----------------------------------------------------------------------------

_frida_module: Any | None = None


def get_frida() -> Any:
    """Lazily import and return the Frida module.

    Raises:
        RuntimeError: If frida is not installed in the current Python environment.
    """
    global _frida_module
    if _frida_module is not None:
        return _frida_module

    try:
        import frida

        _frida_module = frida
        return frida
    except ImportError as exc:
        raise RuntimeError(
            "Frida is not installed. Install with 'pip install frida' to enable dynamic instrumentation."
        ) from exc


def is_frida_available() -> bool:
    """Return True if the frida module is importable without errors."""
    try:
        get_frida()
        return True
    except (ImportError, RuntimeError):
        return False


# -----------------------------------------------------------------------------
# Credential & Error Sanitization
# -----------------------------------------------------------------------------


def redact_secrets(
    text: str,
    secrets: Sequence[str] | None = None,
    max_length: int = DEFAULT_MAX_MESSAGE_BYTES,
) -> tuple[str, bool]:
    """Redact sensitive strings (tokens, certificates) and bound string length.

    Args:
        text: String to sanitize.
        secrets: Collection of secrets to replace with '[redacted]'.
        max_length: Maximum allowed character length before truncation.

    Returns:
        Tuple of (sanitized_text, was_truncated).
    """
    if not text:
        return "", False

    sanitized = text
    if secrets:
        for secret in secrets:
            if secret and len(secret) > 0:
                sanitized = sanitized.replace(secret, "[redacted]")

    was_truncated = False
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + " ... [truncated]"
        was_truncated = True

    return sanitized, was_truncated


def sanitize_error(
    error: Exception | str,
    secrets: Sequence[str] | None = None,
    max_length: int = DEFAULT_MAX_ERROR_BYTES,
) -> str:
    """Convert an exception or error string to a redacted and bounded string."""
    msg = str(error) if not isinstance(error, str) else error
    sanitized, _ = redact_secrets(msg, secrets, max_length=max_length)
    return sanitized


# -----------------------------------------------------------------------------
# Circular FIFO Message Buffer
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class CapturedLogEntry:
    """Structured observation of a single Frida script or runner log message."""

    timestamp: float
    level: str  # "info", "warning", "error", "trace"
    message: str
    script_name: str = "default"
    charge: int = 0
    raw_message: dict[str, Any] | None = None
    data: bytes | None = None

    @property
    def formatted(self) -> str:
        """Formatted string representation."""
        prefix = f"[{self.level.upper()}]"
        if self.script_name and self.script_name != "default":
            return f"{prefix} [{self.script_name}] {self.message}"
        return f"{prefix} {self.message}"


class CircularMessageBuffer:
    """Bounded arrival-ordered FIFO queue with byte and item ceilings.

    Evicts oldest entries when total byte charge or item count exceeds the
    budget, matching REA's MessageFifo behavior.
    """

    def __init__(
        self,
        max_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
        max_messages: int = DEFAULT_MAX_MESSAGES,
    ) -> None:
        self.max_bytes = max_bytes
        self.max_messages = max_messages
        self._deque: collections.deque[CapturedLogEntry] = collections.deque()
        self._total_bytes: int = 0
        self._is_truncated: bool = False

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    @property
    def is_truncated(self) -> bool:
        return self._is_truncated

    def __len__(self) -> int:
        return len(self._deque)

    def append(self, entry: CapturedLogEntry) -> None:
        """Push an entry into the buffer, evicting oldest items if capacity exceeded."""
        if entry.charge <= 0:
            msg_bytes = len(entry.message.encode("utf-8", errors="replace"))
            data_bytes = len(entry.data) if entry.data else 0
            entry.charge = msg_bytes + data_bytes + 64

        # If a single message exceeds the entire buffer capacity, mark truncated and bound it
        if entry.charge > self.max_bytes:
            self._is_truncated = True
            bounded_msg, _ = redact_secrets(entry.message, max_length=1024)
            entry.message = f"{bounded_msg} [Payload exceeded buffer limit]"
            entry.charge = len(entry.message.encode("utf-8", errors="replace")) + 64

        # Evict oldest items while exceeding byte limit or item count limit
        while self._deque and (
            (self._total_bytes + entry.charge > self.max_bytes)
            or (len(self._deque) >= self.max_messages)
        ):
            evicted = self._deque.popleft()
            self._total_bytes -= evicted.charge
            self._is_truncated = True

        self._deque.append(entry)
        self._total_bytes += entry.charge

    def to_list(self) -> list[CapturedLogEntry]:
        """Return a snapshot list of captured log entries."""
        return list(self._deque)

    def to_log_lines(self) -> list[str]:
        """Return formatted string lines for all captured entries."""
        return [entry.formatted for entry in self._deque]

    def clear(self) -> None:
        """Clear all entries in the buffer."""
        self._deque.clear()
        self._total_bytes = 0
        self._is_truncated = False


# -----------------------------------------------------------------------------
# Configuration & Result Dataclasses
# -----------------------------------------------------------------------------


@dataclass
class FridaSessionConfig:
    """Configuration for starting and managing a Frida instrumentation session."""

    target: str | int
    mode: Literal["spawn", "attach"] = "spawn"
    argv: list[str] | None = None
    device_type: Literal["local", "usb", "remote", "by_id"] = "local"
    device_id: str | None = None
    remote_address: str | None = None
    remote_token: str | None = None
    remote_certificate: str | None = None
    remote_origin: str | None = None
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES
    max_messages: int = DEFAULT_MAX_MESSAGES
    secrets: list[str] = field(default_factory=list)
    resume_on_start: bool = True
    spawn_timeout: float = 30.0

    def all_secrets(self) -> list[str]:
        """Collate all declared secrets and connection credentials."""
        collated = list(self.secrets)
        if self.remote_token:
            collated.append(self.remote_token)
        if self.remote_certificate:
            collated.append(self.remote_certificate)
        return [s for s in collated if s]


@dataclass
class FridaRunResult:
    """Result summary of a Frida instrumentation run."""

    success: bool
    target: str | int
    mode: str
    pid: int
    entries: list[CapturedLogEntry]
    logs: list[str]
    truncated: bool
    target_resumed: bool
    detached: bool
    captured_bytes: int
    error: str | None = None


# -----------------------------------------------------------------------------
# Device Resolution
# -----------------------------------------------------------------------------


def resolve_device(config: FridaSessionConfig, frida_mod: Any | None = None) -> frida.Device:
    """Resolve and return the appropriate Frida Device based on configuration.

    Supports local, USB, remote (with optional token/cert auth), or specific device ID.
    """
    f = frida_mod if frida_mod is not None else get_frida()

    try:
        if config.device_type == "usb":
            return cast("frida.Device", f.get_usb_device())

        if config.device_type == "remote" or config.remote_address:
            address = config.remote_address or "127.0.0.1:27042"
            if config.remote_token or config.remote_certificate or config.remote_origin:
                mgr = f.get_device_manager()
                kwargs: dict[str, Any] = {}
                if config.remote_token:
                    kwargs["token"] = config.remote_token
                if config.remote_certificate:
                    kwargs["certificate"] = config.remote_certificate
                if config.remote_origin:
                    kwargs["origin"] = config.remote_origin
                return cast("frida.Device", mgr.add_remote_device(address, **kwargs))
            return cast("frida.Device", f.get_remote_device(address))

        if config.device_type == "by_id" or config.device_id:
            dev_id = config.device_id or "local"
            return cast("frida.Device", f.get_device(dev_id))

        return cast("frida.Device", f.get_local_device())
    except Exception as exc:
        secrets = config.all_secrets()
        sanitized = sanitize_error(exc, secrets)
        raise RuntimeError(f"Unable to resolve Frida device ({config.device_type}): {sanitized}") from exc


# -----------------------------------------------------------------------------
# Frida Session Lifecycle Runner
# -----------------------------------------------------------------------------


class FridaSessionRunner:
    """Lifecycle manager for Frida sessions with safe orphan prevention.

    Manages spawn vs attach, script loading, message capturing, log streaming,
    and guarantees that spawned processes are resumed upon cleanup or failure
    to prevent orphaned paused processes.
    """

    def __init__(
        self,
        config: FridaSessionConfig,
        *,
        frida_mod: Any | None = None,
        on_log: Callable[[CapturedLogEntry], None] | None = None,
        on_message: Callable[[dict[str, Any], bytes | None], None] | None = None,
    ) -> None:
        self.config = config
        self._frida = frida_mod
        self.on_log = on_log
        self.on_message = on_message

        self.device: frida.Device | None = None
        self.session: frida.Session | None = None
        self.spawned_pid: int | None = None
        self.is_paused: bool = False
        self.target_resumed: bool = False
        self.is_detached: bool = False
        self.scripts: dict[str, frida.Script] = {}
        self.buffer = CircularMessageBuffer(
            max_bytes=config.max_capture_bytes,
            max_messages=config.max_messages,
        )
        self._lock = threading.Lock()
        self._secrets: list[str] = config.all_secrets()
        self._started = False
        self._closed = False

    @property
    def pid(self) -> int:
        """Return the target process PID."""
        if self.spawned_pid is not None:
            return self.spawned_pid
        if isinstance(self.config.target, int):
            return self.config.target
        return 0

    def start(self) -> None:
        """Connect to device and initiate session (spawn or attach).

        Guarantees that if spawn succeeds but subsequent attach or setup fails,
        the spawned process is resumed before raising to prevent orphaned paused processes.
        """
        if self._started:
            return

        f = self._frida if self._frida is not None else get_frida()
        self.device = resolve_device(self.config, frida_mod=f)

        try:
            if self.config.mode == "spawn":
                target_str = str(self.config.target)
                argv: list[str | bytes] | None = [target_str, *self.config.argv] if self.config.argv else None
                logger.info("Spawning process %s (argv=%s)...", target_str, argv)
                # Spawn creates the process in a PAUSED state
                self.spawned_pid = self.device.spawn(target_str, argv=argv)
                self.is_paused = True
                logger.info("Spawned PID %d (paused). Attaching session...", self.spawned_pid)
                self.session = self.device.attach(self.spawned_pid)
            else:
                logger.info("Attaching to target %s...", self.config.target)
                self.session = self.device.attach(self.config.target)
                self.spawned_pid = None
                self.is_paused = False

            cast(Any, self.session).on("detached", self._on_detached)
            self._started = True

        except Exception as exc:
            # PREVENT ORPHANED PAUSED PROCESS:
            # If spawn succeeded but attach failed or threw an exception, resume it immediately!
            if self.spawned_pid is not None and self.is_paused and self.device is not None:
                try:
                    logger.warning(
                        "Startup failed after spawn. Resuming spawned PID %d to prevent orphan...",
                        self.spawned_pid,
                    )
                    self.device.resume(self.spawned_pid)
                    self.is_paused = False
                    self.target_resumed = True
                except Exception as resume_exc:
                    logger.error("Failed to resume orphaned spawned PID %d: %s", self.spawned_pid, resume_exc)

            sanitized = sanitize_error(exc, self._secrets)
            raise RuntimeError(f"Failed to start Frida session ({self.config.mode}): {sanitized}") from exc

    def _on_detached(self, reason: Any = None, crash: Any = None) -> None:
        """Callback invoked when Frida session detaches."""
        with self._lock:
            self.is_detached = True
            msg = f"Frida session detached (reason: {reason})"
            if crash:
                msg += f" [Crash: {crash}]"
            entry = CapturedLogEntry(
                timestamp=time.time(),
                level="warning",
                message=msg,
                script_name="session",
            )
            self.buffer.append(entry)
            if self.on_log:
                with contextlib.suppress(Exception):
                    self.on_log(entry)

    def load_script(self, source: str, name: str = "reforge-hook") -> str:
        """Create, configure, and load a Frida script inside the target.

        Args:
            source: JavaScript/TypeScript instrumentation source code.
            name: Label or script name.

        Returns:
            The script name.
        """
        if not self._started or self.session is None:
            raise RuntimeError("Cannot load script: session is not started.")
        if self.is_detached:
            raise RuntimeError("Cannot load script: session is detached.")

        try:
            script = self.session.create_script(source, name=name)
            cast(Any, script).on("message", lambda msg, data: self._handle_script_message(name, msg, data))
            script.load()
            with self._lock:
                self.scripts[name] = script
            logger.info("Loaded script '%s' into session.", name)
            return name
        except Exception as exc:
            sanitized = sanitize_error(exc, self._secrets)
            raise RuntimeError(f"Failed to load Frida script '{name}': {sanitized}") from exc

    def unload_script(self, name: str) -> None:
        """Unload and destroy a loaded script by name."""
        with self._lock:
            script = self.scripts.pop(name, None)

        if script is not None:
            try:
                script.unload()
                logger.info("Unloaded script '%s'.", name)
            except Exception as exc:
                sanitized = sanitize_error(exc, self._secrets)
                logger.warning("Error unloading script '%s': %s", name, sanitized)

    def resume(self) -> None:
        """Resume a paused spawned target process."""
        if self.spawned_pid is not None and self.is_paused and self.device is not None:
            try:
                self.device.resume(self.spawned_pid)
                self.is_paused = False
                self.target_resumed = True
                logger.info("Resumed spawned process PID %d.", self.spawned_pid)
            except Exception as exc:
                sanitized = sanitize_error(exc, self._secrets)
                raise RuntimeError(f"Failed to resume process PID {self.spawned_pid}: {sanitized}") from exc

    def _handle_script_message(self, script_name: str, message: dict[str, Any], data: bytes | None) -> None:
        """Process incoming Frida message, redacting secrets and bounding output."""
        with self._lock:
            msg_type = message.get("type", "send")
            level = "info"
            text = ""

            if msg_type == "send":
                payload = message.get("payload")
                if isinstance(payload, str):
                    text, _ = redact_secrets(payload, self._secrets)
                elif isinstance(payload, (dict, list, int, float, bool)) or payload is None:
                    try:
                        raw_json = json.dumps(payload)
                        text, _ = redact_secrets(raw_json, self._secrets)
                    except Exception:
                        text = f"<unserializable payload: {type(payload).__name__}>"
                else:
                    text, _ = redact_secrets(str(payload), self._secrets)

                # Classify log level based on message markers
                if text.startswith("[reforge]") or text.startswith("[+]"):
                    level = "trace"
                elif text.startswith("[-]") or text.startswith("[!]"):
                    level = "error"
                elif text.startswith("[*]"):
                    level = "info"

            elif msg_type == "error":
                level = "error"
                description = message.get("description", "Unknown script error")
                stack = message.get("stack", "")
                sanitized_desc, _ = redact_secrets(description, self._secrets)
                sanitized_stack, _ = redact_secrets(stack, self._secrets)
                text = f"Script error: {sanitized_desc}"
                if sanitized_stack:
                    text += f"\n{sanitized_stack}"
            else:
                text = f"Message type: {msg_type}"

            # Scrub binary data if secrets appear in it
            sanitized_data = data
            if data is not None and self._secrets:
                for secret in self._secrets:
                    if secret.encode("utf-8") in data:
                        sanitized_data = b"[redacted_binary_secret]"
                        break

            entry = CapturedLogEntry(
                timestamp=time.time(),
                level=level,
                message=text,
                script_name=script_name,
                raw_message=message,
                data=sanitized_data,
            )

            self.buffer.append(entry)

            # Fire streaming callbacks
            if self.on_log is not None:
                try:
                    self.on_log(entry)
                except Exception as cb_exc:
                    logger.debug("Exception in on_log callback: %s", cb_exc)

            if self.on_message is not None:
                try:
                    self.on_message(message, sanitized_data)
                except Exception as cb_exc:
                    logger.debug("Exception in on_message callback: %s", cb_exc)

    def close(self) -> None:
        """Safely close session, unload scripts, detach, and prevent orphaned processes."""
        if self._closed:
            return
        self._closed = True

        # 1. Unload all active scripts
        with self._lock:
            active_scripts = list(self.scripts.values())
            self.scripts.clear()

        for script in active_scripts:
            with contextlib.suppress(Exception):
                script.unload()

        # 2. Detach session
        if self.session is not None and not self.is_detached:
            with contextlib.suppress(Exception):
                self.session.detach()
                self.is_detached = True

        # 3. PREVENT ORPHANED PAUSED PROCESS:
        # If target was spawned and remains paused, resume it so it is not orphaned!
        if self.spawned_pid is not None and self.is_paused and self.device is not None:
            try:
                logger.info("Resuming paused spawned process PID %d during session close...", self.spawned_pid)
                self.device.resume(self.spawned_pid)
                self.is_paused = False
                self.target_resumed = True
            except Exception as exc:
                logger.warning("Could not resume spawned process PID %d on close: %s", self.spawned_pid, exc)

        self.session = None
        self.device = None

    def __enter__(self) -> FridaSessionRunner:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


# -----------------------------------------------------------------------------
# High-Level Execution Functions
# -----------------------------------------------------------------------------


def run_frida_session(
    config: FridaSessionConfig,
    script_source: str,
    *,
    duration: float | None = None,
    stream_to_stdout: bool = False,
    on_log: Callable[[CapturedLogEntry], None] | None = None,
    stop_event: threading.Event | None = None,
    frida_mod: Any | None = None,
) -> FridaRunResult:
    """Execute a Frida instrumentation session, streaming logs and bounding output.

    Args:
        config: Frida session configuration.
        script_source: JavaScript/TypeScript script code to execute.
        duration: Maximum time to run in seconds, or None to run until detached/interrupted.
        stream_to_stdout: If True, print log entries to stdout as they arrive.
        on_log: Optional callback receiving each CapturedLogEntry in real-time.
        stop_event: Optional threading.Event to signal early termination.
        frida_mod: Optional mock or injected frida module.

    Returns:
        FridaRunResult summarizing execution and captured trace output.
    """
    def _combined_log_handler(entry: CapturedLogEntry) -> None:
        if stream_to_stdout:
            sys.stdout.write(f"{entry.formatted}\n")
            sys.stdout.flush()
        if on_log is not None:
            on_log(entry)

    runner = FridaSessionRunner(
        config,
        frida_mod=frida_mod,
        on_log=_combined_log_handler,
    )

    err_msg: str | None = None
    try:
        with runner:
            runner.load_script(script_source, name="reforge-instrumentation")
            if config.mode == "spawn" and config.resume_on_start:
                runner.resume()

            start_time = time.time()
            poll_interval = 0.1
            while True:
                if runner.is_detached:
                    break
                if stop_event is not None and stop_event.is_set():
                    break
                if duration is not None and (time.time() - start_time) >= duration:
                    break
                time.sleep(poll_interval)

    except Exception as exc:
        err_msg = sanitize_error(exc, config.all_secrets())
        logger.error("Frida session run error: %s", err_msg)

    return FridaRunResult(
        success=(err_msg is None),
        target=config.target,
        mode=config.mode,
        pid=runner.pid,
        entries=runner.buffer.to_list(),
        logs=runner.buffer.to_log_lines(),
        truncated=runner.buffer.is_truncated,
        target_resumed=runner.target_resumed,
        detached=runner.is_detached,
        captured_bytes=runner.buffer.total_bytes,
        error=err_msg,
    )


def run_synthesized_hook(
    target: str | int,
    hook_script: str,
    *,
    mode: Literal["spawn", "attach"] = "spawn",
    argv: list[str] | None = None,
    device_type: Literal["local", "usb", "remote", "by_id"] = "local",
    remote_address: str | None = None,
    duration: float | None = 10.0,
    stream: bool = True,
    on_log: Callable[[CapturedLogEntry], None] | None = None,
    frida_mod: Any | None = None,
) -> FridaRunResult:
    """Execute Reforge synthesized hooks generated by `reforge hook`.

    Args:
        target: Target program name, package, or PID.
        hook_script: Synthesized hook JavaScript source code.
        mode: "spawn" or "attach".
        argv: Command line arguments if spawning.
        device_type: "local", "usb", or "remote".
        remote_address: Optional remote HOST:PORT.
        duration: Seconds to trace, or None.
        stream: Whether to stream logs to stdout.
        on_log: Optional callback for each log entry.
        frida_mod: Injected frida module for testing.

    Returns:
        FridaRunResult with execution details.
    """
    config = FridaSessionConfig(
        target=target,
        mode=mode,
        argv=argv,
        device_type=device_type,
        remote_address=remote_address,
        resume_on_start=True,
    )
    return run_frida_session(
        config,
        hook_script,
        duration=duration,
        stream_to_stdout=stream,
        on_log=on_log,
        frida_mod=frida_mod,
    )
