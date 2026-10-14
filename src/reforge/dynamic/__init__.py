"""Reforge dynamic instrumentation and Frida session management."""

from __future__ import annotations

from reforge.dynamic.frida_runner import (
    CapturedLogEntry,
    CircularMessageBuffer,
    FridaRunResult,
    FridaSessionConfig,
    FridaSessionRunner,
    get_frida,
    is_frida_available,
    redact_secrets,
    resolve_device,
    run_frida_session,
    run_synthesized_hook,
    sanitize_error,
)

__all__ = [
    "CapturedLogEntry",
    "CircularMessageBuffer",
    "FridaRunResult",
    "FridaSessionConfig",
    "FridaSessionRunner",
    "get_frida",
    "is_frida_available",
    "redact_secrets",
    "resolve_device",
    "run_frida_session",
    "run_synthesized_hook",
    "sanitize_error",
]
