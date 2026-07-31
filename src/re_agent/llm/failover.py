"""Explicit, policy-gated failover across independently configured LLMs."""
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from re_agent.llm.base import BaseLLMProvider
from re_agent.llm.protocol import LLMProvider, Message

logger = logging.getLogger(__name__)


class FailureKind(str, Enum):
    """Routing disposition for a provider failure."""

    RATE_LIMIT = "rate_limit"
    TRANSIENT = "transient"
    CONTEXT_LIMIT = "context_limit"
    UNAVAILABLE = "unavailable"
    SAFETY = "safety"
    INVALID_REQUEST = "invalid_request"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProviderRoute:
    """One provider in an ordered failover chain."""

    name: str
    provider: LLMProvider
    max_retries: int = 1
    retry_base_delay_s: float = 1.0


class LLMFailoverError(RuntimeError):
    """Raised after every eligible provider route has failed."""


class UnavailableLLMProvider(BaseLLMProvider):
    """Deferred initialization failure that an explicit chain can route around."""

    def __init__(self, provider_name: str, error: BaseException) -> None:
        super().__init__()
        self._provider_name = provider_name
        self._error = error

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        del messages, kwargs
        raise RuntimeError(
            f"{self._provider_name} provider is unavailable: {self._error}"
        ) from self._error


_SAFETY_MARKERS = (
    "blocked for safety",
    "content filter",
    "content policy",
    "finish_reason: safety",
    "finishreason.safety",
    "policy violation",
    "prohibited content",
    "recitation",
    "safety rating",
    "safety settings",
)
_CONTEXT_MARKERS = (
    "context length",
    "context window",
    "input token limit",
    "maximum context",
    "max context",
    "prompt is too long",
    "request is too large",
    "request too large",
    "payload too large",
    "too many input tokens",
    "too many tokens",
    "command line is too long",
    "argument list too long",
    "filename or extension is too long",
)
_RATE_LIMIT_MARKERS = (
    "429",
    "resource_exhausted",
    "rate limit",
    "quota exceeded",
    "quota exhausted",
    "usage limit",
    "capacity",
)
_TRANSIENT_MARKERS = (
    "timed out",
    "timeout",
    "500 internal",
    "502 bad gateway",
    "503",
    "504",
    "connection aborted",
    "connection error",
    "connection refused",
    "connection reset",
    "network error",
    "service unavailable",
    "temporarily unavailable",
)
_UNAVAILABLE_MARKERS = (
    "not logged in",
    "authentication required",
    "credential",
    "unauthenticated",
    "unauthorized",
    "401",
    "403",
    "cli not found",
    "could not be started",
    "command not found",
    "model not found",
    "does not exist",
    "requires a newer version of codex",
    "please upgrade to the latest app or cli",
)
_INVALID_REQUEST_MARKERS = (
    "400 invalid_argument",
    "400 bad request",
    "invalid request",
    "malformed request",
    "unsupported message role",
)


def classify_provider_failure(exc: BaseException) -> FailureKind:
    """Classify failures conservatively without routing around safety policy."""
    text = f"{type(exc).__name__}: {exc}".casefold()
    if any(marker in text for marker in _SAFETY_MARKERS):
        return FailureKind.SAFETY
    if any(marker in text for marker in _CONTEXT_MARKERS):
        return FailureKind.CONTEXT_LIMIT
    if any(marker in text for marker in _RATE_LIMIT_MARKERS):
        return FailureKind.RATE_LIMIT
    if any(marker in text for marker in _TRANSIENT_MARKERS):
        return FailureKind.TRANSIENT
    if any(marker in text for marker in _INVALID_REQUEST_MARKERS):
        return FailureKind.INVALID_REQUEST
    if any(marker in text for marker in _UNAVAILABLE_MARKERS):
        return FailureKind.UNAVAILABLE
    return FailureKind.UNKNOWN


class FailoverLLMProvider(BaseLLMProvider):
    """Try an explicit provider chain for eligible operational failures."""

    def __init__(
        self,
        routes: Sequence[ProviderRoute],
        *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__()
        if not routes:
            raise ValueError("FailoverLLMProvider requires at least one route")
        self._routes = tuple(routes)
        self._sleep = sleep
        self.last_metadata: dict[str, object] = {}

    @property
    def provider_names(self) -> tuple[str, ...]:
        return tuple(route.name for route in self._routes)

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        attempts: list[dict[str, object]] = []
        failures: list[str] = []

        for route_index, route in enumerate(self._routes):
            for attempt_index in range(route.max_retries + 1):
                try:
                    route_kwargs = kwargs if route_index == 0 else {
                        key: value for key, value in kwargs.items() if key != "model"
                    }
                    response = route.provider.send(messages, **route_kwargs)
                except Exception as exc:
                    kind = classify_provider_failure(exc)
                    error = self._brief_error(exc)
                    attempts.append(
                        {
                            "provider": route.name,
                            "attempt": attempt_index + 1,
                            "outcome": "failed",
                            "failure_kind": kind.value,
                            "error": error,
                        }
                    )
                    failures.append(f"{route.name}: {kind.value}: {error}")

                    if kind in {FailureKind.SAFETY, FailureKind.INVALID_REQUEST, FailureKind.UNKNOWN}:
                        self.last_metadata = {
                            "provider": route.name,
                            "failed_over": route_index > 0,
                            "attempts": attempts,
                        }
                        raise

                    can_retry = (
                        kind in {FailureKind.RATE_LIMIT, FailureKind.TRANSIENT}
                        and attempt_index < route.max_retries
                    )
                    if can_retry:
                        delay = route.retry_base_delay_s * (2 ** attempt_index)
                        logger.warning(
                            "LLM provider %s failed (%s); retrying in %.1fs",
                            route.name,
                            kind.value,
                            delay,
                        )
                        if delay:
                            self._sleep(delay)
                        continue

                    if route_index + 1 < len(self._routes):
                        logger.warning(
                            "LLM provider %s failed (%s); trying fallback %s",
                            route.name,
                            kind.value,
                            self._routes[route_index + 1].name,
                        )
                    break
                else:
                    attempts.append(
                        {
                            "provider": route.name,
                            "attempt": attempt_index + 1,
                            "outcome": "success",
                        }
                    )
                    self.last_metadata = {
                        "provider": route.name,
                        "failed_over": route_index > 0,
                        "attempts": attempts,
                    }
                    return response

        self.last_metadata = {
            "provider": None,
            "failed_over": len(self._routes) > 1,
            "attempts": attempts,
        }
        detail = " | ".join(failures)
        raise LLMFailoverError(f"All configured LLM providers failed: {detail}")

    @staticmethod
    def _brief_error(exc: BaseException) -> str:
        return " ".join(str(exc).split())[:500] or type(exc).__name__
