"""OpenAI-compatible LLM provider implementation."""

from __future__ import annotations

from typing import Any

import openai

from reforge.llm.base import BaseLLMProvider
from reforge.llm.protocol import Message


class OpenAIProvider(BaseLLMProvider):
    """LLM provider backed by any OpenAI-compatible API.

    Works with the official OpenAI API as well as any third-party endpoint
    that implements the same ``/v1/chat/completions`` interface (vLLM, Ollama,
    LM Studio, Together, etc.).

    Implements :class:`LLMProvider`.

    Args:
        api_key: API key.  If ``None``, the SDK falls back to the
            ``OPENAI_API_KEY`` environment variable.
        model: Model identifier (e.g. ``"gpt-4o"``).
        max_tokens: Maximum tokens in the response.
        temperature: Sampling temperature (``0.0`` = deterministic).
        base_url: Optional base URL for an OpenAI-compatible endpoint.
        timeout_s: Request timeout in seconds.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        base_url: str | None = None,
        timeout_s: int = 1800,
    ) -> None:
        super().__init__()
        self._client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout_s,
        )
        self.last_metadata: dict[str, Any] = {}
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature

    # -- LLMProvider interface ------------------------------------------------

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        """Send messages via the chat completions API and return the response."""
        api_messages: list[dict[str, str]] = [{"role": m.role, "content": m.content} for m in messages]

        response = self._client.chat.completions.create(
            model=kwargs.get("model", self._model),
            messages=api_messages,  # type: ignore[arg-type]
            max_tokens=kwargs.get("max_tokens", self._max_tokens),
            temperature=kwargs.get("temperature", self._temperature),
        )

        usage = getattr(response, "usage", None)
        self.last_metadata = {"model": self._model, "usage": usage.model_dump() if usage is not None else {}}

        if not response.choices:
            raise RuntimeError("OpenAI-compatible provider returned no choices")
        choice = response.choices[0]
        return choice.message.content or ""
