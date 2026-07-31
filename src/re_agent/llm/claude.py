"""Claude (Anthropic) LLM provider implementation."""

from __future__ import annotations

from typing import Any

import anthropic

from re_agent.llm.base import BaseLLMProvider
from re_agent.llm.protocol import Message


class ClaudeProvider(BaseLLMProvider):
    """LLM provider backed by the Anthropic Claude API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-5-20250929",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        timeout_s: int = 600,
    ) -> None:
        super().__init__()
        self._client = anthropic.Anthropic(api_key=api_key, timeout=timeout_s)
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        api_messages: list[dict[str, str]] = []
        system_text: str | None = None

        for msg in messages:
            if msg.role == "system":
                system_text = msg.content
            else:
                api_messages.append({"role": msg.role, "content": msg.content})

        create_kwargs: dict[str, Any] = {
            "model": kwargs.get("model", self._model),
            "max_tokens": kwargs.get("max_tokens", self._max_tokens),
            "temperature": kwargs.get("temperature", self._temperature),
            "messages": api_messages,
        }
        if system_text is not None:
            create_kwargs["system"] = system_text

        response = self._client.messages.create(**create_kwargs)

        # Extract text from content blocks.
        parts: list[str] = []
        for block in response.content:
            if hasattr(block, "text"):
                parts.append(block.text)
        return "\n".join(parts)
