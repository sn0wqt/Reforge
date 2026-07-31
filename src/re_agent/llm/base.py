"""Base class for LLM providers eliminating duplicate conversation and message rendering code."""

from __future__ import annotations

import uuid
from typing import Any

from re_agent.llm.protocol import Message

_MAX_CONVERSATION_MESSAGES = 64
_MAX_CONVERSATION_CHARS = 240_000


class BaseLLMProvider:
    """Abstract base provider providing conversation management and message formatting."""

    def __init__(self, *, max_conversation_chars: int = _MAX_CONVERSATION_CHARS) -> None:
        self._conversations: dict[str, list[Message]] = {}
        self._max_conversation_chars = max(1_000, max_conversation_chars)

    @property
    def supports_conversations(self) -> bool:
        """All derived providers support multi-turn client-side conversation state."""
        return True

    def new_conversation(self, system: str) -> str:
        """Start a new conversation with a system prompt."""
        cid = uuid.uuid4().hex
        self._conversations[cid] = [Message(role="system", content=system)]
        return cid

    def resume(self, conversation_id: str, message: str) -> str:
        """Append a user message to the conversation and return the assistant's response."""
        history = self._conversations.get(conversation_id)
        if history is None:
            raise KeyError(f"Unknown conversation ID: {conversation_id}")

        pending = self._bounded_messages([*history, Message(role="user", content=message)])
        response_text = self.send(pending)
        history.extend(
            [
                Message(role="user", content=message),
                Message(role="assistant", content=response_text),
            ]
        )
        history[:] = self._bounded_messages(history)
        return response_text

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        """Send messages and return response text. Override in subclass."""
        raise NotImplementedError

    @staticmethod
    def _render_messages(messages: list[Message]) -> str:
        """Format messages into a standard prompt string."""
        return "\n\n".join(f"[{message.role.upper()}]\n{message.content.strip()}" for message in messages).strip()

    def _bounded_messages(self, messages: list[Message]) -> list[Message]:
        """Drop oldest complete turns while preserving system and newest input.

        Individual task prompts are bounded by the agents. This second bound
        prevents replayed multi-turn history from growing without limit.
        """
        bounded = list(messages)
        while len(bounded) > _MAX_CONVERSATION_MESSAGES or self._message_chars(bounded) > self._max_conversation_chars:
            first_non_system = next(
                (index for index, item in enumerate(bounded) if item.role != "system"),
                len(bounded),
            )
            # Always retain at least the newest non-system message.
            if len(bounded) - first_non_system <= 1:
                break
            remove_count = 1
            if (
                len(bounded) - first_non_system >= 3
                and bounded[first_non_system].role == "user"
                and bounded[first_non_system + 1].role == "assistant"
            ):
                remove_count = 2
            del bounded[first_non_system : first_non_system + remove_count]
        return bounded

    @staticmethod
    def _message_chars(messages: list[Message]) -> int:
        return sum(len(item.role) + len(item.content) + 4 for item in messages)
