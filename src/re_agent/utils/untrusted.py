"""Prompt-safe serialization for evidence recovered from untrusted binaries."""

from __future__ import annotations

import json


def quote_untrusted(value: object, *, max_chars: int) -> str:
    """Serialize bounded evidence as one JSON string, never as prompt instructions."""
    text = str(value).replace("\x00", "\uFFFD")
    if len(text) > max_chars:
        omitted = len(text) - max_chars
        text = f"{text[:max_chars]}\n[TRUNCATED {omitted} CHARACTERS]"
    return json.dumps(text, ensure_ascii=True)
