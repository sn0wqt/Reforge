"""Unit tests for GeminiProvider auth modes and fallbacks."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from re_agent.llm.gemini_api import GeminiProvider


def test_gemini_provider_api_key_mode() -> None:
    provider = GeminiProvider(api_key="test_key_123")
    assert provider._auth_mode == "apikey"


def test_gemini_provider_service_account_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    sa_file = tmp_path / "sa.json"
    sa_file.write_text("""{
        "type": "service_account",
        "project_id": "test-project",
        "private_key": "fake",
        "client_email": "test@test.iam.gserviceaccount.com"
    }""")

    credentials = SimpleNamespace(project_id="test-project")
    with (
        patch("google.genai.Client"),
        patch(
            "google.oauth2.service_account.Credentials.from_service_account_file",
            return_value=credentials,
        ),
    ):
        provider = GeminiProvider(service_account_file=str(sa_file))
        assert provider._auth_mode == "vertex"


def test_gemini_provider_does_not_hide_cross_provider_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)

    with pytest.raises(RuntimeError, match="explicit llm.fallbacks"):
        GeminiProvider(api_key=None, allow_provider_fallback=True)


def test_gemini_provider_no_creds_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)

    with patch("shutil.which", return_value=None), pytest.raises(
        RuntimeError,
        match="No Gemini credentials found",
    ):
        GeminiProvider(api_key=None)


def test_gemini_provider_auth_precedence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test_key")
    sa_file = tmp_path / "sa.json"
    sa_file.write_text("{}")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa_file))

    credentials = SimpleNamespace(project_id="test-project")
    with (
        patch(
            "google.oauth2.service_account.Credentials.from_service_account_file",
            return_value=credentials,
        ),
    ):
        # 1. API key takes precedence
        provider = GeminiProvider(api_key=None)
        assert provider._auth_mode == "apikey"

        # 2. Vertex AI (via SA)
        monkeypatch.delenv("GEMINI_API_KEY")
        provider = GeminiProvider(api_key=None, allow_provider_fallback=True)
        assert provider._auth_mode == "vertex"

        # 3. Cross-provider fallback must be configured in LLMConfig.
        monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS")
        with pytest.raises(RuntimeError, match="explicit llm.fallbacks"):
            GeminiProvider(api_key=None, allow_provider_fallback=True)


def test_gemini_preserves_conversation_roles() -> None:
    from re_agent.llm.protocol import Message

    provider = GeminiProvider(api_key="test_key")
    contents = provider._conversation_contents(
        [
            Message(role="system", content="system"),
            Message(role="user", content="first"),
            Message(role="assistant", content="answer"),
            Message(role="user", content="second"),
        ]
    )

    assert [content["role"] for content in contents] == ["user", "model", "user"]
    assert contents[1]["parts"][0]["text"] == "answer"


def test_gemini_keeps_configured_model_and_http_options() -> None:
    with patch("google.genai.Client") as client:
        provider = GeminiProvider(
            api_key="test_key",
            model="gemini-3.6-flash",
            base_url="https://example.invalid",
            timeout_s=12,
        )

    assert provider._model == "gemini-3.6-flash"
    options = client.call_args.kwargs["http_options"]
    assert options.base_url == "https://example.invalid"
    assert options.timeout == 12000


def test_gemini_http_options_are_valid_sdk_options() -> None:
    from google.genai import types

    options = types.HttpOptions(timeout=5000, base_url="https://example.invalid")
    assert options.model_dump(exclude_none=True)["base_url"] == "https://example.invalid"


def test_gemini_fallback_does_not_replace_primary_client(monkeypatch) -> None:
    from re_agent.llm.protocol import Message

    provider = GeminiProvider(api_key="test_key")
    primary = object()
    fallback = object()
    provider._client = primary  # type: ignore[assignment]
    provider._fallback_client = fallback  # type: ignore[assignment]
    calls: list[object] = []

    def generate(client, contents, system_prompt, want_json):
        calls.append(client)
        if client is primary:
            raise RuntimeError("429 RESOURCE_EXHAUSTED")
        return "fallback response"

    monkeypatch.setattr(provider, "_generate_with_client", generate)

    messages = [Message(role="user", content="hello")]
    assert provider.send(messages) == "fallback response"
    assert provider.send(messages) == "fallback response"
    assert calls == [primary, fallback, primary, fallback]
    assert provider._client is primary
    assert provider._fallback_client is fallback


def test_gemini_safety_block_never_uses_alternate_account(monkeypatch) -> None:
    from re_agent.llm.protocol import Message

    provider = GeminiProvider(api_key="test_key")
    fallback = object()
    provider._fallback_client = fallback  # type: ignore[assignment]
    calls: list[object] = []

    def generate(client, contents, system_prompt, want_json):
        del contents, system_prompt, want_json
        calls.append(client)
        raise RuntimeError("403 request BLOCKED FOR SAFETY by content policy")

    monkeypatch.setattr(provider, "_generate_with_client", generate)

    with pytest.raises(RuntimeError, match="BLOCKED FOR SAFETY"):
        provider.send([Message(role="user", content="hello")])
    assert calls == [provider._client]
