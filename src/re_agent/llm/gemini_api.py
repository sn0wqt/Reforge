"""Google Gemini API provider — supports API key AND Vertex AI service account auth."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from re_agent.llm.base import BaseLLMProvider
from re_agent.llm.protocol import Message

logger = logging.getLogger(__name__)


class GeminiProvider(BaseLLMProvider):
    """LLM provider for Google Gemini models using the official `google-genai` SDK.

    Supports AI Studio API-key auth and Vertex AI service-account auth.
    An alternate Gemini account is used only when explicitly enabled.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-2.5-flash",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        base_url: str | None = None,
        service_account_file: str | None = None,
        timeout_s: int = 600,
        allow_provider_fallback: bool = False,
    ) -> None:
        super().__init__()
        from google import genai
        from google.genai import types

        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._allow_provider_fallback = allow_provider_fallback
        http_options = types.HttpOptions(
            timeout=timeout_s * 1000,
            base_url=base_url,
        )

        self._client: genai.Client | None = None
        self._fallback_client: genai.Client | None = None
        self._auth_mode: str = "unconfigured"

        explicit_sa_path = Path(service_account_file).expanduser() if service_account_file else None
        environment_sa = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        environment_sa_path = Path(environment_sa).expanduser() if environment_sa else None
        sa_path = explicit_sa_path or environment_sa_path
        resolved_key = api_key or os.environ.get("GEMINI_API_KEY")

        # An explicitly configured service account is authoritative and never
        # mutates GOOGLE_APPLICATION_CREDENTIALS process-wide.
        if explicit_sa_path is not None:
            self._client = self._create_vertex_client(
                genai,
                explicit_sa_path,
                http_options,
            )
            self._auth_mode = "vertex"
            if resolved_key and allow_provider_fallback:
                self._fallback_client = genai.Client(
                    api_key=resolved_key,
                    http_options=http_options,
                )
        elif resolved_key:
            self._client = genai.Client(
                api_key=resolved_key,
                http_options=http_options,
            )
            self._auth_mode = "apikey"
            if sa_path is not None and allow_provider_fallback:
                self._fallback_client = self._create_vertex_client(
                    genai,
                    sa_path,
                    http_options,
                )
        elif sa_path is not None:
            self._client = self._create_vertex_client(
                genai,
                sa_path,
                http_options,
            )
            self._auth_mode = "vertex"

        if self._client is None:
            raise RuntimeError(
                "No Gemini credentials found. Provide GEMINI_API_KEY or "
                "service_account_file. Configure an explicit llm.fallbacks chain "
                "for cross-provider failover."
            )

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        system_prompt = "\n\n".join(m.content for m in messages if m.role == "system")
        contents = self._conversation_contents(messages)
        want_json = "json" in system_prompt.lower() or any(
            "json" in message.content.lower() for message in messages if message.role != "system"
        )

        try:
            return self._generate_with_client(self._client, contents, system_prompt, want_json)
        except Exception as exc:
            from re_agent.llm.failover import FailureKind, classify_provider_failure

            failure_kind = classify_provider_failure(exc)
            may_change_gemini_account = failure_kind in {
                FailureKind.RATE_LIMIT,
                FailureKind.TRANSIENT,
                FailureKind.UNAVAILABLE,
            }

            if may_change_gemini_account and self._fallback_client:
                logger.warning(
                    "[GeminiProvider] Primary client failed; explicit account fallback is enabled (%s)",
                    exc,
                )
                fallback = self._fallback_client
                return self._generate_with_client(
                    fallback,
                    contents,
                    system_prompt,
                    want_json,
                )
            raise

    def _generate_with_client(
        self,
        client: Any,
        contents: list[dict[str, Any]],
        system_prompt: str,
        want_json: bool,
    ) -> str:
        if client is None:
            raise RuntimeError("Gemini client is None")

        config: dict[str, Any] = {
            "system_instruction": system_prompt if system_prompt else None,
            "max_output_tokens": self._max_tokens,
            "temperature": self._temperature,
        }
        if want_json:
            config["response_mime_type"] = "application/json"

        # Remove None values
        config = {k: v for k, v in config.items() if v is not None}

        response = client.models.generate_content(
            model=self._model,
            contents=contents,
            config=config,
        )
        return response.text or ""

    @staticmethod
    def _conversation_contents(messages: list[Message]) -> list[dict[str, Any]]:
        """Preserve user/assistant turn boundaries for the Gemini API."""
        contents: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "system":
                continue
            if message.role not in {"user", "assistant"}:
                raise ValueError(f"Unsupported message role: {message.role!r}")
            role = "model" if message.role == "assistant" else "user"
            part = {"text": message.content}
            if contents and contents[-1]["role"] == role:
                contents[-1]["parts"].append(part)
            else:
                contents.append({"role": role, "parts": [part]})
        if not contents:
            raise ValueError("Gemini request requires at least one non-system message")
        return contents

    @staticmethod
    def _create_vertex_client(
        genai: Any,
        service_account_path: Path,
        http_options: Any,
    ) -> Any:
        if not service_account_path.is_file():
            raise RuntimeError(f"Gemini service-account file does not exist: {service_account_path}")
        try:
            from google.oauth2 import service_account

            credentials = service_account.Credentials.from_service_account_file(  # type: ignore[no-untyped-call]
                str(service_account_path.resolve()),
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
        except Exception as exc:
            raise RuntimeError(f"Could not load Gemini service-account credentials: {service_account_path}") from exc
        project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or credentials.project_id
        if not project_id:
            raise RuntimeError("Gemini Vertex credentials do not identify a Google Cloud project")
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "global")
        return genai.Client(
            vertexai=True,
            credentials=credentials,
            project=project_id,
            location=location,
            http_options=http_options,
        )
