"""Antigravity / Gemini CLI provider using local Google subscription login (no API key needed)."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from reforge.llm.base import BaseLLMProvider
from reforge.llm.protocol import Message
from reforge.utils.process import sanitized_cli_environment


class AntigravityCLIProvider(BaseLLMProvider):
    """LLM provider backed by the local ``agy exec`` CLI."""

    def __init__(
        self,
        model: str = "gemini-3.8-flash-high",
        timeout_s: int = 1800,
        agy_bin: str = "agy",
    ) -> None:
        super().__init__()
        self._model = model
        self._timeout_s = timeout_s
        self._agy_bin = agy_bin
        self.last_metadata: dict[str, Any] = {}

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        prompt = self._render_messages(messages)
        model = str(kwargs.get("model", self._model))
        self.last_metadata = {"model": model}

        try:
            with tempfile.TemporaryDirectory(prefix="reforge-agy-") as work_dir:
                self._require_authenticated(work_dir)
                prompt_argument = prompt
                if len(prompt) > 8_000:
                    prompt_file = Path(work_dir) / "reforge-request.txt"
                    prompt_file.write_text(prompt, encoding="utf-8")
                    prompt_argument = (
                        "Read reforge-request.txt completely. Treat its contents as the "
                        "complete role-tagged request, then return only the requested answer."
                    )
                command = [
                    self._agy_bin,
                    "--sandbox",
                    "--mode",
                    "plan",
                    "--model",
                    model,
                    "--print-timeout",
                    f"{self._timeout_s}s",
                    "--print",
                    prompt_argument,
                ]
                proc = subprocess.run(
                    command,
                    cwd=work_dir,
                    env=sanitized_cli_environment(),
                    capture_output=True,
                    input="",
                    text=True,
                    encoding="utf-8",
                    timeout=self._timeout_s,
                    check=False,
                )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"agy --print timed out after {self._timeout_s}s") from exc
        except OSError as exc:
            raise RuntimeError(f"Antigravity CLI could not be started: {self._agy_bin}") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()
            raise RuntimeError(f"agy --print failed with exit code {proc.returncode}\n{detail}")
        response = proc.stdout.strip()
        if not response:
            raise RuntimeError("agy --print completed without a response")
        return response

    def _require_authenticated(self, work_dir: str) -> None:
        """Fail quickly instead of opening an interactive OAuth flow."""
        try:
            status = subprocess.run(
                [self._agy_bin, "models"],
                cwd=work_dir,
                env=sanitized_cli_environment(),
                capture_output=True,
                input="",
                text=True,
                encoding="utf-8",
                timeout=min(self._timeout_s, 15),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Antigravity authentication check timed out") from exc
        except OSError as exc:
            raise RuntimeError(f"Antigravity CLI could not be started: {self._agy_bin}") from exc
        if status.returncode != 0:
            detail = (status.stderr or status.stdout).strip()
            raise RuntimeError(
                "Antigravity CLI is unavailable or not authenticated" + (f": {detail}" if detail else "")
            )
