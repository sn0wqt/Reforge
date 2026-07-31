"""Codex CLI-backed LLM provider using saved Codex authentication."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from re_agent.llm.base import BaseLLMProvider
from re_agent.llm.protocol import Message
from re_agent.utils.process import sanitized_cli_environment


class CodexCLIProvider(BaseLLMProvider):
    """Run the local ``codex exec`` CLI in read-only, ephemeral mode."""

    def __init__(
        self,
        model: str | None = None,
        timeout_s: int = 600,
        codex_bin: str = "codex",
        effort: str | None = None,
    ) -> None:
        super().__init__()
        self._model = model
        self._timeout_s = timeout_s
        self._codex_bin = shutil.which(codex_bin) or codex_bin
        self._effort = effort

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        """Send messages through ``codex exec`` and return its final message."""
        prompt = self._render_messages(messages)
        model = kwargs.get("model", self._model)
        with tempfile.TemporaryDirectory(prefix="re-agent-codex-") as temporary:
            run_directory = Path(temporary)
            out_path = run_directory / "last-message.txt"
            command = [
                self._codex_bin,
                "exec",
                "--sandbox",
                "read-only",
                "--color",
                "never",
                "--skip-git-repo-check",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--output-last-message",
                str(out_path),
            ]
            if model:
                command.extend(["--model", str(model)])
            if self._effort:
                effort_value = json.dumps(self._effort)
                command.extend(["--config", f"model_reasoning_effort={effort_value}"])
            # Passing the prompt on stdin avoids command-line length limits and
            # prevents prompt contents from appearing in process listings.
            command.append("-")

            try:
                proc = subprocess.run(
                    command,
                    input=prompt,
                    cwd=run_directory,
                    env=sanitized_cli_environment(),
                    capture_output=True,
                    text=True,
                    timeout=self._timeout_s,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"codex exec timed out after {self._timeout_s}s") from exc
            except FileNotFoundError as exc:
                raise RuntimeError(f"Codex CLI not found: {self._codex_bin}") from exc
            except OSError as exc:
                raise RuntimeError(f"Could not run Codex CLI: {self._codex_bin}") from exc
            if proc.returncode != 0:
                detail = proc.stderr.strip() or proc.stdout.strip() or "no error details"
                raise RuntimeError(
                    f"codex exec failed with exit code {proc.returncode}\n{detail}"
                )

            response = (
                out_path.read_text(encoding="utf-8").strip()
                if out_path.is_file()
                else ""
            )
            if not response:
                response = proc.stdout.strip()
            if not response:
                raise RuntimeError("codex exec completed without a final response")
            return response
