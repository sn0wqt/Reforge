"""Checker agent — verifies reversed code against Ghidra decompilation."""
from __future__ import annotations

import json
import re
from pathlib import Path

from re_agent.backend.protocol import REBackend
from re_agent.core.models import CheckerVerdict, FunctionTarget, Verdict
from re_agent.llm.protocol import LLMProvider, Message
from re_agent.utils.templates import render_template
from re_agent.utils.untrusted import quote_untrusted

PROMPTS_DIR = Path(__file__).parent / "prompts"



class CheckerAgent:
    """Verifies reversed code against Ghidra decompilation."""

    def __init__(
        self,
        llm: LLMProvider,
        backend: REBackend,
        *,
        max_prompt_chars: int = 120_000,
    ) -> None:
        self.llm = llm
        self.backend = backend
        self._conversation_id: str | None = None
        self.last_prompt: str = ""
        self.last_response: str = ""
        self._max_prompt_chars = max(1_000, max_prompt_chars)

    def check(self, code: str, target: FunctionTarget) -> CheckerVerdict:
        """Check reversed code against decompilation. Returns CheckerVerdict."""
        decompile_result = self.backend.decompile(target.address)
        decompiled = decompile_result.raw_output

        system_prompt = render_template(PROMPTS_DIR / "checker_system.md")
        evidence_limit = max(1_000, (self._max_prompt_chars - 2_000) // 2)
        task_prompt = render_template(
            PROMPTS_DIR / "checker_task.md",
            class_name=quote_untrusted(target.class_name, max_chars=512),
            function_name=quote_untrusted(target.function_name, max_chars=512),
            address=quote_untrusted(target.address, max_chars=128),
            reversed_code=quote_untrusted(code, max_chars=evidence_limit),
            decompiled=quote_untrusted(decompiled, max_chars=evidence_limit),
        )
        if len(task_prompt) > self._max_prompt_chars:
            raise ValueError(
                "Checker prompt exceeds data_handling.max_prompt_chars after evidence bounding"
            )

        self.last_prompt = task_prompt

        if self._conversation_id is None and self.llm.supports_conversations:
            self._conversation_id = self.llm.new_conversation(system_prompt)

        if self._conversation_id:
            response = self.llm.resume(self._conversation_id, task_prompt)
        else:
            messages = [
                Message(role="system", content=system_prompt),
                Message(role="user", content=task_prompt),
            ]
            response = self.llm.send(messages)

        self.last_response = response
        return self._parse_verdict(response)

    @staticmethod
    def _parse_verdict(response: str) -> CheckerVerdict:
        json_verdict = CheckerAgent._parse_json_verdict(response)
        if json_verdict is not None:
            return json_verdict
        return CheckerVerdict(
            verdict=Verdict.UNKNOWN,
            summary="Invalid JSON response",
            issues=["Failed to parse checker response."],
            fix_instructions=[],
        )

    @staticmethod
    def _parse_json_verdict(response: str) -> CheckerVerdict | None:
        text = response.strip()
        fenced = re.fullmatch(r"```json\s*\n(?P<body>.*)\n```", text, re.S | re.I)
        if fenced:
            text = fenced.group("body").strip()
        if not text.startswith("{"):
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        raw_verdict = payload.get("verdict")
        if not isinstance(raw_verdict, str):
            return None
        raw_verdict = raw_verdict.upper()
        verdict = {
            "PASS": Verdict.PASS,
            "FAIL": Verdict.FAIL,
        }.get(raw_verdict, Verdict.UNKNOWN)
        issues = payload.get("issues", [])
        fixes = payload.get("fix_instructions", [])
        summary = payload.get("summary", "")
        if (
            not isinstance(summary, str)
            or not isinstance(issues, list)
            or not all(isinstance(item, str) for item in issues)
            or not isinstance(fixes, list)
            or not all(isinstance(item, str) for item in fixes)
        ):
            return None
        if verdict == Verdict.PASS and (issues or fixes):
            verdict = Verdict.UNKNOWN
        return CheckerVerdict(
            verdict=verdict,
            summary=summary,
            issues=list(issues),
            fix_instructions=list(fixes),
        )
