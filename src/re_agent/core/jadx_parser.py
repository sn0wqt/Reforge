"""JADX and Smali bytecode decompiler parser for Android Kotlin and Java DEX applications."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from re_agent.utils.toolchain import resolve_jadx


def parse_smali_instructions(smali_text: str) -> list[dict[str, Any]]:
    """Parse Smali assembly instructions (.method, .field, invoke-virtual, const/4)."""
    methods: list[dict[str, Any]] = []
    method_pattern = re.compile(r"\.method\s+([^\n]+)\n(.*?)\.end method", re.DOTALL)
    invoke_pattern = re.compile(
        r"invoke-(?:virtual|direct|static|super|interface|polymorphic)(?:/range)?"
        r"\s+\{([^}]*)\},\s*L([^;]+);->([^\(]+)(\([^\)]*\)[^\s,]+)"
    )
    custom_invoke_pattern = re.compile(
        r"invoke-custom(?:/range)?\s+\{([^}]*)\},\s*(.+)$",
        re.MULTILINE,
    )

    for match in method_pattern.finditer(smali_text):
        method_sig = match.group(1).strip()
        body = match.group(2)

        invokes: list[dict[str, str]] = []
        for inv in invoke_pattern.finditer(body):
            invokes.append(
                {
                    "registers": inv.group(1).strip(),
                    "class_name": inv.group(2).strip(),
                    "method_name": inv.group(3).strip(),
                    "descriptor": inv.group(4).strip(),
                }
            )
        for inv in custom_invoke_pattern.finditer(body):
            call_site = inv.group(2).strip()
            invokes.append(
                {
                    "registers": inv.group(1).strip(),
                    "class_name": "",
                    "method_name": call_site.split("(", 1)[0].strip(),
                    "descriptor": call_site,
                }
            )

        methods.append(
            {
                "signature": method_sig,
                "invokes": invokes,
                "body_lines": [line.strip() for line in body.splitlines() if line.strip()],
            }
        )

    return methods


def decompile_apk_or_dex(target_file: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Decompile an Android .apk or .dex file into Kotlin/Java source code using JADX CLI if available."""
    target_path = Path(target_file)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    jadx_path = resolve_jadx()
    if jadx_path is None:
        err_msg = (
            "JADX executable not found in PATH. Install JADX (github.com/skylot/jadx) to decompile Kotlin/DEX files."
        )
        return {
            "success": False,
            "error": err_msg,
            "output_dir": str(out_path),
        }

    try:
        cmd = [str(jadx_path), "-d", str(out_path), str(target_path)]
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        return {
            "success": res.returncode == 0,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "output_dir": str(out_path),
        }
    except (OSError, subprocess.TimeoutExpired) as e:
        return {
            "success": False,
            "error": str(e),
            "output_dir": str(out_path),
        }
