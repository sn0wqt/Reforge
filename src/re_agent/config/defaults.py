"""Default configuration templates for re-agent."""
from __future__ import annotations

from typing import Any

DEFAULT_CONFIG_YAML: str = """\
# re-agent configuration
# See: https://github.com/dryxio/auto-re-agent for documentation.

project_profile:
  name: "gta-reversed"
  language_standard: "C++23"
  prompt_rules:
    - "Use real member names from the existing project and reference headers"
    - "Never call virtual methods on this inside hook implementations"
    - "Use matrix.TransformVector(vec) instead of deprecated Multiply3x3"
    - "Verify struct offsets against project VALIDATE_OFFSET checks"
  hook_patterns:
    - "RH_ScopedInstall\\\\s*\\\\(\\\\s*(\\\\w+)\\\\s*,\\\\s*(0x[0-9A-Fa-f]+)"
    - "RH_ScopedVirtualInstall\\\\s*\\\\(\\\\s*(\\\\w+)\\\\s*,\\\\s*(0x[0-9A-Fa-f]+)"
  stub_patterns:
    - "plugin::Call"
  stub_markers:
    - "NOTSA_UNREACHABLE"
  stub_call_prefix: "plugin::Call"
  class_macro: "RH_ScopedClass"
  source_root: "source/game_sa"
  source_extensions:
    - ".cpp"
    - ".h"
    - ".hpp"
  hooks_csv: "docs/hooks.csv"

llm:
  provider: "codex"
  model: "gpt-5.6-sol"
  cli_path: "codex"
  effort: "high"
  timeout_s: 600
  max_retries: 0
  fallbacks:
    - provider: "gemini"
      model: "gemini-3.6-flash"
      service_account_file: "credentials/vertex-sa.json"
      timeout_s: 600
    - provider: "antigravity"
      model: "gemini-3.6-flash"
      cli_path: "agy"
  input_cost_per_million: 0.0
  output_cost_per_million: 0.0

agents:
  reverser:
    provider: "gemini"
    model: "gemini-3.6-flash"
    service_account_file: "credentials/vertex-sa.json"
    timeout_s: 600
    fallbacks:
      - provider: "codex"
        model: "gpt-5.6-sol"
        cli_path: "codex"
        effort: "high"
      - provider: "antigravity"
        model: "gemini-3.6-flash"
        cli_path: "agy"

  checker:
    provider: "codex"
    model: "gpt-5.6-sol"
    cli_path: "codex"
    effort: "high"
    timeout_s: 600
    fallbacks:
      - provider: "gemini"
        model: "gemini-3.6-flash"
        service_account_file: "credentials/vertex-sa.json"
        timeout_s: 600
      - provider: "antigravity"
        model: "gemini-3.6-flash"
        cli_path: "agy"

backend:
  type: "ghidra-bridge"
  cli_path: "ghidra-bridge"
  timeout_s: 45

parity:
  enabled: true
  call_count_warn_diff: 3
  inline_wrapper_autoskip: false
  # semantic_rules_file: null
  # manual_checks_file: null
  cache_dir: ".cache/re-agent-parity"

orchestrator:
  max_review_rounds: 4
  max_functions_per_class: 10
  objective_verifier_enabled: true
  objective_call_count_tolerance: 3
  objective_control_flow_tolerance: 2
  investigation_enabled: true
  max_investigations: 8
  selection_strategy: "dependency-order"
  max_attempts_per_function: 3

validation:
  enabled: true
  copy_project: false
  project_root: "."
  build_commands: []
  test_commands: []
  runtime_commands: []
  require_build: false
  require_tests: false
  require_runtime: false
  # UNKNOWN (for example, no configured commands) is not accepted by default.
  require_verified: true
  # Separate execution consent from whether passing commands count as proof.
  allow_host_commands: false
  # Arbitrary shell commands are only evidence after an explicit trust decision.
  trust_configured_commands: false
  # Secrets and provider credentials are not inherited by validation commands.
  environment_allowlist:
    - "PATH"
    - "PATHEXT"
    - "SYSTEMROOT"
    - "COMSPEC"
    - "TEMP"
    - "TMP"
    - "HOME"
    - "USERPROFILE"
    - "LANG"
    - "LC_ALL"
  parity_fail_on_red: true
  parity_fail_on_yellow: false
  command_timeout_s: 900
  working_directory: "."
  keep_project_copy: false

data_handling:
  # Reverse-engineering evidence may contain proprietary or sensitive code.
  allow_external_llm: true
  allowed_providers:
    - "codex"
    - "codex-cli"
    - "gemini"
    - "google-gemini"
    - "antigravity"
    - "antigravity-cli"
    - "claude"
    - "claude-cli"
  allow_prompt_logging: false
  allow_evidence_persistence: false
  max_prompt_chars: 120000

output:
  report_dir: "reports/re-agent"
  log_dir: "reports/re-agent/logs"
  session_file: "re-agent-progress.json"
  format: "json"
"""

EXAMPLE_PROFILE_TEMPLATES: dict[str, dict[str, Any]] = {
    "generic-cpp": {
        "name": "generic-cpp",
        "language_standard": "C++20",
        "prompt_rules": [
            "Preserve the detected ABI, calling convention, widths, and signedness",
            "Use evidence-backed names and retain address-based placeholders when unresolved",
        ],
        "hook_patterns": [],
        "stub_patterns": [r"TODO|NOT_IMPLEMENTED"],
        "stub_markers": ["NOT_IMPLEMENTED"],
        "stub_call_prefix": "__re_agent_no_stub_prefix__",
        "class_macro": "",
        "source_root": "src",
        "source_extensions": [".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"],
        "hooks_csv": None,
    },
    "windows-x64": {
        "name": "windows-x64",
        "language_standard": "C++20",
        "prompt_rules": [
            "Assume the Microsoft x64 ABI only when supported by binary metadata",
            "Preserve SEH-visible behavior and distinguish direct from indirect calls",
        ],
        "hook_patterns": [],
        "stub_patterns": [r"TODO|NOT_IMPLEMENTED"],
        "stub_markers": ["NOT_IMPLEMENTED"],
        "stub_call_prefix": "__re_agent_no_stub_prefix__",
        "class_macro": "",
        "source_root": "src",
        "source_extensions": [".cpp", ".cc", ".cxx", ".h", ".hpp"],
        "hooks_csv": None,
    },
    "gta-reversed": {
        "name": "gta-reversed",
        "language_standard": "C++23",
        "prompt_rules": [
            "Use real member names from the existing project and reference headers",
            "Never call virtual methods on this inside hook implementations",
            "Use matrix.TransformVector(vec) instead of deprecated Multiply3x3",
            "Verify struct offsets against project VALIDATE_OFFSET checks",
        ],
        "hook_patterns": [
            r"RH_ScopedInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)",
            r"RH_ScopedVirtualInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)",
        ],
        "stub_patterns": [
            r"plugin::Call",
        ],
        "stub_markers": [
            "NOTSA_UNREACHABLE",
        ],
        "stub_call_prefix": "plugin::Call",
        "class_macro": "RH_ScopedClass",
        "source_root": "source/game_sa",
        "source_extensions": [".cpp", ".h", ".hpp"],
        "hooks_csv": "docs/hooks.csv",
    },
    "openrct2": {
        "name": "openrct2",
        "language_standard": "C++20",
        "prompt_rules": [],
        "hook_patterns": [
            r"HOOK_FUNCTION\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)",
        ],
        "stub_patterns": [
            r"original_function\(",
        ],
        "stub_markers": [
            "NOT_IMPLEMENTED",
        ],
        "stub_call_prefix": "original_function",
        "class_macro": "",
        "source_root": "src",
        "source_extensions": [".cpp", ".h", ".hpp"],
        "hooks_csv": None,
    },
    "ios-arm64": {
        "name": "ios-arm64",
        "language_standard": "C++20",
        "prompt_rules": [
            "Preserve ARM64 calling conventions (X0-X7 registers, FP/LR frame pointers)",
            "Account for Objective-C runtime Messaging (objc_msgSend) and Swift ABI metadata if present",
            "Maintain 8-byte structure alignment for 64-bit iOS pointers",
        ],
        "hook_patterns": [],
        "stub_patterns": [r"TODO|NOT_IMPLEMENTED"],
        "stub_markers": ["NOT_IMPLEMENTED"],
        "stub_call_prefix": "__re_agent_no_stub_prefix__",
        "class_macro": "",
        "source_root": "src",
        "source_extensions": [".cpp", ".mm", ".m", ".cc", ".h", ".hpp"],
        "hooks_csv": None,
    },
    "android-arm64": {
        "name": "android-arm64",
        "language_standard": "C++20",
        "prompt_rules": [
            "Preserve AAPCS64 (ARM64 Android) ABI conventions and alignment",
            "Account for Android NDK C++ STL types and JNI native method signatures (Java_...)",
            "Maintain 8-byte pointer alignment for .so shared libraries",
        ],
        "hook_patterns": [],
        "stub_patterns": [r"TODO|NOT_IMPLEMENTED"],
        "stub_markers": ["NOT_IMPLEMENTED"],
        "stub_call_prefix": "__re_agent_no_stub_prefix__",
        "class_macro": "",
        "source_root": "src",
        "source_extensions": [".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"],
        "hooks_csv": None,
    },
    "linux-x64": {
        "name": "linux-x64",
        "language_standard": "C++20",
        "prompt_rules": [
            "Assume System V AMD64 ABI (RDI, RSI, RDX, RCX, R8, R9 argument passing)",
            "Preserve ELF dynamic linking symbol resolution and mangled C++ names",
        ],
        "hook_patterns": [],
        "stub_patterns": [r"TODO|NOT_IMPLEMENTED"],
        "stub_markers": ["NOT_IMPLEMENTED"],
        "stub_call_prefix": "__re_agent_no_stub_prefix__",
        "class_macro": "",
        "source_root": "src",
        "source_extensions": [".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"],
        "hooks_csv": None,
    },
}
