# Configuration

Reforge is configured through `reforge.yaml`, environment variables, and CLI flags.

## Priority Order

CLI flags > environment variables > YAML configuration > defaults

## Environment Variables

| Variable | Maps to | Description |
|---|---|---|
| `REFORGE_CONFIG` | Config path | Default YAML path used from any working directory |
| `REFORGE_LLM_PROVIDER` | `llm.provider` | Provider name (e.g. claude, codex, gemini) |
| `REFORGE_LLM_API_KEY` | `llm.api_key` | API key for the selected provider |
| `REFORGE_LLM_MODEL` | `llm.model` | Model identifier |
| `REFORGE_LLM_BASE_URL` | `llm.base_url` | Custom API endpoint URL |
| `REFORGE_BACKEND_CLI_PATH` | `backend.cli_path` | Path to the Ghidra bridge executable |
| `REFORGE_BACKEND_TIMEOUT` | `backend.timeout_s` | Backend response timeout in seconds |
| `REFORGE_TOOLS_DIR` | Toolchain root | External tool installation root directory |
| `REFORGE_APKTOOL` | Toolchain path | Custom apktool executable path |
| `REFORGE_APK_SIGNER_JAR` | Toolchain path | Custom uber-apk-signer JAR path |
| `REFORGE_FRIDA_GADGET_DIR` | Toolchain path | Frida Gadget directory or file path |
| `REFORGE_FRIDA_GADGET_VERSION` | Toolchain version | Pinned Frida Gadget version |
| `REFORGE_IL2CPP_DUMPER` | Toolchain path | Custom Il2CppDumper executable path |

On Windows, `scripts/setup_android_tools.ps1` sets tool paths at user scope and adds ADB, JADX, and Il2CppDumper to PATH. Run `reforge doctor` to inspect resolved paths.

When `--config` is omitted, Reforge checks `REFORGE_CONFIG`, `./reforge.yaml`, and the repository checkout root.

## LLM Configuration

```yaml
llm:
  provider: "claude"        # claude | claude-cli | gemini | openai | openai-compat | codex
  model: "claude-sonnet-4-5-20250929"
  api_key: null
  base_url: null
  max_tokens: 4096
  temperature: 0.0
  timeout_s: 1800
  max_retries: 1
  retry_base_delay_s: 1.0
  fallbacks:
    - provider: codex
      model: gpt-5.6-sol
      effort: high
    - provider: antigravity
      model: gemini-3.6-flash
  input_cost_per_million: 0.0
  output_cost_per_million: 0.0
```

Provider details:

- `claude`: Anthropic API via `ANTHROPIC_API_KEY`
- `openai` / `openai-compat`: OpenAI-compatible endpoint via `OPENAI_API_KEY`
- `codex`: Local Codex CLI via authenticated session (`codex exec`). Uses `model: gpt-5.6-sol` and `effort: high`
- `claude-cli`: Local Claude Code CLI session (`claude`)
- `gemini`: Google GenAI API via `GEMINI_API_KEY` or Vertex AI service account JSON
- `fallbacks`: Ordered list of fallback providers if the primary fails with retriable errors

Role-specific overrides allow different models for reverser and checker roles:

```yaml
agents:
  reverser:
    provider: claude-cli
    model: sonnet
    max_budget_usd: 1.0
    effort: high
  checker:
    provider: codex
    model: gpt-5.6-sol
    effort: high
```

## Backend Configuration

```yaml
backend:
  type: ghidra-bridge
  cli_path: ghidra-bridge
  timeout_s: 45
```

Requires `ghidra-ai-bridge` installed and configured.

## Data Handling

External model access is opt-in to prevent accidental leakage of proprietary code:

```yaml
data_handling:
  allow_external_llm: true
  allowed_providers: [gemini, codex, antigravity]
  allow_prompt_logging: false
  allow_evidence_persistence: false
  max_prompt_chars: 120000
```

Prompts are bounded to `max_prompt_chars`. Input binaries are analyzed locally; models receive only structured, bounded summaries.

## Project Profile

```yaml
project_profile:
  name: "generic-cpp"
  language_standard: "C++20"
  source_root: "src"
  source_extensions: [".cpp", ".h", ".hpp"]
```

## Parity Configuration

```yaml
parity:
  enabled: true
  call_count_warn_diff: 3
  inline_wrapper_autoskip: false
```

## Orchestrator Configuration

```yaml
orchestrator:
  max_review_rounds: 4
  max_functions_per_class: 10
  objective_verifier_enabled: true
  objective_call_count_tolerance: 3
  objective_control_flow_tolerance: 2
  investigation_enabled: true
  max_investigations: 8
  selection_strategy: dependency-order # dependency-order | easiest-first | high-impact
  max_attempts_per_function: 3
```

## Candidate Validation

```yaml
validation:
  enabled: true
  copy_project: false
  project_root: .
  build_commands:
    - 'clang++ -fsyntax-only "{candidate_file}"'
  test_commands: []
  runtime_commands: []
  require_build: true
  require_tests: false
  require_runtime: false
  require_verified: true
  allow_host_commands: true
  trust_configured_commands: true
  parity_fail_on_red: true
  parity_fail_on_yellow: false
  command_timeout_s: 900
  working_directory: .
  keep_project_copy: false
```

- When `copy_project: true`, commands run in a temporary directory copy of the project.
- `{candidate_file}`, `{overlay_root}`, and `{source_file}` placeholders are replaced dynamically.
- `allow_host_commands` and `trust_configured_commands` must be true for build commands to execute and count as verification evidence.
