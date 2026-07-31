# Configuration

re-agent is configured primarily through `re-agent.yaml`, plus the supported
environment variables and runtime CLI flags documented below.

## Priority Order

Supported CLI overrides > supported environment variables > YAML config > defaults

## Environment Variables

| Variable | Maps to |
|----------|---------|
| `RE_AGENT_LLM_PROVIDER` | `llm.provider` |
| `RE_AGENT_LLM_API_KEY` | `llm.api_key` |
| `RE_AGENT_LLM_MODEL` | `llm.model` |
| `RE_AGENT_LLM_BASE_URL` | `llm.base_url` |
| `RE_AGENT_BACKEND_CLI_PATH` | `backend.cli_path` |
| `RE_AGENT_BACKEND_TIMEOUT` | `backend.timeout_s` |

## LLM Config

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

Notes:

- `claude` uses the Anthropic SDK and typically reads `ANTHROPIC_API_KEY`
- `openai` and `openai-compat` use the OpenAI-compatible chat completions provider and typically read `OPENAI_API_KEY`
- `codex` uses the authenticated local `codex exec` CLI instead of an API key.
  It runs read-only and ephemerally; `cli_path` and `effort` are optional. Use
  `model: gpt-5.6-sol` for the GPT-5.6 flagship tier and keep the CLI current
  with `npm install -g @openai/codex@latest`. `effort: high` maps to the Codex
  CLI's `model_reasoning_effort="high"` setting.
- `claude-cli` uses the local Claude Code CLI login. `cli_path`,
  `max_budget_usd`, and `effort` are optional.
- Login-backed CLI providers receive only the minimal path, locale, certificate,
  and auth-cache environment needed to start. API-key and service-account
  variables from another provider are not inherited by their subprocesses.
- `fallbacks` is an ordered, explicit chain. Transient failures are retried
  with exponential backoff up to `max_retries` (0–2), then eligible failures
  move to the next provider. Context-limit, unavailable-tool, and
  authentication failures move immediately. Invalid requests, unknown
  implementation errors, and model safety/policy blocks do not fail over.
- Every fallback is a complete `LLMConfig`; nested fallback chains are rejected.
  The primary remains primary on later calls even when one request used a
  fallback. Provider-attempt metadata records which route answered.

Independent role overrides inherit the top-level `llm` block only when the
role is omitted:

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

A role block inherits omitted fields from the top-level `llm` block.
Provider-specific credentials, model names, endpoint URLs, and CLI paths are
not inherited when the role changes provider; an omitted model then uses that
provider's default.

## Backend Config

```yaml
backend:
  type: ghidra-bridge
  cli_path: ghidra-bridge
  timeout_s: 45
```

The `ghidra-ai-bridge` package installs the `ghidra-bridge` executable. Prepare
its exports separately before running reversal commands.

## Data Handling

External model use is denied by default. Authorize each provider only after
reviewing where proprietary source, decompilation, metadata, and binary strings
will be processed:

```yaml
data_handling:
  allow_external_llm: true
  allowed_providers: [gemini, codex, antigravity]
  allow_prompt_logging: false
  allow_evidence_persistence: false
  max_prompt_chars: 120000
```

Provider authorization is checked independently for reverser, checker,
batch-analysis roles, and every fallback route. Prompt/response logging remains
disabled unless separately enabled.

The configured `max_prompt_chars` bounds each agent evidence prompt before it
reaches a provider. Multi-turn history is also bounded and drops the oldest
complete review turns first while preserving the system prompt and newest
request. Large binary files are parsed locally; providers receive bounded
evidence summaries rather than the complete binary.

## Project Profile

The `project_profile` section makes re-agent work across different RE projects.
This example is specifically for GTA-reversed-style source:

```yaml
project_profile:
  hook_patterns:
    - 'RH_ScopedInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)'
  stub_markers: ["NOTSA_UNREACHABLE"]
  stub_call_prefix: "plugin::Call"
  source_root: "./source/game_sa"
  source_extensions: [".cpp", ".h", ".hpp"]
```

## Parity Config

```yaml
parity:
  enabled: true
  call_count_warn_diff: 3
  inline_wrapper_autoskip: false
```

## Orchestrator Config

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

Generated code is written to a safe overlay. Commands can use both format
placeholders and environment variables.

```yaml
validation:
  enabled: true
  # true copies the project to a temporary isolated directory before commands
  copy_project: false
  project_root: .
  build_commands:
    - 'clang++ -fsyntax-only "{candidate_file}"'
  test_commands: []
  runtime_commands: [] # optional differential/record-replay harness
  require_build: true
  require_tests: false
  require_runtime: false
  require_verified: true # UNKNOWN validation results block acceptance
  allow_host_commands: false # separate consent to execute shell commands
  trust_configured_commands: false # explicit attestation for project-owned shell gates
  environment_allowlist: # provider credentials are not inherited
    - PATH
    - PATHEXT
    - SYSTEMROOT
    - COMSPEC
    - TEMP
    - TMP
  parity_fail_on_red: true
  parity_fail_on_yellow: false
  command_timeout_s: 900
  working_directory: .
  keep_project_copy: false # delete isolated full-project copies after validation
```

With `copy_project: true`, the default working directory becomes the isolated
project copy and the source candidate replaces the real relative source file.
Configure the project inside that copy (for example `cmake -S . -B build`)
before building because generated `build/` directories are intentionally not copied.
With it disabled, build commands must consume `{candidate_file}` or
`RE_AGENT_CANDIDATE_FILE` explicitly.

Shell commands are user-defined and cannot be proven meaningful merely by
inspecting their text. They therefore produce `UNKNOWN` until
`trust_configured_commands: true` explicitly attests that the configured
project commands compile/test the candidate. The non-isolated placeholder
check is an additional mistake detector, not a semantic proof.

Commands are not executed at all unless `allow_host_commands: true` is also
set. A copied project is a temporary isolation boundary for source mutation,
not an operating-system or network sandbox.

The `reverse` command performs this acceptance preflight before constructing
an LLM provider. If `require_verified: true` cannot possibly produce `PASS`
(for example, there are no commands, host execution is disabled, or the
commands have not been explicitly trusted), it exits before spending model
tokens. Configure real project gates or deliberately set
`require_verified: false`; the latter permits unverified results and must not
be interpreted as build/runtime proof.
