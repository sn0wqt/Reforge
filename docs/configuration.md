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
  provider: "cliproxy"        # cliproxy | codex | claude | gemini | openai | openai-compat
  model: "gemini-3.8-flash-high"
  api_key: null
  base_url: null
  max_tokens: 4096
  temperature: 0.0
  timeout_s: 600
  max_retries: 1
  retry_base_delay_s: 1.0
  fallbacks:
    - provider: codex
      model: gpt-6.1-sol
      effort: high
    - provider: antigravity
      model: gemini-3.8-flash-high
  input_cost_per_million: 0.0
  output_cost_per_million: 0.0
```

Provider details:

- `cliproxy`: Local CLIProxyAPI gateway (`http://127.0.0.1:8317/v1`) using Antigravity OAuth and auto-detected `CLIPROXY_API_KEY`
- `codex`: Local Codex CLI via authenticated session (`codex exec`). Uses `model: gpt-6.1-sol` and `effort: high`
- `claude`: Anthropic API via `ANTHROPIC_API_KEY`
- `claude-cli`: Local Claude Code CLI session (`claude`)
- `gemini`: Google GenAI API via `GEMINI_API_KEY` or Vertex AI service account JSON
- `openai` / `openai-compat`: OpenAI-compatible endpoint via `OPENAI_API_KEY`
- `fallbacks`: Ordered list of fallback providers if the primary fails with retriable errors

Role-specific overrides configure separate models for the reverser (heavy reconstruction) and checker (verification review):

```yaml
agents:
  reverser:
    provider: cliproxy
    model: gemini-3.8-flash-high
    timeout_s: 600
  checker:
    provider: cliproxy
    model: gpt-6.1-sol
    timeout_s: 600
```

## Backend Configuration

```yaml
backend:
  type: ghidra-bridge
  cli_path: ghidra-bridge
  timeout_s: 45
```

Requires [ghidra-bridge](https://github.com/Dryxio/ghidra-bridge) (`ghidra-ai-bridge`) installed and configured to communicate with your Ghidra instance.

## Data Handling

External model access is opt-in to prevent accidental leakage of proprietary code:

```yaml
data_handling:
  allow_external_llm: true
  allowed_providers: [cliproxy, codex, gemini, antigravity]
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

### Portable validation commands

Each build/test/runtime command may be a legacy POSIX shell string or an argument
array. Arrays execute directly, without a shell, on Windows and POSIX:

```yaml
validation:
  build_commands:
    - [cmake, -S, "{overlay_root}", -B, "{overlay_root}/build"]
    - [cmake, --build, "{overlay_root}/build"]
  test_commands:
    - [ctest, --test-dir, "{overlay_root}/build", --output-on-failure]
```

Arguments support `{candidate_file}`, `{overlay_root}`, and `{source_file}`.
Spaces and shell metacharacters remain literal data; `$VAR` and shell syntax are
not expanded in arrays. Legacy strings still require `/bin/sh`; `reforge doctor` reports
when it is missing. Existing isolation and command-trust requirements still
apply. Non-isolated arrays must explicitly include a candidate/overlay placeholder.

### Differential validation

Differential harness commands use argument arrays, without shell expansion. Each
harness reads one JSON value from stdin and emits one JSON value describing the
observed behavior. Include return values, modified memory and relevant effects in
that result. Comparison is exact; normalize address-dependent values or floating
point representations in the project-owned adapters when appropriate.

```yaml
validation:
  differential_reference: [/path/to/reference-harness]
  differential_candidate: ['{overlay_root}/candidate-harness']
  differential_cases_file: /path/to/cases.json
  trust_configured_commands: true
```

The cases file must be a nonempty JSON array. Timeouts, invalid JSON, nonzero exits
and mismatches fail the gate and are fed back to the reverser.

A benchmark manifest is a JSON array of objects with `name`, `reference`,
`candidate`, and `cases`. Optional `expected_match: false` marks a negative control;
`timeout_s` defaults to 30. Run with `reforge benchmark --manifest benchmark.json`.

### Optional evidence gaps

Function-context bundles and per-function Ghidra JSON exports may include `gaps`:

```json
{"function":"0x140001000","site":"0x140001010","kind":"unresolved_call",
 "reason":"Indirect register call target not resolved","origin":"analysis-export"}
```

Kinds are `unavailable`, `unsupported`, `query_failed`, `unresolved_call`, and
`limit`. The site is optional. Addresses are hexadecimal strings of unrestricted
width. Labels describe observations; they do not establish recovered semantics.
Old exports remain supported; absent caller/callee fields produce unavailable records
while explicitly empty lists describe a known empty result. Reforge does not invent targets.

### Bounded target manifests

`reforge plan --address 0x140001000 --max-depth 2 --max-functions 50 --output group.json`
creates a deterministic inventory without model calls. Repeat `--address` or use
`--match` with the backend's symbol-search syntax. Seeds are visited first, then
direct callees breadth-first. Cycles and duplicates are visited once. Depth zero
includes only seeds but still records their observed direct dependencies.

The manifest stores the existing project fingerprint, selected function identity,
selection depth, full returned decompilation/context evidence, direct call edges,
and explicit gaps. Limits describe incomplete exploration, never completeness.

Run a reviewed manifest with `reforge reverse --manifest group.json --max-functions 5`.
`--dry-run` checks input identity and displays the inventory without model calls.
Manifest mode is exclusive with `--address` and `--class`. Existing retry limits,
acceptance rules, sessions, and cumulative scratch validation apply across class boundaries.

### Searchable stored evidence

`reforge evidence --manifest group.json --output packets` writes an index,
per-function JSON packets, a copy of the input manifest, and function/call/
reference/gap TSV files. This reads stored manifest evidence only: it needs no
backend, LLM, or configuration file and makes no claim about current binary state.
Use a new or empty destination. TSV cells escape backslashes, tabs, carriage
returns, and newlines.

### Manifest coverage

`reforge status --manifest group.json --format json` reconciles every selected
function with existing session results. Primary statuses are `unattempted`,
`attempted` (checkpoint only), `accepted`, `failed`, and `stale`; their counts sum
to the planned inventory. Input mismatch marks recorded work stale.

