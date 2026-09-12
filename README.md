# Reforge

[![CI](https://github.com/sn0wqt/Reforge/actions/workflows/ci.yml/badge.svg)](https://github.com/sn0wqt/Reforge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`Reforge` is an open-source AI reverse-engineering agent that uses Ghidra
and LLMs—including Claude, Codex, and OpenAI-compatible models—to reconstruct
and validate C/C++ functions from compiled binaries. It combines independent
reverser/checker models, agentic evidence gathering, candidate build and test
gates, structural verification, and parity analysis in one autonomous workflow.

## What it does

```text
re-agent reverse --class CTrain
    │
    ├── Configuration (YAML + supported environment overrides + CLI flags)
    ├── Function selection (dependency-order | easiest-first | high-impact)
    ├── Source and binary context
    │   ├── decompile, xrefs, structs, enums, vtables, globals, and strings
    │   └── normalized high P-code, CFG, assembly, and nearby project source
    ├── Reverser → checker → fix loop (bounded rounds and investigations)
    ├── Conservative structural verifier
    ├── Candidate overlay
    │   └── configured build, test, and runtime gates
    ├── Candidate parity gate (GREEN | YELLOW | RED)
    └── Reports, per-round logs, session history, and knowledge graph
```

The tool generates candidate C/C++ implementations; it does not patch the
original source tree automatically. A successful reversal can require four
independent conditions:

1. the LLM checker returns `PASS`;
2. the objective verifier finds no strong structural mismatch;
3. candidate validation satisfies the configured acceptance policy;
4. parity is not blocked by the configured RED/YELLOW policy.

This is conservative verification, not a proof of semantic equivalence.

## Requirements

- Python 3.10+
- Git, for the current source installation
- Ghidra plus a configured
  [ghidra-ai-bridge](https://github.com/sn0wqt/ghidra-ai-bridge)
- At least one LLM setup:
  - Claude API: `ANTHROPIC_API_KEY`
  - OpenAI-compatible API: `OPENAI_API_KEY`
  - Claude CLI: an authenticated local `claude` command
  - Codex CLI: an authenticated local `codex` command

## Installation

Install the agent and its Ghidra query bridge from PyPI:

```bash
python3 -m pip install --upgrade "reforge[providers,ghidra-bridge]>=0.3.0"
```

For headless Ghidra exports, install the bridge with its PyGhidra extra:

```bash
python3 -m pip install --upgrade "reforge[providers,headless]>=0.3.0"
```

To install the latest development versions directly from GitHub instead:

```bash
python3 -m pip install --upgrade \
  "ghidra-ai-bridge @ git+https://github.com/sn0wqt/ghidra-ai-bridge.git@main" \
  "reforge[providers] @ git+https://github.com/sn0wqt/Reforge.git@main"
```

## Android one-time setup

On Windows, APK analysis/repackaging expects `apktool`, Java, and Frida to be
on `PATH`. Once those three prerequisites are present, the repository setup
script installs and configures everything else:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_android_tools.ps1

# Open a new terminal so the persistent PATH/environment updates are visible.
re-agent doctor
```

The script installs the following under
`%LOCALAPPDATA%\Reforge\tools` and does not add the downloaded binaries
to Git:

| Tool | Installed version | Used for |
|---|---:|---|
| uber-apk-signer | 1.3.0 | Aligning, signing, and verifying rebuilt APKs |
| Frida Gadget | 17.16.4, all four Android ABIs | Non-root runtime instrumentation |
| Android platform-tools | 37.0.1 | `adb install`, port forwarding, and device communication |
| JADX | 1.5.6 | Deeper Java/Kotlin/DEX decompilation |
| Il2CppDumper | 6.7.46 | Unity IL2CPP metadata sidecar generation |

The installer verifies pinned SHA-256 values before extracting anything,
stores an `install-manifest.json`, persists the required environment variables,
and deletes its temporary ZIP downloads. Frida CLI and Gadget must remain on
the same version. The currently pinned pair is:

```powershell
python -m pip install --upgrade "frida==17.16.4" "frida-tools==14.10.4"
```

Upstream sources: [Frida releases](https://github.com/frida/frida/releases),
[Frida Gadget documentation](https://frida.re/docs/gadget/),
[Android platform-tools](https://developer.android.com/tools/releases/platform-tools),
[uber-apk-signer](https://github.com/patrickfav/uber-apk-signer/releases),
[JADX](https://github.com/skylot/jadx/releases), and
[Il2CppDumper](https://github.com/Perfare/Il2CppDumper/releases).

### Which command should I use?

| Goal | Command |
|---|---|
| Check whether the machine is ready | `re-agent doctor` |
| Find and rank targets from an APK/dump | `re-agent batch --binary app.apk --goal "..."` |
| Run detection, analysis, hook generation, and optional packaging | `re-agent pipeline --binary app.apk --goal "..."` |
| Build a signed non-root Gadget APK | `re-agent pipeline --binary app.apk --goal "..." --embed-frida-gadget` |
| Generate or launch a live logging trace | `re-agent trace --class CLASS --symbol METHOD ...` |
| Deeply reconstruct functions from Ghidra/IL2CPP evidence | `re-agent reverse --address RVA` or `re-agent reverse --class CLASS` |

`pipeline` is the normal end-to-end APK command. `batch` is candidate discovery
without packaging. `trace` observes a running app; it does not search a dump.
`reverse` is the multi-round reverser/checker reconstruction workflow, not a
replacement for `pipeline`.

### Non-root Android workflow

After setup, no signer or Gadget path is required:

```powershell
re-agent pipeline `
  --binary "C:\path\game.apk" `
  --goal "give infinite coins" `
  --embed-frida-gadget
```

The pipeline automatically selects the managed Gadget directory matching the
local Frida version, covers every ABI present in the APK, rebuilds and signs
the APK, and verifies that the loader and Gadget bytes survived signing. Then:

```powershell
adb install "C:\path\app_output\modded_app-aligned-signed.apk"
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -n Gadget -l "C:\path\app_output\Hook_Frida.js"
```

If the original app is installed with a different certificate, Android will
normally require uninstalling it first, which removes that app's local data.
Without a user-supplied release keystore, uber-apk-signer uses its debug-signing
mode; the result is suitable for local testing, not Play Store distribution.
Signature pinning, anti-tamper logic, split delivery, or Play Integrity may
still reject a rebuilt APK; setup tooling cannot truthfully guarantee otherwise.

## Set up Ghidra evidence

Run these commands from the project you want to reverse:

```bash
# Create ghidra-bridge.yaml, then edit its Ghidra project/program paths
ghidra-bridge init

# Requires the bridge headless extra and a local Ghidra installation
ghidra-bridge export all

# Optional but recommended when reversed source/hook patterns are available
ghidra-bridge build-map

# Confirm that exports and configuration are visible
ghidra-bridge info
```

See the [bridge documentation](https://github.com/sn0wqt/ghidra-ai-bridge)
for its Ghidra, export, and source-map configuration.

## Quick start

Create a configuration in the target project:

```bash
# Recommended portable default
re-agent init --profile generic-cpp

# Other available profiles
# re-agent init --profile windows-x64
# re-agent init --profile gta-reversed
# re-agent init --profile openrct2
```

Running `re-agent init` without `--profile` preserves the original
GTA-reversed defaults. Prefer an explicit profile for new projects.

Then edit `re-agent.yaml`. At minimum, select an LLM, point the backend at the
installed bridge executable, set the source paths, and configure validation.

```yaml
llm:
  provider: claude-cli
  model: sonnet

# Optional: use a different provider/model for checking.
agents:
  checker:
    provider: codex
    model: gpt-5.6-sol
    effort: high

backend:
  type: ghidra-bridge
  cli_path: ghidra-bridge

project_profile:
  name: generic-cpp
  language_standard: C++20
  source_root: src
  hooks_csv: null

orchestrator:
  max_review_rounds: 4
  investigation_enabled: true
  max_investigations: 8
  selection_strategy: dependency-order
  max_attempts_per_function: 3

validation:
  enabled: true
  copy_project: true
  project_root: .
  build_commands:
    - cmake -S . -B build
    - cmake --build build
  test_commands:
    - ctest --test-dir build --output-on-failure
  require_build: true
  require_tests: true
  require_verified: true
  # Separate consent to execute project-owned commands on this host.
  allow_host_commands: true
  # This explicitly attests that the project-owned shell commands above are
  # meaningful validation gates. Leave false for untrusted commands.
  trust_configured_commands: true
  keep_project_copy: false
  parity_fail_on_red: true
  parity_fail_on_yellow: false
```

Validation is deliberately strict: with the generated defaults, no configured
commands produce `UNKNOWN`, and `require_verified: true` rejects that result.
For exploration without build validation, explicitly set
`validation.enabled: false`; such results are not build-verified.

Start with one function before launching a class run:

```bash
re-agent reverse --address 0x401000
re-agent reverse --class CTrain --max-functions 10
re-agent status
```

## LLM providers

### Claude API

```yaml
llm:
  provider: claude
  model: claude-sonnet-4-5-20250929
```

Set `ANTHROPIC_API_KEY` or `RE_AGENT_LLM_API_KEY`.

### Claude CLI

Authenticate the local Claude Code CLI first, then configure:

```yaml
llm:
  provider: claude-cli
  model: sonnet
  cli_path: claude
  effort: high
  max_budget_usd: 1.0
```

Claude CLI supports real session resume and reports usage/cost metadata. A
stale CLI login can still require re-authentication even when its auth-status
command reports a session.

### OpenAI-compatible APIs

```yaml
llm:
  provider: openai # or openai-compat
  model: your-model
  base_url: https://your-endpoint.example/v1 # optional
```

Set `OPENAI_API_KEY` or `RE_AGENT_LLM_API_KEY`.

### Codex CLI

Install Codex CLI, authenticate it once, and verify the saved session:

```bash
codex --version
codex login
codex login status
```

Then select the provider:

```yaml
llm:
  provider: codex
  model: gpt-5.6-sol
  cli_path: codex
  effort: high
```

Codex uses the authenticated local `codex exec` command; it does not use
`api_key` or `service_account_file`. Reforge sends prompts over stdin and runs
Codex with a read-only sandbox and ephemeral session storage. CLI-provider
`max_tokens` values are planning allowances, not hard output limits. The
recommended quality-first checker pin is `gpt-5.6-sol`; `effort: high` becomes
Codex's `model_reasoning_effort="high"` setting. Keep Codex CLI current:

```bash
npm install -g @openai/codex@latest
```

If the server reports that the model requires a newer Codex version, Reforge
classifies that route as unavailable so an explicitly configured operational
fallback can continue.

You can also keep Gemini as the top-level provider and use Codex only as the
independent checker:

```yaml
llm:
  provider: gemini
  model: gemini-3.6-flash
  service_account_file: credentials/vertex-sa.json

agents:
  checker:
    provider: codex
    model: gpt-5.6-sol
    effort: high
```

These are two different mechanisms:

- `agents.checker` makes Codex independently review Gemini's proposed source
  against the binary evidence. A checker `PASS` is still only one acceptance
  gate; objective, build/test/runtime, and parity gates remain separate.
- `llm.fallbacks` handles operational failure for one request. It does not
  bypass safety/policy blocks or silently turn an unverified answer into a
  verified one.

For a fast-primary, independent-checker, operational-fallback setup:

```yaml
llm:
  provider: gemini
  model: gemini-3.6-flash
  service_account_file: credentials/vertex-sa.json
  max_retries: 1
  fallbacks:
    - provider: codex
      model: gpt-5.6-sol
      cli_path: codex
      effort: high
      max_retries: 0
    - provider: antigravity
      model: gemini-3.6-flash
      cli_path: agy
      max_retries: 0

agents:
  checker:
    provider: codex
    model: gpt-5.6-sol
    cli_path: codex
    effort: high
```

Rate-limit and transient failures retry with bounded exponential backoff.
Context-limit, missing-tool, and authentication failures move directly to the
next configured route. Invalid requests, unknown implementation failures, and
model safety/policy blocks stop instead of provider-shopping. Each provider
keeps its own model, credentials, endpoint, and CLI path.

Omit `agents.reverser` or `agents.checker` to reuse the top-level `llm`
configuration for that role. Same-provider role blocks inherit omitted
non-sensitive fields from `llm`.
Switching providers never carries credentials, endpoints, CLI paths, or model
identifiers across the provider boundary.

External model use is denied by default because binary/source evidence may be
proprietary. Explicitly authorize the provider boundary in the same config:

```yaml
data_handling:
  allow_external_llm: true
  allowed_providers: [gemini, codex, antigravity]
  allow_prompt_logging: false
  allow_evidence_persistence: false
  max_prompt_chars: 120000
```

Large binaries are parsed locally. Agents receive bounded decompilation,
metadata, and string-evidence summaries, never an unbounded binary or dump.
The semantic metadata payload remains valid JSON while capped at 60,000
characters, individual agent prompts are capped by `max_prompt_chars`, and
old complete conversation turns are discarded before replay can grow without
bound. A genuine provider context-limit response can therefore fail over, but
the fallback receives the same bounded evidence; it does not invent missing
analysis or silently truncate the newest request.

## Evidence and investigation

When supported by the backend, the reverser preloads a bounded evidence bundle
and can request additional read-only operations:

- `decompile`, `xrefs_from`, and `xrefs_to`
- `struct` and `enum`
- `vtable`, `global`, and `strings`
- `context`, normalized `pcode`, and `cfg`

When `data_handling.allow_evidence_persistence` is explicitly enabled, evidence
bundle data is also ingested into
`reports/re-agent/knowledge-graph.json`, connecting functions, calls, globals,
and strings. It stays in memory otherwise. Unsupported bridge capabilities
degrade gracefully.

## Candidate validation

Generated code is written to an overlay. With `copy_project: true`, the project
is copied to a temporary directory, the candidate replaces the matching body
there, and commands run from that copy. `.git`, `.venv`, `build`, `reports`, and
Python cache files are not copied. Temporary project copies are deleted unless
`keep_project_copy: true`.

Commands may use:

- `{candidate_file}`, `{overlay_root}`, and `{source_file}` placeholders;
- `RE_AGENT_CANDIDATE_FILE`, `RE_AGENT_OVERLAY_ROOT`, and
  `RE_AGENT_SOURCE_FILE` environment variables.

Configured build/test/runtime commands are arbitrary project-owned shell
commands. The agent cannot prove from their text that they actually validate a
candidate, so they only become acceptance evidence when
`trust_configured_commands: true` is set explicitly.

If multiple C++ definitions match an overloaded method and the source cannot be
disambiguated, the overlay is rejected instead of replacing an arbitrary body.

## Verification and parity

The objective verifier runs on each review round. It compares generated code
with available decompile, assembly, CFG, and normalized high P-code evidence.
It returns `FAIL` only for strong mismatches; insufficient evidence returns
`UNKNOWN`.

The reversal pipeline runs the 11 built-in heuristic parity signals against the
generated candidate body. RED is blocking by default; YELLOW can be made
blocking with `validation.parity_fail_on_yellow`.

The standalone command is different: `re-agent parity` analyzes functions in
the existing source tree. It also supports semantic-rule files and manual check
overrides. Its process exit code remains zero on RED unless `--strict-exit` is
used.

The 11 built-in signals are:

| Signal | Level | Description |
|---|---|---|
| Missing source | RED | No source body was found |
| Stub markers | RED | Source contains a configured stub marker |
| Trivial stub | RED | Small plugin-call-heavy body with no control flow |
| Large ASM, tiny source | RED | Large disassembly with a very small source body |
| Plugin-call heavy | YELLOW | Plugin calls dominate the source body |
| Short body | YELLOW | Body has fewer than six lines |
| Low call count | YELLOW | Decompiled callees greatly exceed source calls |
| FP sensitivity | YELLOW | Assembly has FP-sensitive operations but source has no math tokens |
| Call-count mismatch | YELLOW | Source and assembly call counts differ beyond the configured threshold |
| NaN logic | YELLOW | Decompile indicates NaN-sensitive behavior missing from source |
| Inline wrapper | INFO | Source forwards to an internal implementation |

The signal set is fixed in `0.3.0`; configuration exposes selected thresholds,
inline-wrapper behavior, semantic rules, and manual overrides rather than an
individual toggle for every signal.

## CLI reference

Global options must precede the subcommand, for example
`re-agent --config custom.yaml status`.

| Command | Purpose |
|---|---|
| `re-agent doctor [--json]` | Verify analysis, packaging, Gadget, and ADB tooling |
| `re-agent init --profile generic-cpp` | Create `re-agent.yaml` from a profile |
| `re-agent reverse --address ADDR` | Reverse one function |
| `re-agent reverse --class CLASS --max-functions N` | Reverse a bounded class batch |
| `re-agent reverse --class CLASS --dry-run` | Show a target plan without LLM calls |
| `re-agent reverse ... --max-rounds N --skip-parity` | Override loop/parity behavior |
| `re-agent parity --address ADDR --strict-exit` | Analyze an existing source function |
| `re-agent parity --filter REGEX --limit N --output report.json` | Filter and export parity results |
| `re-agent parity ... --skip-ghidra` | Run source-only parity signals |
| `re-agent status --class CLASS --format text` | Show session progress |
| `re-agent estimate --address ADDR` | Estimate one function |
| `re-agent estimate --class CLASS --limit N` | Estimate a class batch |
| `re-agent batch --binary FILE --goal TEXT --limit N` | Rank a complete local candidate inventory and semantically refine a bounded shortlist |
| `re-agent pipeline --binary FILE --goal TEXT --no-repack` | Generate pathway-aware candidate reports and review hook scaffolds |
| `re-agent pipeline --metadata-dir DIR --platform ios --goal TEXT --no-repack` | Analyze a metadata-only IL2CPP dump with an explicit platform when auto-detection is ambiguous |
| `re-agent trace --class CLASS --symbol METHOD --assembly Assembly-CSharp` | Generate a Frida trace script |
| `re-agent trace ... --attach PROCESS --usb` | Generate the script and attach it through the local Frida CLI |
| `re-agent pipeline --binary app.apk --goal TEXT --embed-frida-gadget` | Use the managed matching Gadget binaries, rebuild, sign, and verify an Android APK |

Use `re-agent <command> --help` for the exact option list.

Pipeline reports retain the complete evidence-ranked candidate inventory.
Generated hook files stay bounded: active blocks require complete readiness
evidence, and at most 20 additional candidates are included as commented
review blocks. This keeps `Hook_Goal.cpp` and `Hook_Frida.js` usable even when
a binary exposes thousands of keyword-adjacent members.

Supplying `--goal` to `batch` or `pipeline` automatically runs semantic
refinement through the configured LLM route when `data_handling` authorizes
every provider in that route. There is no separate `--llm` switch. The model
receives only the bounded local shortlist, and policy denial, quota exhaustion,
timeouts, or provider errors leave deterministic local discovery running.

Native addresses and offsets are never equated with mutation safety. An
IL2CPP/native RVA may be displayed as verified address evidence, but generated
native interceptors log only until the return ABI, calling convention, module
lifecycle, and replacement behavior have been independently verified. The
narrow active path is an exact executable Java/DEX method with a recovered
descriptor and primitive return type.

## Configuration precedence

The effective order is CLI runtime overrides, supported environment variables,
`re-agent.yaml`, then dataclass defaults. The currently supported environment
variables are:

- `RE_AGENT_LLM_PROVIDER`
- `RE_AGENT_LLM_API_KEY`
- `RE_AGENT_LLM_MODEL`
- `RE_AGENT_LLM_BASE_URL`
- `RE_AGENT_BACKEND_CLI_PATH`
- `RE_AGENT_BACKEND_TIMEOUT`
- `RE_AGENT_TOOLS_DIR`
- `RE_AGENT_APKTOOL`
- `RE_AGENT_APK_SIGNER_JAR`
- `RE_AGENT_FRIDA_GADGET_DIR`
- `RE_AGENT_FRIDA_GADGET_VERSION`
- `RE_AGENT_IL2CPP_DUMPER`

Role-specific `agents.*` configuration, validation, project profiles, parity,
and output paths should be configured in YAML.

See [docs/configuration.md](docs/configuration.md) for the complete schema.

## Profiles

- `generic-cpp`: portable C/C++ defaults
- `windows-x64`: Microsoft x64-oriented prompt rules
- `linux-x64`: System V AMD64-oriented prompt rules
- `android-arm64`: Android AAPCS64-oriented prompt rules
- `ios-arm64`: Apple ARM64-oriented prompt rules
- `gta-reversed`: GTA-reversed hooks, stubs, source paths, and project rules
- `openrct2`: OpenRCT2-oriented hook/stub patterns

Profiles initialize project configuration; they do not replace bridge exports
or project-specific validation commands.

## Outputs

Default artifacts include:

- `reports/re-agent/code/`: final generated code per function
- `reports/re-agent/logs/`: per-round reverser/checker prompts, responses, and provider metadata
- `reports/re-agent/candidates/`: non-isolated candidate overlays
- `reports/re-agent/knowledge-graph.json`: persistent evidence graph
- `re-agent-progress.json`: current per-function state plus run history

The session file is atomically rewritten on save. Its `functions` map stores the
latest state per address, while its `runs` list preserves recorded attempts.

## How it compares

| Approach | Primary use | Evidence and validation | Workflow |
|---|---|---|---|
| Traditional decompiler | Translate machine code into analyst-readable pseudocode | Decompiler analysis; correctness is assessed manually | Function-by-function analysis |
| Interactive Ghidra AI or MCP assistant | Let an analyst ask questions and request Ghidra operations | Depends on the analyst, prompts, and connected tools | Human-directed conversation |
| `Reforge` | Generate and validate candidate C/C++ implementations | Ghidra evidence, independent checker, structural checks, configured build/tests, and parity signals | Bounded autonomous reverser/checker pipeline with persistent reports |

`Reforge` complements Ghidra rather than replacing it: Ghidra supplies
the program analysis, while the agent orchestrates evidence collection,
implementation, review, validation, and reporting. It is designed for
repeatable project-scale workflows, not just one-off decompiler chat.

## Frequently asked questions

### Is Reforge a decompiler?

Not in the traditional sense. Ghidra performs the disassembly, decompilation,
and program analysis. `Reforge` uses that evidence plus project source
context and LLMs to produce and validate candidate C/C++ implementations.

### Does it require Ghidra?

The full binary-backed reversal workflow currently uses Ghidra through
`ghidra-ai-bridge`. Existing source can be checked with source-only parity via
`re-agent parity --skip-ghidra`, but that mode has less evidence.

### Which LLM providers are supported?

Claude API, Claude CLI, Gemini API/Vertex AI, OpenAI-compatible APIs, Codex
CLI, and AntiGravity CLI are supported. The reverser and checker can use
different providers or models, and an explicit ordered fallback chain can be
configured independently.

### Does it modify the original source tree?

No. Generated implementations are written to reports and candidate overlays.
When isolated validation is enabled, builds and tests run in a temporary copy
of the project.

### Can it prove that generated source is equivalent to the binary?

No. The checker, structural verifier, configured build/test gates, and parity
signals provide conservative evidence, not a formal proof of semantic or
binary equivalence.

### What binaries and projects can it analyze?

It can work with programs that Ghidra can import and that the bridge can export.
Useful reconstruction also depends on project-specific source context, types,
symbols, validation commands, and the evidence available in the target binary.

### How are LLM cost and run length controlled?

Review rounds, investigations, and attempts per function are bounded in the
configuration. Provider logs record available usage and cost metadata; actual
cost depends on the selected models, evidence volume, and target complexity.

## Safety and limitations

- Reforge does not commit or push generated code;
- candidate generation does not overwrite the original source tree;
- review rounds, evidence actions, and per-function attempts are bounded;
- prompt/response logs are written per review round, not for every internal
  evidence-loop call;
- configured validation commands execute through `/bin/sh` on Unix and a
  detected Git shell or `cmd.exe` on Windows; they should only be enabled when
  controlled by the project owner;
- a pipeline exit code of zero means its declared analysis/artifact stages
  completed; `pipeline_manifest.json` separately records that runtime hook
  installation and runtime behavior remain unverified;
- structural and parity checks catch useful mismatches but do not prove binary
  equivalence;
- real Ghidra/PyGhidra integration depends on the local Ghidra project and has
  to be tested in that environment.

## Why ghidra-ai-bridge stays separate

`ghidra-ai-bridge` remains an independent analysis package with a versioned
JSON/CLI evidence surface. Reforge consumes it through a capability-based
backend, leaving room for future IDA, Binary Ninja, or other backends.

## Development

```bash
git clone https://github.com/sn0wqt/Reforge.git
git clone https://github.com/sn0wqt/ghidra-ai-bridge.git
cd Reforge

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e "../ghidra-ai-bridge[headless]"
python3 -m pip install -e ".[dev]"

pytest -q
ruff check src tests
mypy src
```

## License

MIT
