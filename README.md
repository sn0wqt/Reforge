# Reforge

[![CI](https://github.com/sn0wqt/Reforge/actions/workflows/ci.yml/badge.svg)](https://github.com/sn0wqt/Reforge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Reforge is an automated reverse-engineering agent that uses Ghidra and LLMs (Claude, Codex, Gemini, OpenAI) to reconstruct and validate C/C++ functions from compiled binaries. It pairs independent reverser and checker models with structural verification, candidate builds, and parity analysis.

## Overview

```text
reforge reverse --class CTrain
    │
    ├── Configuration (reforge.yaml + environment variables + CLI flags)
    ├── Function selection (dependency-order | easiest-first | high-impact)
    ├── Context extraction
    │   ├── Decompilation, xrefs, structs, enums, vtables, globals, strings
    │   └── P-code, control flow graph, assembly, nearby source
    ├── Reverser -> checker -> fix loop (bounded review rounds)
    ├── Structural verification
    ├── Candidate overlay (isolated build, test, and runtime gates)
    ├── Parity evaluation (GREEN / YELLOW / RED)
    └── Reports, logs, session state, and knowledge graph
```

Generated code is placed in isolated candidate overlays rather than modifying the original project repository directly.

## Requirements

- Python 3.10+
- Git
- Ghidra with [ghidra-bridge](https://github.com/Dryxio/ghidra-bridge)
- An authenticated LLM provider:
  - Local CLIProxyAPI (recommended for Antigravity Gemini and Codex models)
  - Codex CLI (`codex`)
  - Claude API (`ANTHROPIC_API_KEY`) or Claude CLI (`claude`)
  - OpenAI-compatible API (`OPENAI_API_KEY`)
  - Gemini API (`GEMINI_API_KEY` or Vertex AI credentials)

## Installation

Clone the repository and install Reforge locally in editable mode:

```bash
git clone https://github.com/sn0wqt/Reforge.git
cd Reforge
python3 -m pip install -e ".[dev,providers]"
```

If using Ghidra as your decompiler backend, install `ghidra-ai-bridge`:

```bash
python3 -m pip install "ghidra-ai-bridge @ git+https://github.com/Dryxio/ghidra-bridge.git@main"
```

## Android Toolchain Setup

Basic static analysis does not require external Android tools. Web bundle repacking requires Java and an APK signer. Frida Gadget embedding and manifest/smali modifications require `apktool`.

Run the automated installer on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_android_tools.ps1
reforge doctor
```

The script installs tools into `%LOCALAPPDATA%\Reforge\tools`:

| Tool | Version | Purpose |
|---|---:|---|
| uber-apk-signer | 1.3.0 | Aligning, signing, and verifying APKs |
| Frida Gadget | 17.16.4 | Android runtime instrumentation (arm, arm64, x86, x86_64) |
| Android platform-tools | 37.0.1 | `adb install`, port forwarding, and device debugging |
| JADX | 1.5.6 | Java/Kotlin decompilation and manual review |
| Il2CppDumper | 6.7.46 | Unity IL2CPP metadata sidecar extraction |

Install matching Frida host tools:

```powershell
python -m pip install --upgrade "frida==17.16.4" "frida-tools==14.10.4"
```

## Commands Summary

| Goal | Command |
|---|---|
| Check toolchain readiness | `reforge doctor` |
| Rank targets from an APK or dump | `reforge batch --binary app.apk --goal "..."` |
| Full pipeline analysis and hook generation | `reforge pipeline --binary app.apk --goal "..."` |
| Build signed non-root Gadget APK | `reforge pipeline --binary app.apk --goal "..." --embed-frida-gadget` |
| Live Frida tracing | `reforge trace --class CLASS --symbol METHOD ...` |
| Reconstruct C/C++ functions from Ghidra | `reforge reverse --address RVA` or `reforge reverse --class CLASS` |
| Check source parity against disassembly | `reforge parity --address RVA --strict-exit` |

## Quick Start

Initialize project configuration:

```bash
reforge init --profile generic-cpp
```

Available profiles: `generic-cpp`, `windows-x64`, `linux-x64`, `android-arm64`, `ios-arm64`, `gta-reversed`, `openrct2`.

Configure `reforge.yaml`:

```yaml
llm:
  provider: claude-cli
  model: sonnet

backend:
  type: ghidra-bridge
  cli_path: ghidra-bridge

project_profile:
  name: generic-cpp
  language_standard: C++20
  source_root: src

orchestrator:
  max_review_rounds: 4
  investigation_enabled: true
  max_investigations: 8
  selection_strategy: dependency-order

validation:
  enabled: true
  copy_project: true
  build_commands:
    - cmake -S . -B build
    - cmake --build build
  test_commands:
    - ctest --test-dir build --output-on-failure
  require_build: true
  require_tests: true
  require_verified: true
  allow_host_commands: true
  trust_configured_commands: true
```

Run reversal:

```bash
# Single function
reforge reverse --address 0x401000

# Class batch
reforge reverse --class CTrain --max-functions 10

# Session status
reforge status
```

## LLM Providers

### Claude API

```yaml
llm:
  provider: claude
  model: claude-sonnet-4-5-20250929
```
Requires `ANTHROPIC_API_KEY` or `REFORGE_LLM_API_KEY`.

### Claude CLI

```yaml
llm:
  provider: claude-cli
  model: sonnet
  cli_path: claude
  effort: high
  max_budget_usd: 1.0
```

### OpenAI Compatible

```yaml
llm:
  provider: openai
  model: your-model
  base_url: https://your-endpoint.example/v1
```
Requires `OPENAI_API_KEY` or `REFORGE_LLM_API_KEY`.

### CLIProxyAPI / Antigravity

Connects to local CLIProxyAPI (`http://127.0.0.1:8317/v1`) using your authenticated Antigravity session and auto-detected `CLIPROXY_API_KEY`:

```yaml
llm:
  provider: cliproxy
  model: gemini-3.8-flash-high
```

### Codex CLI

```yaml
llm:
  provider: codex
  model: gpt-6.1-sol
  cli_path: codex
  effort: high
```
Uses local `codex exec` with an authenticated session.

### Multi-Model Reverser and Checker

Both models route through local CLIProxyAPI (`http://127.0.0.1:8317/v1`) using Antigravity and Codex authentication. Reconstruct functions with Gemini 3.8 Flash High and run independent verification checks with GPT 6.1 Sol:

```yaml
agents:
  reverser:
    provider: cliproxy
    model: gemini-3.8-flash-high
  checker:
    provider: cliproxy
    model: gpt-6.1-sol
```

### Data Handling Policy

External model access is opt-in by default:

```yaml
data_handling:
  allow_external_llm: true
  allowed_providers: [cliproxy, codex, gemini, claude]
  allow_prompt_logging: false
  allow_evidence_persistence: false
  max_prompt_chars: 120000
```

## Android Workflows

### Split APK and XAPK Repackaging

Reforge accepts directories or ZIP/XAPK/APKS archives containing `base.apk` and configuration splits:

```powershell
reforge pipeline `
  --binary "C:\path\app.xapk" `
  --goal "unlimited coins" `
  --repack-apk
```

Outputs:
- `modded_split_apks/`: Re-signed base and split APKs
- `modded_split_apks.zip`: Archive containing all modified APKs
- `INSTALL_SPLIT_APKS.txt`: Command lines for ADB and Shizuku

### Non-Root Frida Gadget Embedding

Injects Frida Gadget into all APK ABIs, configures the loader, and re-signs the APK:

```powershell
reforge pipeline `
  --binary "C:\path\game.apk" `
  --goal "infinite coins" `
  --embed-frida-gadget
```

Install and attach:

```powershell
adb install "C:\path\app_output\modded_app-aligned-signed.apk"
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -n Gadget -l "C:\path\app_output\Hook_Frida.js"
```

## Parity Verification Signals

Reforge evaluates generated code against decompilation with 11 heuristic signals:

| Signal | Level | Description |
|---|---|---|
| Missing source | RED | Source body not found |
| Stub markers | RED | Source contains configured stub marker |
| Trivial stub | RED | Small plugin-call body with no control flow |
| Large ASM, tiny source | RED | Large disassembly with disproportionately small source |
| Plugin-call heavy | YELLOW | Plugin calls dominate function body |
| Short body | YELLOW | Body has fewer than six lines |
| Low call count | YELLOW | Callees in disassembly greatly exceed source calls |
| FP sensitivity | YELLOW | Floating-point ops in assembly missing from source |
| Call-count mismatch | YELLOW | Source and assembly call counts differ beyond threshold |
| NaN logic | YELLOW | Disassembly NaN checks missing from source |
| Inline wrapper | INFO | Source forwards directly to internal implementation |

Run parity independently on existing source:

```bash
reforge parity --address 0x401000 --strict-exit
reforge parity --filter "CTrain::.*" --output report.json
```

## CLI Reference

Global options precede subcommands (e.g. `reforge --config custom.yaml status`).

| Command | Purpose |
|---|---|
| `reforge doctor [--json]` | Check toolchain and backend readiness |
| `reforge init --profile NAME` | Generate `reforge.yaml` from profile |
| `reforge reverse --address ADDR` | Reverse one function |
| `reforge reverse --class CLASS --max-functions N` | Reverse a class batch |
| `reforge reverse --class CLASS --dry-run` | Preview target list without LLM calls |
| `reforge batch --binary FILE --goal TEXT` | Discover and rank targets |
| `reforge pipeline --binary FILE --goal TEXT` | End-to-end detection, analysis, and hooks |
| `reforge pipeline ... --embed-frida-gadget` | Build signed APK with embedded Frida Gadget |
| `reforge pipeline ... --metadata-dir DIR --platform ios` | Analyze metadata dump with explicit platform |
| `reforge trace --class CLASS --symbol METHOD` | Generate Frida trace script |
| `reforge trace ... --attach PROCESS --usb` | Generate trace and attach to process |
| `reforge parity --address ADDR [--strict-exit]` | Run parity checks on existing source |
| `reforge status [--class CLASS]` | Show session state and progress |
| `reforge estimate --address ADDR` | Estimate complexity and token allowance |

## Environment Variables

| Variable | Description |
|---|---|
| `REFORGE_CONFIG` | Path to default configuration YAML file |
| `REFORGE_LLM_PROVIDER` | LLM provider override |
| `REFORGE_LLM_API_KEY` | LLM API key |
| `REFORGE_LLM_MODEL` | LLM model identifier |
| `REFORGE_LLM_BASE_URL` | LLM API base URL |
| `REFORGE_BACKEND_CLI_PATH` | Path to Ghidra bridge CLI |
| `REFORGE_BACKEND_TIMEOUT` | Backend timeout in seconds |
| `REFORGE_TOOLS_DIR` | Root directory for managed tools |
| `REFORGE_APKTOOL` | Path to custom apktool executable |
| `REFORGE_APK_SIGNER_JAR` | Path to uber-apk-signer JAR |
| `REFORGE_FRIDA_GADGET_DIR` | Directory containing Frida Gadget binaries |
| `REFORGE_FRIDA_GADGET_VERSION` | Pinned Frida Gadget version |
| `REFORGE_IL2CPP_DUMPER` | Path to Il2CppDumper executable |

## Output Artifacts

- `reports/reforge/code/`: Final reconstructed C++ code per function
- `reports/reforge/logs/`: Prompt and response logs per review round
- `reports/reforge/candidates/`: Generated candidate files
- `reports/reforge/knowledge-graph.json`: Evidence graph (calls, globals, strings)
- `reforge-progress.json`: Session progress and attempt history

## Development

```bash
git clone https://github.com/sn0wqt/Reforge.git
cd Reforge

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"

pytest tests/ -m "not llm and not ghidra" --strict-markers
ruff check src/ tests/
mypy src/reforge/
```

## License

MIT
