# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`Reforge` is a Python 3.10+ CLI for evidence-driven reverse engineering. Its main architectural flow is:

```text
CLI -> configuration/policy -> backend + local artifact analysis
    -> candidate discovery or reverser/checker loop
    -> structural/validation/parity gates -> reports + session state
```

The installed command is `reforge` (with `re-agent` supported as an alias), backed by `re_agent.cli.main:main`. Source uses a `src/` layout and tests mirror package areas under `tests/`.

## Development commands

Install the package and development dependencies in an activated virtual environment:

```bash
python -m pip install -e ".[dev]"
```

Full Ghidra-backed development may also require an editable sibling bridge checkout:

```bash
python -m pip install -e "../ghidra-ai-bridge[headless]"
```

Run the CI-equivalent checks:

```bash
ruff check src/ tests/
mypy src/re_agent/
pytest tests/ -m "not llm and not ghidra" --strict-markers --tb=short
pytest tests/ -m "not llm and not ghidra" --strict-markers \
  --cov=re_agent --cov-branch --cov-report=term-missing --cov-fail-under=70
```

Run a test file or one test by node ID:

```bash
pytest tests/test_cli/test_main.py -q
pytest tests/test_cli/test_main.py::test_name -q
```

Build and smoke-test the distributable package:

```bash
python -m pip install build
python -m build
python -m pip install dist/*.whl
reforge --version
```

There is no repository-established formatter command; Ruff linting, strict mypy, and pytest are the enforced checks. CI runs on Linux and Windows across Python 3.10-3.14.

Useful CLI entry points while developing:

```bash
reforge doctor
reforge init --profile generic-cpp
reforge reverse --address 0x401000
reforge reverse --class CTrain --max-functions 5
reforge batch --binary app.apk --goal "..."
reforge pipeline --binary app.apk --goal "..." --no-repack
reforge parity --address 0x401000 --strict-exit
reforge status
```

Global `--config` belongs before the subcommand:

```bash
reforge --config path/to/reforge.yaml status
```

Tests marked `llm` require provider credentials; tests marked `ghidra` require `ghidra-ai-bridge`. The default CI suite excludes both.

## Architecture

### CLI and configuration

- `src/re_agent/cli/main.py` owns the no-abbreviation `argparse` surface and lazily imports command handlers. Core commands are `init`, `reverse`, `parity`, `status`, and `estimate`; mobile/artifact commands are `batch`, `pipeline`, `hook`, `trace`, `doctor`, and `scan-strings`.
- `src/re_agent/config/` defines dataclass schemas, defaults, loading, and data-handling policy. Precedence is **CLI overrides > supported `REFORGE_*` environment variables (with `RE_AGENT_*` compatibility) > YAML (`reforge.yaml` or legacy `re-agent.yaml`) > defaults**. Unknown keys and invalid values fail closed.
- Role-specific `agents.reverser` and `agents.checker` settings overlay top-level LLM settings. Switching providers intentionally strips inherited provider-specific credentials, endpoints, models, and fallbacks.
- External LLM use is deny-by-default and each primary/fallback route must pass `data_handling` policy. Prompt logging and persistent evidence are separate opt-ins.

### Artifact analysis and backend layer

- `src/re_agent/core/engine_detector.py` selects Android, iOS, Windows, Unity/IL2CPP, React Native/Hermes, DEX, or native pathways using archive layout, directory contents, magic bytes, and metadata evidence. Ambiguous metadata-only inputs require an explicit `--platform` rather than a guessed platform.
- `src/re_agent/core/dex_parser.py`, `il2cpp_parser.py`, `native_scanner.py`, `ipa_scanner.py`, `macho.py`, and related modules perform bounded local analysis. APK/IPA identity extraction feeds safe naming and Android namespace filtering.
- Archive handling in `src/re_agent/utils/archives.py` is intentionally fail-closed: path traversal, links/reparse points, encryption, duplicates, oversized members, and suspicious compression are rejected.
- `src/re_agent/backend/protocol.py` defines the `REBackend` abstraction and optional capability flags. `backend/registry.py` selects Ghidra bridge, IL2CPP metadata, or stub implementations. Enhanced evidence must be capability-checked because older bridge installations degrade gracefully.

### LLM and reversal orchestration

- `src/re_agent/llm/protocol.py` provides the small provider interface; `llm/registry.py` lazily constructs API or local-CLI providers, and `llm/failover.py` controls retries and route changes. Safety/policy, invalid-request, and unknown failures do not trigger provider shopping.
- `src/re_agent/cli/cmd_reverse.py` performs validation and data-policy preflight before constructing providers, then selects the backend and persistent session.
- `src/re_agent/orchestrator/` coordinates address- or class-level runs. `agents/loop.py` drives independent `ReverserAgent` and `CheckerAgent` roles through bounded rounds: gather evidence, generate code, obtain strict checker JSON, run non-LLM structural verification, and feed failures into the next round.
- Model-requested backend actions are read-only and narrowly validated; the reversal loop does not expose model-directed shell or filesystem operations.

### Candidate validation, parity, and persistence

- Acceptance is conjunctive: checker `PASS`, no objective `FAIL`, configured candidate validation accepted, and parity not blocked by configured RED/YELLOW policy.
- `src/re_agent/verification/candidate.py` writes generated code to an overlay rather than the original source tree. Project validation and host shell commands are separately controlled high-trust features; passing commands count as evidence only when explicitly trusted.
- `src/re_agent/verification/objective.py` treats missing evidence as `UNKNOWN`; only strong structural contradictions should become `FAIL`.
- `src/re_agent/parity/` combines deterministic local signals, optional Ghidra evidence, semantic rules, and manual overrides into GREEN/YELLOW/RED status.
- `src/re_agent/core/session.py` persists function/run state with locking, merge-before-save, fsync, atomic replacement, and corrupt-file quarantine. `src/re_agent/reports/` writes accepted code and authorized reports/logs.

### Batch and universal pipeline

- `src/re_agent/cli/cmd_batch.py` is local-first discovery: parse DEX/IL2CPP evidence, derive and rank candidates, optionally ask an LLM to refine a bounded shortlist, then ground every LLM result back against submitted evidence.
- `src/re_agent/core/candidates.py` enforces the activation gate. A score alone is never mutation or ABI proof. Active Java/DEX return overrides require an exact executable declaration and compatible primitive return; active IL2CPP return overrides require an exact nonzero method RVA and compatible bool/integer type. Native offsets and unsupported types remain review-only.
- `src/re_agent/cli/cmd_pipeline.py` composes detection, extraction, batch analysis, optional textual Hermes patching, hook generation, packaging, summaries, and `pipeline_manifest.json`. Hermes bytecode pseudo-JS is analysis-only; only original textual bundles may be patched.
- Pipeline output distinguishes static artifact generation from installation and runtime behavior verification. Android rebuild/sign happens only for a verified textual patch or explicitly requested, validated Frida Gadget embedding. iOS signing is not attempted on Windows.
- `doctor` reports core analysis, packaging, and Gadget/deployment readiness independently so missing optional deployment tooling does not imply core analysis is unavailable.

## Repository-specific invariants

- Preserve the design sequence: **local evidence -> bounded LLM input -> independently grounded output**.
- Do not promote strings, symbols, candidate scores, or native addresses into callable ABI or mutation proof.
- Keep default data-handling denial, prompt-persistence opt-ins, overlay isolation, and host-command consent fail-closed.
- Treat `pipeline_manifest.json` as the source of truth for completed pipeline stages; generated hooks are not equivalent to installation or runtime verification.
- Match nearby code style: Python 3.10-compatible typing, 120-character Ruff line length, strict mypy, and lazy imports for optional providers/tool integrations.
