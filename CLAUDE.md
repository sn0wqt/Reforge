# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project Overview

Reforge is an evidence-driven binary reverse-engineering agent (Python 3.10+):

```text
CLI -> Config -> Backend/Artifact Analysis -> Discovery / Reverser-Checker Loop -> Verification/Parity -> Reports
```

- Primary command: `reforge`, backed by `reforge.cli.main:main`.
- Source layout: `src/reforge/`.
- Test layout: `tests/`.

## Development Commands

Install in development mode:

```bash
python -m pip install -e ".[dev]"
```

Run test suite and quality checks:

```bash
ruff check src/ tests/
mypy src/reforge/
pytest tests/ -m "not llm and not ghidra" --strict-markers --tb=short
pytest tests/ -m "not llm and not ghidra" --strict-markers --cov=reforge --cov-branch --cov-report=term-missing --cov-fail-under=70
```

Targeted testing:

```bash
pytest tests/test_cli/test_main.py -q
pytest tests/test_cli/test_main.py::test_name -q
```

Build package:

```bash
python -m pip install build
python -m build
python -m pip install dist/*.whl
reforge --version
```

Common CLI invocations:

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

Global options precede subcommands (e.g. `reforge --config custom.yaml status`).

Tests marked `llm` require API credentials; tests marked `ghidra` require `ghidra-ai-bridge`. Both are excluded in standard CI runs.

## Architecture

### CLI and Configuration
- `src/reforge/cli/main.py`: `argparse` definition with lazy command imports.
- `src/reforge/config/`: Dataclass schemas, YAML loading, environment overrides, and data handling policy.
- Precedence: **CLI overrides > `REFORGE_*` environment variables > `reforge.yaml` > defaults**.
- External LLM access is denied by default; each active provider must be explicitly allowed under `data_handling`.

### Artifact Analysis and Backend
- `src/reforge/core/engine_detector.py`: Detects Android, iOS, Windows, Unity/IL2CPP, React Native/Hermes, DEX, and native binaries.
- `src/reforge/core/`: Dedicated local parsers for DEX, IL2CPP metadata, native symbols, Mach-O, and web assets.
- `src/reforge/utils/archives.py`: Fail-closed archive extraction protecting against path traversal, symlinks, and zip bombs.
- `src/reforge/backend/protocol.py`: `REBackend` abstraction. Implementations include Ghidra Bridge, IL2CPP metadata, and stubs.

### LLM and Reversal Loop
- `src/reforge/llm/`: Provider interfaces for CLIProxyAPI (Antigravity), Codex CLI, Claude (API/CLI), OpenAI, and Gemini API with failover routing.
- `src/reforge/orchestrator/`: Manages address and class runs.
- `src/reforge/agents/loop.py`: Coordinates independent `ReverserAgent` and `CheckerAgent` in bounded feedback rounds.
- Backend queries from agents are read-only and strictly validated.

### Candidate Validation and Parity
- Multi-gate verification: Checker `PASS`, objective structural verification, candidate build/test execution, and parity checks.
- `src/reforge/verification/candidate.py`: Evaluates code in isolated candidate overlays without modifying the original source tree.
- `src/reforge/parity/`: 11 heuristic signals comparing disassembly against generated source (GREEN / YELLOW / RED).
- `src/reforge/core/session.py`: Atomic progress persistence with locking, quarantine, and merge-on-save.

### Universal Pipeline
- `src/reforge/cli/cmd_pipeline.py`: Detection, extraction, batch analysis, optional Hermes patching, hook scaffolding, and packaging.
- `src/reforge/core/candidates.py`: Strict activation boundaries. Only verified primitive returns with complete type descriptors are emitted as active hooks.
- `src/reforge/cli/cmd_doctor.py`: Independent health checks for analysis, packaging, and Frida Gadget dependencies.

## Key Invariants

- Follow the sequence: **local evidence -> bounded LLM input -> independently verified output**.
- Never promote strings, symbols, or unverified native offsets into active mutation hooks.
- Keep data-handling denials, prompt persistence opt-ins, and host command execution fail-closed.
- Code style: Python 3.10+ typing, 120-character line length (Ruff), strict mypy, and lazy provider imports.
