# Architecture

Reforge is organized into modular layers:

```text
CLI -> Config -> Orchestrator -> Evidence Loop -> LLM Providers
                      |              |
                      v              v
              Function Picker    RE Backend Protocol
                      |
                      v
       Candidate Overlay -> Build/Test -> Parity/IR Gate
```

## System Components

- **CLI (`reforge.cli`)**: Entry points for `init`, `reverse`, `plan`, `evidence`, `benchmark`, `batch`, `pipeline`, `parity`, `status`, `doctor`, and `trace`.
- **Config (`reforge.config`)**: Dataclass schemas, YAML loading, environment overrides, and data handling policy.
- **Orchestrator (`reforge.orchestrator`)**: Coordinates address, class, and manifest-level reversal workflows.
- **Agents (`reforge.agents`)**: Independent reverser and checker roles running in a bounded review and fix loop.
- **LLM (`reforge.llm`)**: Provider adapters for Claude API/CLI, OpenAI-compatible APIs, Codex CLI, Gemini API, CLIProxyAPI, and failover routing.
- **Backend (`reforge.backend`)**: Reverse engineering tool abstraction covering Ghidra Bridge, Ghidra JSON exports, IL2CPP metadata, and stubs.
- **Core Analysis (`reforge.core`)**: Local parsers for DEX, IL2CPP metadata, Mach-O, Swift symbols, web assets, and target plan manifests.
- **Packaging (`reforge.packaging`)**: Android APK alignment, re-signing, split APK assembly, and Frida Gadget injection.
- **Validation (`reforge.verification`)**: Isolated candidate file overlays, portable build/test/runtime gates, differential harness verification, and objective structural verification.
- **Parity Engine (`reforge.parity`)**: Heuristic signals evaluating decompilation versus generated C/C++ source, plus Clang AST indexing.
- **Reports (`reforge.reports`)**: Run tracking, JSON session state, searchable evidence packets, and manifest coverage formatting.
