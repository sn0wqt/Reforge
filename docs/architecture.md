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

- **CLI (`reforge.cli`)**: Entry points for `init`, `reverse`, `batch`, `pipeline`, `parity`, `status`, `doctor`, and `trace`.
- **Config (`reforge.config`)**: Dataclass schemas, YAML loading, environment overrides, and data handling policy.
- **Orchestrator (`reforge.orchestrator`)**: Coordinates address and class-level reversal workflows.
- **Agents (`reforge.agents`)**: Independent reverser and checker roles running in a bounded review and fix loop.
- **LLM (`reforge.llm`)**: Provider adapters for Claude API/CLI, OpenAI-compatible APIs, Codex CLI, Gemini API, and failover routing.
- **Backend (`reforge.backend`)**: Reverse engineering tool abstraction covering Ghidra Bridge, IL2CPP metadata, and stubs.
- **Core Analysis (`reforge.core`)**: Local parsers for DEX, IL2CPP metadata, Mach-O, Swift symbols, and web assets.
- **Packaging (`reforge.packaging`)**: Android APK alignment, re-signing, split APK assembly, and Frida Gadget injection.
- **Validation (`reforge.verification`)**: Isolated candidate file overlays, build and test gates, and objective structural verification.
- **Parity Engine (`reforge.parity`)**: Heuristic signals evaluating decompilation versus generated C/C++ source.
- **Reports (`reforge.reports`)**: Run tracking, JSON session state, and output formatting.
