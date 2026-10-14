"""Configuration schema dataclasses for re-agent."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProjectProfile:
    """Project-specific patterns and paths."""

    hook_patterns: list[str] = field(default_factory=list)
    stub_patterns: list[str] = field(default_factory=lambda: [r"TODO|NOT_IMPLEMENTED"])
    stub_markers: list[str] = field(default_factory=lambda: ["NOT_IMPLEMENTED"])
    stub_call_prefix: str = "__re_agent_no_stub_prefix__"
    class_macro: str = ""
    source_root: str = "output"
    source_extensions: list[str] = field(
        default_factory=lambda: [
            ".cpp",
            ".cc",
            ".cxx",
            ".c",
            ".h",
            ".hpp",
        ]
    )
    hooks_csv: str | None = None
    name: str = "generic-cpp"
    language_standard: str = "C++20"
    prompt_rules: list[str] = field(
        default_factory=lambda: [
            "Preserve the detected ABI, calling convention, widths, and signedness",
            "Use evidence-backed names and retain address-based placeholders when unresolved",
        ]
    )


@dataclass
class LLMConfig:
    """LLM provider configuration."""

    provider: str = "codex"
    model: str | None = "gpt-5.6-sol"
    api_key: str | None = None
    base_url: str | None = None
    max_tokens: int = 4096
    temperature: float = 0.0
    timeout_s: int = 600
    cli_path: str | None = "codex"
    max_budget_usd: float | None = None
    effort: str | None = "high"
    input_cost_per_million: float = 0.0
    output_cost_per_million: float = 0.0
    service_account_file: str | None = None
    allow_provider_fallback: bool = False
    fallbacks: list[LLMConfig] = field(default_factory=list)
    max_retries: int = 0
    retry_base_delay_s: float = 1.0


@dataclass
class AgentModelsConfig:
    """Optional per-role model overrides.

    ``None`` keeps backwards compatibility by falling back to the top-level
    :class:`LLMConfig`.
    """

    reverser: LLMConfig | None = None
    checker: LLMConfig | None = None


@dataclass
class BackendConfig:
    """Decompiler backend configuration."""

    type: str = "ghidra-bridge"
    cli_path: str = "ghidra-bridge"
    timeout_s: int = 45


@dataclass
class ParityConfig:
    """Static parity verification settings."""

    enabled: bool = True
    call_count_warn_diff: int = 3
    inline_wrapper_autoskip: bool = False
    semantic_rules_file: str | None = None
    manual_checks_file: str | None = None
    cache_dir: str = ".cache/re-agent-parity"


@dataclass
class OrchestratorConfig:
    """Orchestrator loop settings."""

    max_review_rounds: int = 4
    max_functions_per_class: int = 10
    objective_verifier_enabled: bool = True
    objective_call_count_tolerance: int = 3
    objective_control_flow_tolerance: int = 2
    investigation_enabled: bool = True
    max_investigations: int = 8
    selection_strategy: str = "dependency-order"
    max_attempts_per_function: int = 3


@dataclass
class ValidationConfig:
    """Candidate overlay, build, test, and acceptance gate settings."""

    enabled: bool = True
    copy_project: bool = False
    project_root: str = "."
    build_commands: list[str] = field(default_factory=list)
    test_commands: list[str] = field(default_factory=list)
    runtime_commands: list[str] = field(default_factory=list)
    require_build: bool = False
    require_tests: bool = False
    require_runtime: bool = False
    require_verified: bool = True
    allow_host_commands: bool = False
    trust_configured_commands: bool = False
    environment_allowlist: list[str] = field(
        default_factory=lambda: [
            "COMSPEC",
            "HOME",
            "LANG",
            "LC_ALL",
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "USERPROFILE",
        ]
    )
    parity_fail_on_red: bool = True
    parity_fail_on_yellow: bool = False
    command_timeout_s: int = 900
    working_directory: str = "."
    keep_project_copy: bool = False


@dataclass
class DataHandlingConfig:
    """Explicit trust policy for external models and retained prompt data."""

    allow_external_llm: bool = False
    allowed_providers: list[str] = field(default_factory=list)
    allow_prompt_logging: bool = False
    allow_evidence_persistence: bool = False
    max_prompt_chars: int = 120_000


@dataclass
class OutputConfig:
    """Output and reporting settings."""

    report_dir: str = "reports/re-agent"
    log_dir: str = "reports/re-agent/logs"
    session_file: str = "re-agent-progress.json"
    format: str = "json"


@dataclass
class ReAgentConfig:
    """Top-level configuration for the re-agent system."""

    project_profile: ProjectProfile = field(default_factory=ProjectProfile)
    llm: LLMConfig = field(default_factory=LLMConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)
    parity: ParityConfig = field(default_factory=ParityConfig)
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    agents: AgentModelsConfig = field(default_factory=AgentModelsConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    data_handling: DataHandlingConfig = field(default_factory=DataHandlingConfig)

    @classmethod
    def create_default(cls) -> ReAgentConfig:
        """Create a configuration with all default values."""
        return cls(
            project_profile=ProjectProfile(),
            llm=LLMConfig(),
            agents=AgentModelsConfig(),
            backend=BackendConfig(),
            parity=ParityConfig(),
            orchestrator=OrchestratorConfig(),
            validation=ValidationConfig(),
            data_handling=DataHandlingConfig(),
            output=OutputConfig(),
        )
