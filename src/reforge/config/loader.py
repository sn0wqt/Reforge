"""Configuration loader for reforge."""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Any, TypeVar

from reforge.config.schema import (
    AgentModelsConfig,
    BackendConfig,
    DataHandlingConfig,
    LLMConfig,
    OrchestratorConfig,
    OutputConfig,
    ParityConfig,
    ProjectProfile,
    ReforgeConfig,
    ValidationConfig,
)


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge overlay into base, returning a new dict."""
    result = dict(base)
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_yaml_file(path: Path) -> dict[str, Any]:
    """Load a YAML file and return its contents as a dict."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as err:
        raise ImportError(
            "PyYAML is required for loading YAML config files. Install it with: pip install pyyaml"
        ) from err
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected a YAML mapping at top level in {path}, got {type(data).__name__}")
    return data


def _resolve_yaml_relative_provider_paths(raw: dict[str, Any], config_path: Path) -> None:
    """Resolve YAML-owned credential files relative to their YAML file.

    Environment and CLI overrides are applied later and intentionally retain
    their caller-relative semantics.  Only paths literally read from YAML are
    rebased here, including independent role fallback chains.
    """

    def resolve_route(route: object) -> None:
        if not isinstance(route, dict):
            return
        service_account = route.get("service_account_file")
        if isinstance(service_account, str) and service_account.strip():
            account_path = Path(service_account).expanduser()
            if not account_path.is_absolute():
                route["service_account_file"] = str((config_path.parent / account_path).resolve())
        fallbacks = route.get("fallbacks", [])
        if isinstance(fallbacks, list):
            for fallback in fallbacks:
                resolve_route(fallback)

    resolve_route(raw.get("llm"))
    agents = raw.get("agents")
    if isinstance(agents, dict):
        resolve_route(agents.get("reverser"))
        resolve_route(agents.get("checker"))


def discover_config_path() -> Path | None:
    """Find the default configuration for an installed or editable checkout.

    The CLI is commonly launched from the directory that contains the target
    binary rather than from the Reforge repository.  In an editable install,
    silently falling back to dataclass defaults in that situation changes the
    configured provider and data-handling policy.  Prefer an explicit
    ``REFORGE_CONFIG`` path, then the current directory, then the editable
    checkout root.  A normal wheel install has no checkout-level YAML and
    therefore continues to use schema defaults unless the user supplies one.
    """
    configured = os.environ.get("REFORGE_CONFIG")
    if configured:
        configured_path = Path(configured).expanduser()
        if not configured_path.is_file():
            raise FileNotFoundError(f"Config file not found: {configured_path}")
        return configured_path.resolve()

    for filename in ("reforge.yaml", "reforge.yml", ".reforge.yaml"):
        cwd_config = Path.cwd() / filename
        if cwd_config.is_file():
            return cwd_config.resolve()

    # loader.py -> config -> reforge -> src -> repository root
    repo_root = Path(__file__).resolve().parents[3]
    for filename in ("reforge.yaml", "reforge.yml", ".reforge.yaml"):
        checkout_config = repo_root / filename
        if checkout_config.is_file():
            return checkout_config.resolve()
    return None


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """Overlay REFORGE_* environment variables onto the raw config dict."""
    env_mappings: list[tuple[tuple[str, ...], list[str], type]] = [
        (("REFORGE_LLM_PROVIDER", "REFORGE_PROVIDER"), ["llm", "provider"], str),
        (("REFORGE_LLM_API_KEY", "REFORGE_API_KEY"), ["llm", "api_key"], str),
        (("REFORGE_LLM_MODEL", "REFORGE_MODEL"), ["llm", "model"], str),
        (("REFORGE_LLM_BASE_URL", "REFORGE_BASE_URL"), ["llm", "base_url"], str),
        (("REFORGE_BACKEND_CLI_PATH", "REFORGE_CLI_PATH"), ["backend", "cli_path"], str),
        (("REFORGE_BACKEND_TIMEOUT", "REFORGE_TIMEOUT"), ["backend", "timeout_s"], int),
    ]

    for env_vars, key_path, cast_type in env_mappings:
        value = None
        for env_var in env_vars:
            val = os.environ.get(env_var)
            if val is not None:
                value = val
                break
        if value is None:
            continue

        # Navigate to the correct nested dict, creating intermediates as needed.
        d = raw
        for part in key_path[:-1]:
            if part not in d or not isinstance(d[part], dict):
                d[part] = {}
            d = d[part]
        d[key_path[-1]] = cast_type(value)

    return raw


def _apply_cli_overrides(raw: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Apply CLI overrides using dot-notation keys (e.g., 'llm.model')."""
    for dotted_key, value in overrides.items():
        parts = dotted_key.split(".")
        d = raw
        for part in parts[:-1]:
            if part not in d or not isinstance(d[part], dict):
                d[part] = {}
            d = d[part]
        d[parts[-1]] = value
    return raw


def _coerce_field(value: Any, field_name: str, field_type_str: str) -> Any:
    """Strictly coerce scalar YAML values and reject ambiguous types."""
    if value is None:
        if "None" not in field_type_str:
            raise ValueError(f"{field_name} may not be null")
        return value

    normalized_type = field_type_str.replace(" ", "")
    if normalized_type.startswith("list["):
        if not isinstance(value, list):
            raise ValueError(f"{field_name} must be a list")
        if normalized_type == "list[str]":
            if not all(isinstance(item, str) for item in value):
                raise ValueError(f"{field_name} must contain only strings")
        elif "list[str]" in normalized_type and (
            "list[list[str]]" in normalized_type or "|list[str]" in normalized_type
        ):
            for item in value:
                if isinstance(item, str):
                    continue
                if isinstance(item, list) and all(isinstance(arg, str) for arg in item):
                    continue
                raise ValueError(f"{field_name} must contain nonempty shell strings or argument arrays")
        return value
    if "bool" in normalized_type:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in {"true", "1", "yes", "on"}:
                return True
            if normalized in {"false", "0", "no", "off"}:
                return False
        raise ValueError(f"{field_name} must be a boolean")
    if "int" in normalized_type:
        if isinstance(value, bool):
            raise ValueError(f"{field_name} must be an integer, not a boolean")
        if isinstance(value, int):
            return value
        try:
            return int(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{field_name} must be a positive integer") from exc
    if "float" in normalized_type:
        if isinstance(value, bool):
            raise ValueError(f"{field_name} must be numeric, not a boolean")
        if isinstance(value, (int, float)):
            return float(value)
        try:
            return float(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{field_name} must be numeric") from exc
    if "str" in normalized_type and not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    return value


_T = TypeVar("_T")


def _build_with_coercion(cls: type[_T], data: dict[str, Any]) -> _T:
    """Build a dataclass from a raw dict and reject unknown configuration."""
    if not isinstance(data, dict):
        raise ValueError(f"{cls.__name__} configuration must be a mapping")
    known = {f.name: f for f in dataclasses.fields(cls)}  # type: ignore[arg-type]
    unknown = sorted(set(data) - set(known))
    if unknown:
        raise ValueError(f"Unknown config key(s) in {cls.__name__}: {', '.join(unknown)}")
    filtered: dict[str, Any] = {}
    for k, v in data.items():
        ft = known[k].type
        type_str = ft if isinstance(ft, str) else getattr(ft, "__name__", str(ft))
        filtered[k] = _coerce_field(v, f"{cls.__name__}.{k}", type_str)
    return cls(**filtered)


def _build_project_profile(data: dict[str, Any]) -> ProjectProfile:
    """Build a ProjectProfile from a raw dict, ignoring unknown keys."""
    return _build_with_coercion(ProjectProfile, data)


def _build_llm_config(
    data: dict[str, Any],
    *,
    allow_fallbacks: bool = True,
) -> LLMConfig:
    """Build an LLM config, including an ordered non-recursive failover chain."""
    if not isinstance(data, dict):
        raise ValueError("LLMConfig configuration must be a mapping")
    values = dict(data)
    raw_fallbacks = values.pop("fallbacks", [])
    if not isinstance(raw_fallbacks, list):
        raise ValueError("LLMConfig.fallbacks must be a list")
    if raw_fallbacks and not allow_fallbacks:
        raise ValueError("Nested LLM fallback chains are not supported")

    if "model" not in values or values["model"] is None:
        provider = str(values.get("provider", LLMConfig.provider))
        if provider == "codex":
            values["model"] = "gpt-6.1-sol"
        elif provider in ("cliproxy", "cli-proxy", "antigravity", "antigravity-cli", "gemini-cli"):
            values["model"] = "gemini-3.8-flash-high"

    config = _build_with_coercion(LLMConfig, values)
    fallbacks: list[LLMConfig] = []
    for index, item in enumerate(raw_fallbacks):
        if not isinstance(item, dict):
            raise ValueError(f"LLMConfig.fallbacks[{index}] must be a mapping")
        fallbacks.append(_build_llm_config(item, allow_fallbacks=False))
    config.fallbacks = fallbacks
    return config


def _build_backend_config(data: dict[str, Any]) -> BackendConfig:
    return _build_with_coercion(BackendConfig, data)


def _build_agents_config(
    data: dict[str, Any],
    base_llm_data: dict[str, Any],
) -> AgentModelsConfig:
    unknown_roles = sorted(set(data) - {"reverser", "checker"})
    if unknown_roles:
        raise ValueError(f"Unknown agents role(s): {', '.join(unknown_roles)}")

    default_agents = AgentModelsConfig()

    def role(name: str) -> LLMConfig | None:
        if name not in data:
            return default_agents.reverser if name == "reverser" else default_agents.checker
        value = data.get(name)
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError(f"agents.{name} must be a mapping")
        base_provider = str(base_llm_data.get("provider", LLMConfig.provider))
        role_provider = str(value.get("provider", base_provider))
        merged = _deep_merge(base_llm_data, value)
        if role_provider != base_provider:
            # Never carry credentials or endpoint paths across provider boundaries.
            for sensitive_key in (
                "api_key",
                "base_url",
                "cli_path",
                "fallbacks",
                "model",
                "service_account_file",
            ):
                if sensitive_key not in value:
                    merged.pop(sensitive_key, None)
        return _build_llm_config(merged)

    return AgentModelsConfig(reverser=role("reverser"), checker=role("checker"))


def _build_parity_config(data: dict[str, Any]) -> ParityConfig:
    return _build_with_coercion(ParityConfig, data)


def _build_orchestrator_config(data: dict[str, Any]) -> OrchestratorConfig:
    return _build_with_coercion(OrchestratorConfig, data)


def _build_output_config(data: dict[str, Any]) -> OutputConfig:
    return _build_with_coercion(OutputConfig, data)


def _build_validation_config(data: dict[str, Any]) -> ValidationConfig:
    return _build_with_coercion(ValidationConfig, data)


def _build_data_handling_config(data: dict[str, Any]) -> DataHandlingConfig:
    return _build_with_coercion(DataHandlingConfig, data)


def _build_config(raw: dict[str, Any]) -> ReforgeConfig:
    """Build a ReforgeConfig from a raw dict."""
    known_sections = {field.name for field in dataclasses.fields(ReforgeConfig)}
    unknown_sections = sorted(set(raw) - known_sections)
    if unknown_sections:
        raise ValueError(f"Unknown top-level config section(s): {', '.join(unknown_sections)}")
    llm_data = raw.get("llm", {})
    if not isinstance(llm_data, dict):
        raise ValueError("llm must be a mapping")
    agents_data = raw.get("agents", {})
    if not isinstance(agents_data, dict):
        raise ValueError("agents must be a mapping")

    config = ReforgeConfig(
        project_profile=_build_project_profile(raw.get("project_profile", {})),
        llm=_build_llm_config(llm_data),
        agents=_build_agents_config(agents_data, llm_data),
        backend=_build_backend_config(raw.get("backend", {})),
        parity=_build_parity_config(raw.get("parity", {})),
        orchestrator=_build_orchestrator_config(raw.get("orchestrator", {})),
        validation=_build_validation_config(raw.get("validation", {})),
        data_handling=_build_data_handling_config(raw.get("data_handling", {})),
        output=_build_output_config(raw.get("output", {})),
    )
    _validate_config(config)
    return config


def _validate_config(config: ReforgeConfig) -> None:
    """Reject unsafe or nonsensical numeric configuration values."""

    def validate_llm(value: LLMConfig, label: str) -> None:
        value.provider = value.provider.strip().casefold()
        if not value.provider:
            raise ValueError(f"{label}.provider may not be empty")
        if value.model is not None and not value.model.strip():
            raise ValueError(f"{label}.model may not be empty")
        if value.max_tokens <= 0:
            raise ValueError(f"{label}.max_tokens must be positive")
        if not 0.0 <= value.temperature <= 2.0:
            raise ValueError(f"{label}.temperature must be between 0 and 2")
        if value.timeout_s <= 0:
            raise ValueError(f"{label}.timeout_s must be positive")
        if value.max_budget_usd is not None and value.max_budget_usd <= 0:
            raise ValueError(f"{label}.max_budget_usd must be positive")
        if value.max_retries < 0 or value.max_retries > 2:
            raise ValueError(f"{label}.max_retries must be between 0 and 2")
        if value.retry_base_delay_s < 0:
            raise ValueError(f"{label}.retry_base_delay_s may not be negative")
        for index, fallback in enumerate(value.fallbacks):
            validate_llm(fallback, f"{label}.fallbacks[{index}]")

    validate_llm(config.llm, "llm")
    if config.agents.reverser is not None:
        validate_llm(config.agents.reverser, "agents.reverser")
    if config.agents.checker is not None:
        validate_llm(config.agents.checker, "agents.checker")
    for name in (
        "max_review_rounds",
        "max_functions_per_class",
        "max_attempts_per_function",
        "max_llm_calls_per_function",
    ):
        value = getattr(config.orchestrator, name)
        if type(value) is not int or value < 1:
            raise ValueError(f"orchestrator.{name} must be a positive integer")
    if type(config.orchestrator.max_investigations) is not int or config.orchestrator.max_investigations < 0:
        raise ValueError("max_investigations must be a nonnegative integer")
    if config.orchestrator.objective_call_count_tolerance < 0:
        raise ValueError("OrchestratorConfig.objective_call_count_tolerance may not be negative")
    if config.orchestrator.objective_control_flow_tolerance < 0:
        raise ValueError("OrchestratorConfig.objective_control_flow_tolerance may not be negative")
    if config.orchestrator.selection_strategy not in {
        "dependency-order",
        "easiest-first",
        "high-impact",
    }:
        raise ValueError(
            "OrchestratorConfig.selection_strategy must be dependency-order, easiest-first, or high-impact"
        )
    if config.parity.call_count_warn_diff < 0:
        raise ValueError("ParityConfig.call_count_warn_diff may not be negative")
    if config.validation.command_timeout_s <= 0:
        raise ValueError("ValidationConfig.command_timeout_s must be positive")
    for name in (
        "build_commands",
        "test_commands",
        "runtime_commands",
    ):
        value = getattr(config.validation, name)
        if not isinstance(value, list) or not all(
            (isinstance(item, str) and bool(item.strip()))
            or (
                isinstance(item, list)
                and bool(item)
                and all(isinstance(arg, str) for arg in item)
                and bool(item[0].strip())
            )
            for item in value
        ):
            raise ValueError(f"validation.{name} must contain nonempty shell strings or argument arrays")
    for name in ("differential_reference", "differential_candidate"):
        value = getattr(config.validation, name)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"validation.{name} must be a list of strings")
    if config.project_profile.compilation_database is not None and (
        not isinstance(config.project_profile.compilation_database, str)
        or not config.project_profile.compilation_database.strip()
    ):
        raise ValueError("project_profile.compilation_database must be a non-empty string")
    if config.data_handling.max_prompt_chars < 1_000:
        raise ValueError("DataHandlingConfig.max_prompt_chars must be at least 1000")
    config.data_handling.allowed_providers = [
        provider.strip().casefold() for provider in config.data_handling.allowed_providers if provider.strip()
    ]


def load_config(
    yaml_path: Path | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> ReforgeConfig:
    """Load configuration from YAML, environment variables, and CLI overrides."""
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    raw: dict[str, Any] = {}

    # 1. Load YAML file if available.
    loaded_yaml_path: Path | None = None
    if yaml_path is not None:
        yaml_p = Path(yaml_path)
        if yaml_p.exists():
            raw = _load_yaml_file(yaml_p)
            loaded_yaml_path = yaml_p.resolve()
        else:
            raise FileNotFoundError(f"Config file not found: {yaml_p}")
    else:
        default_path = discover_config_path()
        if default_path is not None:
            raw = _load_yaml_file(default_path)
            loaded_yaml_path = default_path.resolve()

    if loaded_yaml_path is not None:
        _resolve_yaml_relative_provider_paths(raw, loaded_yaml_path)

    # 2. Overlay environment variables.
    raw = _apply_env_overrides(raw)

    # 3. Overlay CLI overrides.
    if cli_overrides:
        raw = _apply_cli_overrides(raw, cli_overrides)

    # 4. Build typed config from the merged dict.
    return _build_config(raw)


def validate_config(config: ReforgeConfig) -> None:
    """Validate a loaded ReforgeConfig instance."""
    _validate_config(config)
