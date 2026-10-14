"""Backend factory: creates a backend from configuration."""

from __future__ import annotations

from pathlib import Path

from reforge.backend.protocol import REBackend
from reforge.config.schema import BackendConfig


def create_backend(
    config: BackendConfig,
    metadata_dir: str | Path | None = None,
) -> REBackend:
    """Create an RE backend based on config.backend.type or explicit metadata_dir.

    Supported types:
        - ``"ghidra-bridge"`` (default): Shells out to a Ghidra CLI tool.
        - ``"ghidra-json"``: Directly reads Ghidra JSON export files.
        - ``"il2cpp"`` / ``"metadata"``: Directly parses dump.cs / script.json metadata directory.
        - ``"stub"``: In-memory stub returning canned data (for testing).

    Raises:
        ValueError: If the backend type is not recognised.
    """
    if metadata_dir is not None:
        from reforge.backend.il2cpp import IL2CPPBackend

        return IL2CPPBackend(metadata_dir)

    backend_type = config.type.lower().replace("_", "-")

    if backend_type in ("ghidra-bridge", "ghidra"):
        from reforge.backend.ghidra_bridge import GhidraBridgeBackend

        return GhidraBridgeBackend(
            cli_path=config.cli_path,
            timeout_s=config.timeout_s,
        )

    if backend_type == "ghidra-json":
        from reforge.backend.exports import GhidraExportsBackend

        if not config.export_dir:
            raise ValueError("backend.export_dir is required for ghidra-json")
        return GhidraExportsBackend(config.export_dir, config.address_map)

    if backend_type in ("il2cpp", "metadata"):
        from reforge.backend.il2cpp import IL2CPPBackend

        return IL2CPPBackend("output")

    if backend_type in ("rea", "rea-mcp", "mcp"):
        from reforge.backend.rea_mcp import ReaMcpBackend

        return ReaMcpBackend(
            binary_path=config.binary_path,
            provider_id=config.rea_provider,
            cli_cmd=config.rea_path,
            timeout_s=config.timeout_s,
        )

    if backend_type == "stub":
        from reforge.backend.stub import StubBackend

        return StubBackend()

    raise ValueError(f"Unknown backend type: {config.type!r}. Supported: ghidra-bridge, ghidra-json, rea, il2cpp, stub")
