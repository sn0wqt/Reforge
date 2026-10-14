"""Backend factory :  creates a backend from configuration."""

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

    if backend_type in ("il2cpp", "metadata"):
        from reforge.backend.il2cpp import IL2CPPBackend

        return IL2CPPBackend("output")

    if backend_type == "stub":
        from reforge.backend.stub import StubBackend

        return StubBackend()

    raise ValueError(f"Unknown backend type: {config.type!r}. Supported: ghidra-bridge, il2cpp, stub")
