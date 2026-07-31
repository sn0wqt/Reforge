"""Unit tests for IL2CPPBackend."""

from __future__ import annotations

from pathlib import Path
from re_agent.backend.il2cpp import IL2CPPBackend
from re_agent.backend.registry import create_backend
from re_agent.config.schema import BackendConfig


def test_il2cpp_backend_remaining_and_decompile(tmp_path: Path) -> None:
    dump_cs = tmp_path / "dump.cs"
    dump_cs.write_text(
        """// Namespace: 
public class RunSessionData
{
    // RVA: 0x293C50C VA: 0x293C50C
    public void AddBonusCoins(int amount) { }
}
""",
        encoding="utf-8",
    )

    backend = IL2CPPBackend(tmp_path)

    # Test capabilities
    assert backend.capabilities.has_decompile is True
    assert backend.capabilities.has_structs is True

    # Test remaining
    entries = backend.remaining("RunSessionData")
    assert len(entries) == 1
    assert entries[0].address == "0x293C50C"
    assert entries[0].name == "AddBonusCoins"

    # Test decompile
    dec = backend.decompile("0x293C50C")
    assert dec.address == "0x293C50C"
    assert "RunSessionData" in dec.name
    assert "AddBonusCoins" in dec.name
    assert "IL2CPP" in dec.decompiled


def test_registry_create_backend_il2cpp(tmp_path: Path) -> None:
    cfg = BackendConfig(type="il2cpp")
    backend = create_backend(cfg, metadata_dir=tmp_path)
    assert isinstance(backend, IL2CPPBackend)
