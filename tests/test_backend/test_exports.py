"""Tests for Ghidra JSON exports backend."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reforge.backend.exports import GhidraExportsBackend
from reforge.backend.protocol import BackendCapabilities, REBackend
from reforge.backend.registry import create_backend
from reforge.config.schema import BackendConfig


@pytest.fixture
def export_tree(tmp_path: Path) -> tuple[Path, Path]:
    export_dir = tmp_path / "exports"
    export_dir.mkdir()

    # Function 0x00401000
    fn_data = {
        "schema_version": 1,
        "address": "00401000",
        "name": "ProcessControl",
        "signature": "void ProcessControl(void)",
        "decompiled": "void ProcessControl(void) { return; }",
        "callers": [{"addr": "00402000", "name": "CallerOne", "ref_type": "CALL"}],
        "callees": [{"addr": "00403000", "name": "CalleeOne", "ref_type": "CALL"}],
        "data_refs": [{"addr": "00501000", "name": "g_State"}],
        "strings": ["Hello World"],
        "pcode": ["(unique, 0x0, 4) = COPY (const, 0x1, 4)"],
        "cfg": [{"index": 0, "out": []}],
        "assembly": ["MOV EAX, 1", "CALL 0x00403000", "RET"],
        "gaps": [],
    }
    (export_dir / "00401000.json").write_text(json.dumps(fn_data), encoding="utf-8")

    # Index
    index_data = {
        "00401000": {"name": "CTrain::ProcessControl"},
        "00402000": {"name": "CallerOne"},
    }
    (export_dir / "_index.json").write_text(json.dumps(index_data), encoding="utf-8")

    # Structs
    struct_data = {
        "CTrain": {
            "size_dec": 64,
            "fields": [
                {"field": "m_nFlags", "offset_hex": "0x00", "offset_dec": 0, "type": "int", "size": 4},
                {"field": "m_fSpeed", "offset_hex": "0x04", "offset_dec": 4, "type": "float", "size": 4},
            ],
        }
    }
    (export_dir / "_source_structs.json").write_text(json.dumps(struct_data), encoding="utf-8")

    # Address map
    map_file = tmp_path / "map.json"
    map_data = {
        "00401000": {"full_name": "CTrain::ProcessControl"},
        "00402000": {"full_name": "CTrain::CallerOne"},
    }
    map_file.write_text(json.dumps(map_data), encoding="utf-8")

    return export_dir, map_file


def test_exports_backend_is_re_backend(export_tree: tuple[Path, Path]) -> None:
    export_dir, map_file = export_tree
    backend = GhidraExportsBackend(str(export_dir), str(map_file))
    assert isinstance(backend, REBackend)
    caps = backend.capabilities
    assert isinstance(caps, BackendCapabilities)
    assert caps.has_decompile
    assert caps.has_xrefs
    assert caps.has_structs
    assert caps.has_context
    assert caps.has_pcode
    assert caps.has_cfg
    assert caps.has_asm
    assert caps.has_search


def test_exports_backend_decompile_and_address_map(export_tree: tuple[Path, Path]) -> None:
    export_dir, map_file = export_tree
    backend = GhidraExportsBackend(str(export_dir), str(map_file))

    res = backend.decompile("0x401000")
    assert res.address == "0x401000"
    assert res.name == "CTrain::ProcessControl"
    assert res.signature == "void ProcessControl(void)"
    assert res.decompiled == "void ProcessControl(void) { return; }"
    assert res.callers == 1
    assert res.callees == 1


def test_exports_backend_xrefs(export_tree: tuple[Path, Path]) -> None:
    export_dir, map_file = export_tree
    backend = GhidraExportsBackend(str(export_dir), str(map_file))

    to_refs = backend.xrefs_to("0x401000")
    assert len(to_refs) == 1
    assert to_refs[0].address == "00402000"
    assert to_refs[0].name == "CTrain::CallerOne"
    assert to_refs[0].ref_type == "CALL"

    from_refs = backend.xrefs_from("0x401000")
    assert len(from_refs) == 1
    assert from_refs[0].address == "00403000"
    assert from_refs[0].name == "CalleeOne"


def test_exports_backend_struct(export_tree: tuple[Path, Path]) -> None:
    export_dir, _ = export_tree
    backend = GhidraExportsBackend(str(export_dir))

    struct_def = backend.get_struct("CTrain")
    assert struct_def is not None
    assert struct_def.name == "CTrain"
    assert struct_def.size == 64
    assert len(struct_def.fields) == 2
    assert struct_def.fields[0].name == "m_nFlags"
    assert struct_def.fields[0].offset == 0
    assert struct_def.fields[1].name == "m_fSpeed"
    assert struct_def.fields[1].offset == 4

    assert backend.get_struct("NonExistent") is None


def test_exports_backend_context_and_artifacts(export_tree: tuple[Path, Path]) -> None:
    export_dir, _ = export_tree
    backend = GhidraExportsBackend(str(export_dir))

    ctx = backend.get_context("0x401000")
    assert ctx.kind == "function-context"
    data = json.loads(ctx.content)
    assert data["schema_version"] == 1
    assert data["target"] == "0x401000"
    assert data["globals"] == [{"addr": "00501000", "name": "g_State"}]

    pcode = backend.get_pcode("0x401000")
    assert pcode is not None
    assert pcode.kind == "pcode"

    cfg = backend.get_cfg("0x401000")
    assert cfg is not None
    assert cfg.kind == "cfg"

    asm = backend.get_asm("0x401000")
    assert asm is not None
    assert asm.instruction_count == 3
    assert asm.call_count == 1
    assert not asm.has_fp_sensitive


def test_exports_backend_search(export_tree: tuple[Path, Path]) -> None:
    export_dir, map_file = export_tree
    backend = GhidraExportsBackend(str(export_dir), str(map_file))

    found = backend.search("Process")
    assert len(found) == 1
    assert found[0].name == "ProcessControl"
    assert found[0].class_name == "CTrain"
    assert found[0].address == "00401000"

    assert len(backend.remaining("CTrain")) == 2
    assert len(backend.unimplemented("Missing")) == 0


def test_exports_backend_errors(tmp_path: Path) -> None:
    # Non-existent export directory
    with pytest.raises(ValueError, match="Export directory not found"):
        GhidraExportsBackend(str(tmp_path / "does_not_exist"))

    export_dir = tmp_path / "bad_exports"
    export_dir.mkdir()

    # Invalid schema version in file
    (export_dir / "00401000.json").write_text('{"schema_version": 999}', encoding="utf-8")
    backend = GhidraExportsBackend(str(export_dir))

    with pytest.raises(ValueError, match="Unsupported Ghidra JSON schema"):
        backend.decompile("0x401000")

    # Invalid non-hex target
    with pytest.raises(ValueError, match="hexadecimal"):
        backend.decompile("invalid_target")

    # Missing file
    with pytest.raises(ValueError, match="Function not found"):
        backend.decompile("0x402000")


def test_create_backend_ghidra_json(export_tree: tuple[Path, Path]) -> None:
    export_dir, map_file = export_tree
    cfg = BackendConfig(
        type="ghidra-json",
        export_dir=str(export_dir),
        address_map=str(map_file),
    )
    backend = create_backend(cfg)
    assert isinstance(backend, GhidraExportsBackend)

    cfg_no_dir = BackendConfig(type="ghidra-json")
    with pytest.raises(ValueError, match="backend.export_dir is required"):
        create_backend(cfg_no_dir)
