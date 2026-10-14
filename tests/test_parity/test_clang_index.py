"""Tests for Clang AST indexing and compilation database support."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reforge.config.schema import ProjectProfile
from reforge.parity.clang_index import definitions
from reforge.parity.source_indexer import SourceIndexer


def test_definitions_invalid_database(tmp_path: Path) -> None:
    db = tmp_path / "compile_commands.json"
    db.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Compilation database must be a JSON array"):
        definitions(db, tmp_path)


def test_definitions_with_mocked_clang(tmp_path: Path) -> None:
    src = tmp_path / "app.cpp"
    # Text with non-ASCII characters to verify UTF-8 byte offset to char offset mapping
    content = "// \u00e9\u00e9 comment\nnamespace demo {\nvoid Helper() {}\n}\n"
    src.write_text(content, encoding="utf-8", newline="\n")

    db = tmp_path / "compile_commands.json"
    db.write_text(
        json.dumps([{"directory": str(tmp_path), "file": "app.cpp", "arguments": ["clang++", "-c", "app.cpp"]}]),
        encoding="utf-8",
    )

    ast_dump = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "NamespaceDecl",
                "name": "demo",
                "id": "0x123",
                "loc": {"file": str(src), "offset": 16},
                "inner": [
                    {
                        "kind": "FunctionDecl",
                        "name": "Helper",
                        "loc": {"file": str(src), "offset": 33},
                        "inner": [
                            {
                                "kind": "CompoundStmt",
                                "range": {
                                    "begin": {"offset": 47},
                                    "end": {"offset": 48, "tokLen": 1},
                                },
                            }
                        ],
                    }
                ],
            }
        ],
    }

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = json.dumps(ast_dump)

    with patch.object(subprocess, "run", return_value=mock_proc):
        defs = definitions(db, tmp_path)
        assert len(defs) == 1
        scope, name, path, decl_pos, start_pos, end_pos = defs[0]
        assert scope == "demo"
        assert name == "Helper"
        assert path == src.resolve()
        # 33 bytes with 2 multi-byte chars (4 bytes -> 2 chars) becomes char offset 31
        assert decl_pos == 31
        assert start_pos == 45
        assert end_pos == 47


def test_definitions_macro_expanded_body_raises(tmp_path: Path) -> None:
    src = tmp_path / "macro.cpp"
    src.write_text("void MacroFn() { }", encoding="utf-8")

    db = tmp_path / "compile_commands.json"
    db.write_text(
        json.dumps([{"directory": str(tmp_path), "file": "macro.cpp", "arguments": ["clang++", "-c", "macro.cpp"]}]),
        encoding="utf-8",
    )

    ast_dump = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "FunctionDecl",
                "name": "MacroFn",
                "loc": {"file": str(src), "offset": 0},
                "inner": [
                    {
                        "kind": "CompoundStmt",
                        "range": {
                            "begin": {},  # Missing offset indicates macro expansion
                            "end": {},
                        },
                    }
                ],
            }
        ],
    }

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = json.dumps(ast_dump)

    with (
        patch.object(subprocess, "run", return_value=mock_proc),
        pytest.raises(ValueError, match="Macro-expanded body cannot be safely replaced"),
    ):
        definitions(db, tmp_path)


def test_definitions_clang_failure_raises(tmp_path: Path) -> None:
    src = tmp_path / "fail.cpp"
    src.write_text("void Fail() {}", encoding="utf-8")

    db = tmp_path / "compile_commands.json"
    db.write_text(
        json.dumps([{"directory": str(tmp_path), "file": "fail.cpp", "arguments": ["clang++", "-c", "fail.cpp"]}]),
        encoding="utf-8",
    )

    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stderr = "error: unknown type name"

    with (
        patch.object(subprocess, "run", return_value=mock_proc),
        pytest.raises(ValueError, match="Clang could not index"),
    ):
        definitions(db, tmp_path)


def test_source_indexer_ast_integration(tmp_path: Path) -> None:
    src = tmp_path / "app.cpp"
    code = (
        "namespace app {\n"
        "int Calc::Foo(int x) { return x * 2; }\n"
        "int Calc::Foo(double x) { return int(x); }\n"
        "int Calc::operator()() { return 42; }\n"
        "}\n"
    )
    src.write_text(code, encoding="utf-8")

    db = tmp_path / "compile_commands.json"
    db.write_text("[]", encoding="utf-8")

    # Mock definitions returned from clang_index
    mocked_defs = [
        ("app::Calc", "Foo", src.resolve(), 16, 37, 54),
        ("app::Calc", "Foo", src.resolve(), 56, 79, 97),
        ("app::Calc", "operator()", src.resolve(), 99, 121, 135),
    ]

    with patch("reforge.parity.clang_index.definitions", return_value=mocked_defs):
        profile = ProjectProfile(compilation_database=str(db))
        indexer = SourceIndexer(tmp_path, profile)

        # Overloaded function: find_all returns 2, find returns None
        all_foo = indexer.find_all("app::Calc", "Foo")
        assert len(all_foo) == 2
        assert indexer.find("app::Calc", "Foo") is None

        # Operator function: find returns unique match
        op = indexer.find("app::Calc", "operator()")
        assert op is not None
        assert op.body == "{ return 42; }"

        all_op = indexer.find_all("app::Calc", "operator()")
        assert len(all_op) == 1

        # Non-matching class does not find free function
        assert indexer.find("NonExistent", "Foo") is None


def test_wrong_class_does_not_select_free_function(tmp_path: Path) -> None:
    (tmp_path / "f.cpp").write_text("int Foo() { return 1; }", encoding="utf-8")
    indexer = SourceIndexer(tmp_path)
    assert indexer.find("MissingClass", "Foo") is None
    assert indexer.find("", "Foo") is not None
    assert len(indexer.find_all("", "Foo")) == 1
    assert len(indexer.find_all("MissingClass", "Foo")) == 0


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_clang_index_real_compiler_if_available(tmp_path: Path, newline: str) -> None:
    if not shutil.which("clang++"):
        pytest.skip("clang++ is not available on this system")

    file = tmp_path / "f.cpp"
    file.write_text(
        "// \u00e9\u00e9\nnamespace app { struct C { int Foo(int); int Foo(double); int operator()(); }; }\n"
        "int app::C::Foo(int x) { return x; }\n"
        "int app::C::Foo(double x) { return int(x); }\n"
        "int app::C::operator()() { return 3; }\n",
        encoding="utf-8",
        newline=newline,
    )
    database = tmp_path / "compile_commands.json"
    database.write_text(
        json.dumps(
            [{"directory": str(tmp_path), "file": str(file), "arguments": ["clang++", "-std=c++17", "-c", str(file)]}]
        ),
        encoding="utf-8",
    )
    index = SourceIndexer(tmp_path, ProjectProfile(compilation_database=str(database)))
    assert len(index.find_all("app::C", "Foo")) == 2
    assert index.find("app::C", "Foo") is None
    operator = index.find("app::C", "operator()")
    assert operator and operator.body == "{ return 3; }"
    assert file.read_text(encoding="utf-8")[operator.body_start : operator.body_end] == operator.body
