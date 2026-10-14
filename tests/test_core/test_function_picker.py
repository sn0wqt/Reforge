"""Tests for function picker."""

from __future__ import annotations

from pathlib import Path

from reforge.backend.stub import StubBackend
from reforge.core.function_picker import pick_next
from reforge.core.models import FunctionEntry
from reforge.core.session import Session


def test_pick_next_returns_highest_caller(tmp_path: Path) -> None:
    session = Session(tmp_path / "progress.json")
    backend = StubBackend(
        remaining_functions=[
            FunctionEntry(address="0x100", name="Foo", class_name="CTest", caller_count=5),
            FunctionEntry(address="0x200", name="Bar", class_name="CTest", caller_count=10),
        ]
    )
    result = pick_next("CTest", backend, session)
    assert result is not None
    assert result.function_name == "Bar"
    assert result.caller_count == 10


def test_pick_next_skips_completed(tmp_path: Path) -> None:
    from reforge.core.models import FunctionTarget, ReversalResult

    session = Session(tmp_path / "progress.json")
    # Record one as completed
    session.record_result(
        ReversalResult(
            target=FunctionTarget(address="0x200", class_name="CTest", function_name="Bar"),
            code="",
            checker_verdict=None,
            parity_status=None,
            parity_findings=[],
            rounds_used=1,
            success=True,
        )
    )

    backend = StubBackend(
        remaining_functions=[
            FunctionEntry(address="0x100", name="Foo", class_name="CTest", caller_count=5),
            FunctionEntry(address="0x200", name="Bar", class_name="CTest", caller_count=10),
        ]
    )
    result = pick_next("CTest", backend, session)
    assert result is not None
    assert result.function_name == "Foo"


def test_pick_next_returns_none_when_empty(tmp_path: Path) -> None:
    session = Session(tmp_path / "progress.json")
    backend = StubBackend(remaining_functions=[])
    result = pick_next("CTest", backend, session)
    assert result is None


def test_pick_next_dependency_order_prefers_low_caller_count(tmp_path: Path) -> None:
    session = Session(tmp_path / "progress.json")
    backend = StubBackend(
        remaining_functions=[
            FunctionEntry(address="0x100", name="Leaf", class_name="CTest", caller_count=1),
            FunctionEntry(address="0x200", name="Hub", class_name="CTest", caller_count=20),
        ]
    )
    result = pick_next("CTest", backend, session, strategy="dependency-order")
    assert result is not None
    assert result.function_name == "Leaf"


def test_pick_next_dependency_order_handles_cycles_and_non_hex_xrefs(tmp_path: Path) -> None:
    from reforge.core.models import XRef

    class CyclicBackend(StubBackend):
        def __init__(self, remaining_functions: list[FunctionEntry], xrefs_map: dict[str, list[XRef]]) -> None:
            super().__init__(remaining_functions)
            self._xrefs_map = xrefs_map

        def xrefs_from(self, target: str) -> list[XRef]:
            return self._xrefs_map.get(target, [])

    session = Session(tmp_path / "progress.json")
    backend = CyclicBackend(
        remaining_functions=[
            FunctionEntry(address="0x100", name="FuncA", class_name="CTest", caller_count=5),
            FunctionEntry(address="0x200", name="FuncB", class_name="CTest", caller_count=10),
            FunctionEntry(address="0x300", name="FuncC", class_name="CTest", caller_count=2),
        ],
        xrefs_map={
            # Cycle between 0x100 and 0x200, plus an invalid non-hex external xref
            "0x100": [XRef("0x200", "FuncB", "CALL"), XRef("external_symbol", "External", "CALL")],
            "0x200": [XRef("0x100", "FuncA", "CALL")],
            "0x300": [],
        },
    )

    result = pick_next("CTest", backend, session, strategy="dependency-order")
    assert result is not None
    # All candidates ordered without hanging or crashing on cycles/non-hex symbols
    assert result.function_name in {"FuncA", "FuncB", "FuncC"}

