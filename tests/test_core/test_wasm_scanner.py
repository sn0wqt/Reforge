"""Unit tests for WebAssembly (WASM) binary scanner."""

from __future__ import annotations

from pathlib import Path

from reforge.core.scanners.wasm_scanner import WasmScanner


def _encode_leb128(val: int) -> bytes:
    res = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            b |= 0x80
        res.append(b)
        if val == 0:
            break
    return bytes(res)


def _encode_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _encode_leb128(len(raw)) + raw


def _build_synthetic_wasm(
    imported_funcs: list[tuple[str, str]] | None = None,
    exported_funcs: list[str] | None = None,
    producers: dict[str, list[str]] | None = None,
) -> bytes:
    buf = bytearray(b"\x00asm\x01\x00\x00\x00")

    # Section 1: Type (single void -> void)
    sec1 = bytearray([0x01, 0x60, 0x00, 0x00])  # 1 type: () -> ()
    buf.append(1)  # Section 1
    buf.extend(_encode_leb128(len(sec1)))
    buf.extend(sec1)

    # Section 2: Import
    if imported_funcs:
        sec2 = bytearray(_encode_leb128(len(imported_funcs)))
        for mod, field in imported_funcs:
            sec2.extend(_encode_string(mod))
            sec2.extend(_encode_string(field))
            sec2.append(0)  # func import
            sec2.extend(_encode_leb128(0))  # type 0
        buf.append(2)
        buf.extend(_encode_leb128(len(sec2)))
        buf.extend(sec2)

    # Section 3: Function
    if exported_funcs:
        sec3 = bytearray(_encode_leb128(len(exported_funcs)))
        for _ in exported_funcs:
            sec3.extend(_encode_leb128(0))  # type 0
        buf.append(3)
        buf.extend(_encode_leb128(len(sec3)))
        buf.extend(sec3)

    # Section 7: Export
    if exported_funcs:
        sec7 = bytearray(_encode_leb128(len(exported_funcs)))
        for idx, exp_name in enumerate(exported_funcs):
            sec7.extend(_encode_string(exp_name))
            sec7.append(0)  # func export
            sec7.extend(_encode_leb128(idx))
        buf.append(7)
        buf.extend(_encode_leb128(len(sec7)))
        buf.extend(sec7)

    # Section 0: Producers custom section
    if producers:
        sec0 = bytearray(_encode_string("producers"))
        sec0.extend(_encode_leb128(len(producers)))
        for k, v in producers.items():
            sec0.extend(_encode_string(k))
            sec0.extend(_encode_leb128(len(v)))
            for val in v:
                parts = val.split(" ", 1)
                sec0.extend(_encode_string(parts[0]))
                sec0.extend(_encode_string(parts[1] if len(parts) > 1 else ""))
        buf.append(0)
        buf.extend(_encode_leb128(len(sec0)))
        buf.extend(sec0)

    # Section 10: Code
    if exported_funcs:
        sec10 = bytearray(_encode_leb128(len(exported_funcs)))
        for _ in exported_funcs:
            code_body = b"\x00\x0b"  # 0 locals, end
            sec10.extend(_encode_leb128(len(code_body)))
            sec10.extend(code_body)
        buf.append(10)
        buf.extend(_encode_leb128(len(sec10)))
        buf.extend(sec10)

    return bytes(buf)


def test_is_wasm_binary() -> None:
    assert WasmScanner.is_wasm_binary(b"\x00asm\x01\x00\x00\x00")
    assert not WasmScanner.is_wasm_binary(b"MZ\x90\x00")
    assert not WasmScanner.is_wasm_binary(b"\x7fELF")
    assert not WasmScanner.is_wasm_binary(b"")


def test_scan_emscripten_wasm() -> None:
    data = _build_synthetic_wasm(
        imported_funcs=[("env", "___syscall_open"), ("env", "emscripten_notify_memory_growth")],
        exported_funcs=["_main", "stackSave", "stackAlloc"],
    )
    info = WasmScanner.scan_bytes(data)
    assert info is not None
    assert info.version == 1
    assert info.runtime == "emscripten"
    assert "env" in info.imported_modules
    assert "_main" in info.exported_functions
    assert "env.___syscall_open" in info.imported_functions
    assert any("emscripten" in n for n in info.notes)


def test_scan_wasi_wasm() -> None:
    data = _build_synthetic_wasm(
        imported_funcs=[("wasi_snapshot_preview1", "fd_write"), ("wasi_snapshot_preview1", "proc_exit")],
        exported_funcs=["_start"],
    )
    info = WasmScanner.scan_bytes(data)
    assert info is not None
    assert info.runtime == "wasi"
    assert "wasi_snapshot_preview1" in info.imported_modules
    assert "_start" in info.exported_functions


def test_scan_rust_wasm_producers() -> None:
    data = _build_synthetic_wasm(
        exported_funcs=["add", "multiply"],
        producers={"processed-by": ["rustc 1.78.0", "wasm-bindgen 0.2.92"]},
    )
    info = WasmScanner.scan_bytes(data)
    assert info is not None
    assert info.runtime == "rust"
    assert "producers" in info.custom_sections
    assert any("rustc" in p for p in info.producers.get("processed-by", []))


def test_scan_unity_webgl_wasm() -> None:
    data = _build_synthetic_wasm(
        imported_funcs=[("env", "UnitySoundInit")],
        exported_funcs=["UnityInvoke", "invoke_viii"],
    )
    info = WasmScanner.scan_bytes(data)
    assert info is not None
    assert info.runtime == "unity-webgl"


def test_scan_go_wasm() -> None:
    data = _build_synthetic_wasm(
        imported_funcs=[("go", "runtime.wasmExit"), ("go", "runtime.resetMemoryDataView")],
        exported_funcs=["run"],
    )
    info = WasmScanner.scan_bytes(data)
    assert info is not None
    assert info.runtime == "go"


def test_scan_file(tmp_path: Path) -> None:
    wasm_file = tmp_path / "module.wasm"
    wasm_file.write_bytes(_build_synthetic_wasm(exported_funcs=["compute"]))

    info = WasmScanner.scan_file(wasm_file)
    assert info is not None
    assert "compute" in info.exported_functions

    # Non-existent and corrupt
    assert WasmScanner.scan_file(tmp_path / "missing.wasm") is None
    bad_file = tmp_path / "bad.wasm"
    bad_file.write_bytes(b"corrupt")
    assert WasmScanner.scan_file(bad_file) is None
