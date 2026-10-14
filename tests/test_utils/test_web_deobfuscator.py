"""Unit tests for JavaScript unbundler, deobfuscator, and Electron IPC/bridge analysis."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from reforge.utils.web_deobfuscator import (
    analyze_web_bundle,
    decode_escaped_strings,
    deobfuscate_javascript,
    detect_bundler,
    extract_context_bridge,
    extract_electron_ipc,
    extract_module_dependencies,
    extract_module_exports,
    find_matching_delimiter,
    normalize_booleans_and_literals,
    normalize_commonjs_params,
    process_web_directory,
    run_wakaru_unbundler,
    unpack_string_arrays,
    unpack_webpack_bundle,
)


def test_find_matching_delimiter() -> None:
    code = "function test() { if (true) { return '{not_a_brace}'; } }"
    start = code.find("{")
    end = find_matching_delimiter(code, start, "{", "}")
    assert end == len(code) - 1

    # Unbalanced delimiter
    assert find_matching_delimiter(code, 0, "{", "}") == -1
    assert find_matching_delimiter("{ open without close", 0, "{", "}") == -1


def test_detect_bundler_webpack_chunk() -> None:
    chunk_code = """
    (self["webpackChunk_app"] = self["webpackChunk_app"] || []).push([
        ["chunk-main", "vendor"],
        {
            "./src/index.js": function (e, t, r) {
                console.log("hello");
            }
        }
    ]);
    """
    sig = detect_bundler(chunk_code)
    assert sig.bundler == "webpack"
    assert sig.is_chunk is True
    assert sig.is_bootstrap is False
    assert "chunk-main" in sig.chunk_ids
    assert "vendor" in sig.chunk_ids
    assert sig.runtime_name == "webpackChunk_app"


def test_detect_bundler_webpack_bootstrap() -> None:
    bootstrap_code = """
    !function(modules) {
        var installedModules = {};
        function __webpack_require__(moduleId) {
            if(installedModules[moduleId]) return installedModules[moduleId].exports;
            var module = installedModules[moduleId] = { i: moduleId, l: false, exports: {} };
            modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
            module.l = true;
            return module.exports;
        }
    }({
        0: function(e, t, r) { r(1); },
        1: function(e, t) { console.log("one"); }
    });
    """
    sig = detect_bundler(bootstrap_code)
    assert sig.bundler == "webpack"
    assert sig.is_bootstrap is True
    assert sig.is_chunk is False


def test_detect_bundler_esbuild_and_vite() -> None:
    esbuild_code = (
        "var __commonJS = (cb, mod) => function() { "
        "return mod || cb((mod = {exports: {}}).exports, mod), mod.exports; };"
    )
    assert detect_bundler(esbuild_code).bundler == "esbuild"

    vite_code = "const url = import.meta.url; console.log(__vite__);"
    assert detect_bundler(vite_code).bundler == "vite"

    browserify_code = "(function e(t,n,r){function s(o,u){...}})"
    assert detect_bundler(browserify_code).bundler == "browserify"


def test_unpack_webpack_bundle_object_table() -> None:
    bundle_code = """
    (self["webpackChunkdemo"] = self["webpackChunkdemo"] || []).push([
        ["main"],
        {
            "./src/auth.js": (function(module, exports, __webpack_require__) {
                const { ipcRenderer } = require("electron");
                const config = __webpack_require__("./src/config.js");
                ipcRenderer.invoke("auth:login", { token: "secret" });
                module.exports.login = true;
            }),
            1024: (function(e, t) {
                exports.version = "1.0.0";
            })
        }
    ]);
    """
    modules = unpack_webpack_bundle(bundle_code)
    assert len(modules) == 2

    auth_mod = next(m for m in modules if m.module_id == "./src/auth.js")
    assert "electron" in auth_mod.dependencies
    assert "./src/config.js" in auth_mod.dependencies
    assert "login" in auth_mod.export_names
    assert len(auth_mod.sha256) == 64
    assert auth_mod.size_bytes > 0
    assert auth_mod.start_offset < auth_mod.end_offset

    id_mod = next(m for m in modules if m.module_id == "1024")
    assert "version" in id_mod.export_names


def test_unpack_webpack_bundle_array_table() -> None:
    bundle_code = """
    (self["webpackChunkdemo"] = self["webpackChunkdemo"] || []).push([
        [0],
        [
            function(module, exports) {
                module.exports.id = 0;
            },
            function(module, exports) {
                module.exports.id = 1;
            }
        ]
    ]);
    """
    modules = unpack_webpack_bundle(bundle_code)
    assert len(modules) == 2
    assert modules[0].module_id == "0"
    assert modules[1].module_id == "1"


def test_extract_module_dependencies_and_exports() -> None:
    code = """
    const fs = require("node:fs");
    const net = __webpack_require__("net");
    import("dynamic-pkg");
    module.exports.alpha = 1;
    exports.beta = 2;
    export const gamma = 3;
    export default delta;
    """
    deps = extract_module_dependencies(code)
    assert "node:fs" in deps
    assert "net" in deps
    assert "dynamic-pkg" in deps

    exps = extract_module_exports(code)
    assert "alpha" in exps
    assert "beta" in exps
    assert "gamma" in exps


def test_decode_escaped_strings() -> None:
    encoded = (
        r'var greeting = "\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64"; '
        r'var name = "\u0041\u006c\u0069\u0063\u0065";'
    )
    decoded = decode_escaped_strings(encoded)
    assert 'greeting = "Hello World"' in decoded
    assert 'name = "Alice"' in decoded


def test_normalize_booleans_and_literals() -> None:
    code = "var a = !0; var b = !1; var c = void 0; var d = void(0); var e = ![]; var f = !![];"
    norm = normalize_booleans_and_literals(code)
    assert "var a = true;" in norm
    assert "var b = false;" in norm
    assert "var c = undefined;" in norm
    assert "var d = undefined;" in norm
    assert "var e = false;" in norm
    assert "var f = true;" in norm


def test_unpack_string_arrays() -> None:
    obfuscated = """
    var _0xa1b2 = ["secret_api_key", "admin_portal", "debug_mode"];
    var key = _0xa1b2[0];
    var endpoint = _0xa1b2[1];
    var hex = _0xa1b2[0x2];
    """
    unpacked = unpack_string_arrays(obfuscated)
    assert 'var key = "secret_api_key";' in unpacked
    assert 'var endpoint = "admin_portal";' in unpacked
    assert 'var hex = "debug_mode";' in unpacked


def test_normalize_commonjs_params() -> None:
    code = "var m = function(e, t, r) { e.exports = t; };"
    res = normalize_commonjs_params(code)
    assert "function(module, exports, require)" in res


def test_deobfuscate_javascript_pipeline() -> None:
    code = """
    var _0x99 = ["\x61\x70\x69\x5f\x6b\x65\x79"];
    var k = _0x99[0];
    var isReady = !0;
    var notReady = !1;
    var init = function(e, t, r) {
        return void 0;
    };
    """
    deob = deobfuscate_javascript(code)
    assert 'var k = "api_key";' in deob
    assert "var isReady = true;" in deob
    assert "var notReady = false;" in deob
    assert "return undefined;" in deob
    assert "function(module, exports, require)" in deob


def test_extract_electron_ipc() -> None:
    script = """
    // Line 2
    const { ipcRenderer } = require("electron");
    ipcRenderer.send("app:minimize");
    ipcRenderer.invoke("auth:token", { id: 123 });
    ipcRenderer.on("status:changed", (event, status) => { console.log(status); });
    ipcMain.handle("data:fetch", async (event, query) => { return []; });
    ipcMain.on("user:logout", () => {});
    ipcRenderer.send(dynamicChannelName);
    """
    findings = extract_electron_ipc(script)
    assert len(findings) == 6

    send_find = next(f for f in findings if f.operation == "send" and f.channel == "app:minimize")
    assert send_find.side == "renderer"
    assert send_find.mode == "send"
    assert send_find.line_number == 4

    invoke_find = next(f for f in findings if f.operation == "invoke")
    assert invoke_find.channel == "auth:token"
    assert invoke_find.mode == "invoke"

    handle_find = next(f for f in findings if f.operation == "handle")
    assert handle_find.side == "main"
    assert handle_find.channel == "data:fetch"
    assert handle_find.mode == "handle"

    dyn_find = next(f for f in findings if f.channel_expression == "dynamicChannelName")
    assert dyn_find.channel is None


def test_extract_context_bridge() -> None:
    script = """
    const { contextBridge, ipcRenderer } = require("electron");
    contextBridge.exposeInMainWorld("apiGateway", {
        sendNotification: (msg) => ipcRenderer.send("notify", msg),
        fetchUserProfile: async (id) => await ipcRenderer.invoke("user:profile", id),
        system: {
            getPlatform: () => process.platform,
            version: "2.0.0"
        }
    });
    contextBridge.exposeInIsolatedWorld(1001, "isolatedGateway", {
        ping: () => "pong"
    });
    """
    findings = extract_context_bridge(script)
    assert len(findings) == 2

    main_bridge = next(f for f in findings if f.world == "main")
    assert main_bridge.api_key == "apiGateway"
    assert "sendNotification" in main_bridge.members
    assert "fetchUserProfile" in main_bridge.members
    assert "system" in main_bridge.members
    assert "system.getPlatform" in main_bridge.members
    assert "system.version" in main_bridge.members

    isolated_bridge = next(f for f in findings if f.world == "isolated")
    assert isolated_bridge.api_key == "isolatedGateway"
    assert "ping" in isolated_bridge.members


def test_analyze_web_bundle_end_to_end(tmp_path: Path) -> None:
    code = """
    (self["webpackChunkhybrid"] = self["webpackChunkhybrid"] || []).push([
        ["chunk-app"],
        {
            "./src/index.js": function (e, t, r) {
                var isOk = !0;
                var { ipcRenderer } = r("electron");
                ipcRenderer.invoke("db:query", "SELECT 1");
                module.exports = { ready: isOk };
            }
        }
    ]);
    """
    file_path = tmp_path / "app.bundle.js"
    file_path.write_text(code, encoding="utf-8")

    result = analyze_web_bundle(file_path, try_wakaru=False)
    assert result.bundler_signature.bundler == "webpack"
    assert "chunk-app" in result.bundler_signature.chunk_ids
    assert len(result.modules) == 1
    assert result.modules[0].module_id == "./src/index.js"
    assert len(result.ipc_channels) == 1
    assert result.ipc_channels[0].channel == "db:query"
    assert result.engine_used == "reforge-builtin"


def test_process_web_directory(tmp_path: Path) -> None:
    dir_a = tmp_path / "www" / "js"
    dir_a.mkdir(parents=True)
    file1 = dir_a / "chunk1.js"
    file1.write_text("var a = !0;", encoding="utf-8")

    file2 = dir_a / "chunk2.cjs"
    file2.write_text("module.exports = 42;", encoding="utf-8")

    results = process_web_directory(tmp_path)
    assert len(results) == 2
    assert any("chunk1.js" in k for k in results)
    assert any("chunk2.cjs" in k for k in results)


def test_run_wakaru_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Test Wakaru execution bridge with mocked CLI runner
    bundle_file = tmp_path / "bundle.js"
    bundle_file.write_text("console.log('test');", encoding="utf-8")

    output_dir = tmp_path / "recovered"

    # Mock resolve_wakaru
    monkeypatch.setattr(
        "reforge.utils.web_deobfuscator.resolve_wakaru",
        lambda: Path("/fake/bin/wakaru"),
    )

    def _mock_run_cmd_split(args: Sequence[str], timeout_s: int = 120) -> tuple[int, str, str]:
        # Create staging module and provenance
        staging = output_dir / "modules"
        staging.mkdir(parents=True, exist_ok=True)
        mod = staging / "module_0.js"
        mod.write_text("module.exports = 'recovered';", encoding="utf-8")
        prov = staging / "provenance.json"
        prov.write_text(
            json.dumps({"modules": {"module_0.js": {"ranges": [[0, 20]]}}}),
            encoding="utf-8",
        )
        report_json = {
            "modules": [{"filename": "module_0.js"}],
            "warnings": [],
        }
        return 0, json.dumps(report_json), ""

    monkeypatch.setattr("reforge.utils.web_deobfuscator.run_cmd_split", _mock_run_cmd_split)

    result = run_wakaru_unbundler(bundle_file, output_dir)
    assert result is not None
    assert result.engine_used == "wakaru"
    assert len(result.modules) == 1
    assert result.modules[0].module_id == "module_0.js"
    assert "recovered" in result.modules[0].code
