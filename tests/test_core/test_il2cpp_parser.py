"""Unit tests for IL2CPP metadata and Rodroid parser."""

from __future__ import annotations

import json
from subprocess import CompletedProcess, TimeoutExpired

from re_agent.core.il2cpp_parser import (
    find_il2cpp_metadata_in_dir,
    parse_dump_cs,
    parse_il2cpp_header,
    parse_rodroid_static_metadata,
    parse_script_json,
    run_il2cpp_dumper_cli,
)


def test_parse_script_json() -> None:
    data = {
        "ScriptMethod": [
            {"Name": "Player$$Update", "Address": 0x10004F210, "Signature": "void Player$$Update(Player* __this)"}
        ],
        "ScriptString": [{"Value": "Health", "Address": 0x100085C00}],
    }
    result = parse_script_json(json.dumps(data))
    assert len(result["methods"]) == 1
    assert result["methods"][0]["name"] == "Player$$Update"
    assert len(result["strings"]) == 1
    assert result["strings"][0]["value"] == "Health"


def test_parse_rodroid_static_metadata() -> None:
    data = {"FieldRVA": [{"name": "s_Instance", "rva": 0x1000}]}
    res = parse_rodroid_static_metadata(json.dumps(data))
    assert len(res["static_fields"]) == 1


def test_parse_dump_cs() -> None:
    dump_text = """
    // Namespace: Game.Core
    public class PlayerManager
    {
        // 0x18
        public int32_t currentHealth;

        // RVA: 0x1000 Offset: 0x1000 VA: 0x1000
        public int32_t get_TotalCoins() { }

        // RVA: 0x2000 Offset: 0x2000 VA: 0x2000
        public void add_OnCurrencyExchange(Delegate value) { }

        // RVA: 0x3000 Offset: 0x3000 VA: 0x3000
        public int GetCurrency(Dictionary<CurrencyType, int> values, CurrencyType type = default) { }
    }
    """
    classes = parse_dump_cs(dump_text)
    assert len(classes) == 1
    assert classes[0]["name"] == "PlayerManager"
    assert len(classes[0]["fields"]) == 1
    assert classes[0]["fields"][0]["name"] == "currentHealth"
    assert len(classes[0]["methods"]) == 3
    assert classes[0]["methods"][0]["return_type"] == "int32_t"
    assert classes[0]["methods"][0]["rva"] == 0x1000
    assert classes[0]["methods"][0]["address_kind"] == "method_rva"
    assert classes[0]["methods"][0]["is_event"] is False
    assert classes[0]["methods"][1]["is_event"] is True
    assert classes[0]["methods"][1]["parameter_types"] == ("Delegate",)
    assert classes[0]["methods"][1]["parameters"] == [{"type": "Delegate"}]
    assert classes[0]["methods"][2]["parameter_types"] == (
        "Dictionary<CurrencyType, int>",
        "CurrencyType",
    )


def test_parse_dump_cs_trailing_field_offsets() -> None:
    dump_text = """
    // Namespace: Game.Core
    public class Wallet
    {
        private int32_t coins; // 0x18
        public float balance; // 0x1C
    }
    """

    classes = parse_dump_cs(dump_text)

    assert classes[0]["fields"] == [
        {
            "type": "int32_t",
            "name": "coins",
            "offset": 0x18,
            "address_kind": "field_offset",
        },
        {
            "type": "float",
            "name": "balance",
            "offset": 0x1C,
            "address_kind": "field_offset",
        },
    ]


def test_parse_il2cpp_header() -> None:
    header = """
    struct PlayerScript {
        float health; // 0x18
        int32_t ammo; // 0x1C
    };
    """
    structs = parse_il2cpp_header(header)
    assert len(structs) == 1
    assert structs[0]["name"] == "PlayerScript"
    assert len(structs[0]["fields"]) == 2
    assert structs[0]["fields"][0]["offset"] == 0x18


def test_find_il2cpp_metadata_in_dir(tmp_path: any) -> None:
    script_json = tmp_path / "script.json"
    script_json.write_text(json.dumps({"ScriptMethod": [{"Name": "Test", "Address": 100}]}))
    res = find_il2cpp_metadata_in_dir(tmp_path)
    assert res is not None
    assert len(res["methods"]) == 1


def test_il2cpp_dumper_requires_a_supported_output_artifact(tmp_path, monkeypatch) -> None:
    dumper = tmp_path / "dumper.exe"
    binary = tmp_path / "libil2cpp.so"
    metadata = tmp_path / "global-metadata.dat"
    for path in (dumper, binary, metadata):
        path.write_bytes(b"fixture")
    monkeypatch.setattr(
        "re_agent.core.il2cpp_parser.subprocess.run",
        lambda command, **kwargs: CompletedProcess(command, 0, stdout="", stderr=""),
    )

    result = run_il2cpp_dumper_cli(
        binary,
        metadata,
        tmp_path / "out",
        dumper_path=dumper,
    )

    assert result["success"] is False
    assert "without producing" in result["error"]


def test_il2cpp_dumper_rejects_unchanged_stale_artifact(tmp_path, monkeypatch) -> None:
    dumper = tmp_path / "dumper.exe"
    binary = tmp_path / "libil2cpp.so"
    metadata = tmp_path / "global-metadata.dat"
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "dump.cs").write_text("stale output", encoding="utf-8")
    for path in (dumper, binary, metadata):
        path.write_bytes(b"fixture")
    monkeypatch.setattr(
        "re_agent.core.il2cpp_parser.subprocess.run",
        lambda command, **kwargs: CompletedProcess(command, 0, stdout="", stderr=""),
    )

    result = run_il2cpp_dumper_cli(
        binary,
        metadata,
        output_dir,
        dumper_path=dumper,
    )

    assert result["success"] is False
    assert result["artifacts"] == []
    assert "new supported metadata sidecar" in result["error"]


def test_il2cpp_dumper_accepts_new_nonempty_artifact(tmp_path, monkeypatch) -> None:
    dumper = tmp_path / "dumper.exe"
    binary = tmp_path / "libil2cpp.so"
    metadata = tmp_path / "global-metadata.dat"
    output_dir = tmp_path / "out"
    for path in (dumper, binary, metadata):
        path.write_bytes(b"fixture")

    def fake_run(command, **kwargs):
        output_dir.mkdir(exist_ok=True)
        (output_dir / "script.json").write_text('{"ScriptMethod": []}', encoding="utf-8")
        return CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("re_agent.core.il2cpp_parser.subprocess.run", fake_run)

    result = run_il2cpp_dumper_cli(
        binary,
        metadata,
        output_dir,
        dumper_path=dumper,
    )

    assert result["success"] is True
    assert result["error"] is None
    assert result["artifacts"] == [str(output_dir / "script.json")]


def test_il2cpp_dumper_reports_timeout_without_fallback(tmp_path, monkeypatch) -> None:
    dumper = tmp_path / "dumper.exe"
    binary = tmp_path / "libil2cpp.so"
    metadata = tmp_path / "global-metadata.dat"
    for path in (dumper, binary, metadata):
        path.write_bytes(b"fixture")
    calls = 0

    def time_out(command, **kwargs):
        nonlocal calls
        calls += 1
        assert kwargs["timeout"] == 7
        raise TimeoutExpired(command, 7)

    monkeypatch.setattr("re_agent.core.il2cpp_parser.subprocess.run", time_out)

    result = run_il2cpp_dumper_cli(
        binary,
        metadata,
        tmp_path / "out",
        dumper_path=dumper,
        timeout_s=7,
    )

    assert result["success"] is False
    assert result["error"] == "Il2CppDumper timed out after 7 seconds."
    assert calls == 1


def test_il2cpp_dumper_validates_inputs_before_starting_process(tmp_path, monkeypatch) -> None:
    def fail_if_called(*args, **kwargs):
        raise AssertionError("subprocess must not run for missing inputs")

    monkeypatch.setattr("re_agent.core.il2cpp_parser.subprocess.run", fail_if_called)

    result = run_il2cpp_dumper_cli(
        tmp_path / "missing-libil2cpp.so",
        tmp_path / "missing-global-metadata.dat",
        tmp_path / "out",
    )

    assert result["success"] is False
    assert "binary not found" in result["error"]


def test_il2cpp_dump_tolerates_invalid_utf8_in_comments(tmp_path) -> None:
    (tmp_path / "dump.cs").write_bytes(
        b"// obfuscated: \xff\npublic class Wallet\n{\n    public int32_t coins; // 0x18\n}\n"
    )

    result = find_il2cpp_metadata_in_dir(tmp_path)

    assert result is not None
    assert result["classes"][0]["fields"][0]["name"] == "coins"
