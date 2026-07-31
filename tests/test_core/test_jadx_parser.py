"""Unit tests for Kotlin/DEX Smali parser and JADX bridge."""
from __future__ import annotations

from re_agent.core.jadx_parser import decompile_apk_or_dex, parse_smali_instructions


def test_parse_smali_instructions() -> None:
    smali_code = """
    .method public updateHealth(I)V
        .registers 3
        const/4 v0, 0x64
        invoke-virtual {p0, v0}, Lcom/example/Player;->setHealth(I)V
        return-void
    .end method
    """
    methods = parse_smali_instructions(smali_code)
    assert len(methods) == 1
    assert "updateHealth" in methods[0]["signature"]
    assert len(methods[0]["invokes"]) == 1
    assert methods[0]["invokes"][0]["class_name"] == "com/example/Player"
    assert methods[0]["invokes"][0]["method_name"] == "setHealth"


def test_parse_smali_interface_and_custom_invokes() -> None:
    smali_code = """
    .method public run()V
        invoke-interface {p0}, Ljava/lang/Runnable;->run()V
        invoke-custom {p0}, call_site_0("apply", (Ljava/lang/Object;)Ljava/lang/Object;)
        return-void
    .end method
    """

    invokes = parse_smali_instructions(smali_code)[0]["invokes"]

    assert invokes[0]["class_name"] == "java/lang/Runnable"
    assert invokes[0]["method_name"] == "run"
    assert invokes[1]["class_name"] == ""
    assert invokes[1]["method_name"] == "call_site_0"


def test_decompile_apk_or_dex_missing_jadx(tmp_path: any) -> None:
    res = decompile_apk_or_dex("nonexistent.apk", tmp_path)
    # Will gracefully return error if JADX is not installed
    assert "output_dir" in res
