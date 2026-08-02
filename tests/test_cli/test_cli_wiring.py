"""Regression tests for public CLI/parser and handler parity."""

from __future__ import annotations

import pytest

from re_agent.cli.main import build_parser


def test_recovered_pipeline_options_are_exact() -> None:
    args = build_parser().parse_args(
        [
            "pipeline",
            "--metadata",
            "global-metadata.dat",
            "--metadata-dir",
            "Dump0",
            "--platform",
            "ios",
            "--max-patches",
            "1",
        ]
    )
    assert args.metadata == "global-metadata.dat"
    assert args.metadata_dir == "Dump0"
    assert args.platform == "ios"
    assert args.max_patches == 1


def test_recovered_batch_and_hook_options_are_exposed() -> None:
    batch = build_parser().parse_args(["batch", "--string", "wallet", "--metadata", "global-metadata.dat"])
    assert batch.string == "wallet"
    assert batch.metadata == "global-metadata.dat"

    hook = build_parser().parse_args(["hook", "--class", "Wallet", "--symbol", "GetCoins", "--dynamic"])
    assert hook.class_name == "Wallet"
    assert hook.dynamic is True


def test_reverse_metadata_input_is_wired() -> None:
    args = build_parser().parse_args(["reverse", "--class", "Wallet", "--metadata-dir", "Dump0"])

    assert args.class_name == "Wallet"
    assert args.metadata_dir == "Dump0"


def test_recovered_trace_live_options_are_exposed() -> None:
    args = build_parser().parse_args(
        [
            "trace",
            "--class",
            "Wallet",
            "--assembly",
            "Game.Runtime",
            "--module",
            "libil2cpp.so",
            "--attach",
            "Gadget",
            "--host",
            "127.0.0.1:27042",
        ]
    )
    assert args.assembly == "Game.Runtime"
    assert args.module == "libil2cpp.so"
    assert args.attach == "Gadget"
    assert args.host == "127.0.0.1:27042"


def test_gadget_options_are_explicit_and_local_only() -> None:
    args = build_parser().parse_args(
        [
            "pipeline",
            "--embed-frida-gadget",
            "--frida-gadget-path",
            "gadget",
            "--frida-gadget-sha256",
            "a" * 64,
            "--frida-gadget-version",
            "17.15.2",
            "--frida-gadget-on-load",
            "wait",
            "--frida-gadget-port",
            "28042",
        ]
    )
    assert args.embed_frida_gadget is True
    assert args.frida_gadget_path == "gadget"
    assert args.frida_gadget_port == 28042


@pytest.mark.parametrize(
    "argv",
    [
        ["batch", "--limit", "0"],
        ["reverse", "--max-functions", "-1"],
        ["pipeline", "--max-patches", "0"],
        ["pipeline", "--frida-gadget-port", "65536"],
    ],
)
def test_numeric_contracts_fail_closed(argv: list[str]) -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)


def test_long_options_do_not_abbreviate() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["pipeline", "--metad", "anything"])
