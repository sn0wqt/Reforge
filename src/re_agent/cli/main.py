"""CLI entry point for re-agent."""

from __future__ import annotations

import argparse
from typing import Any

from re_agent import __version__

_PLATFORM_CHOICES = (
    "android",
    "android-arm64",
    "ios",
    "ios-arm64",
    "windows",
    "windows-x64",
)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _port(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return parsed


def _command_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    **kwargs: Any,
) -> argparse.ArgumentParser:
    """Create a command parser without ambiguous long-option abbreviations."""
    return subparsers.add_parser(name, allow_abbrev=False, **kwargs)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="re-agent",
        description="Autonomous reverse engineering agent",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", default="re-agent.yaml", help="Config file path")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # init
    init_p = _command_parser(sub, "init", help="Initialize re-agent.yaml config file")
    init_p.add_argument("--profile", default=None, help="Use a built-in project profile template")

    # reverse
    rev_p = _command_parser(sub, "reverse", help="Reverse engineer functions")
    rev_p.add_argument("--address", help="Single function address to reverse")
    rev_p.add_argument("--class", dest="class_name", help="Class name for class-level reversal")
    rev_p.add_argument("--metadata-dir", help="IL2CPP dump metadata directory path")
    rev_p.add_argument("--dump", help="Compatibility alias for an IL2CPP dump directory")
    rev_p.add_argument("--binary", help="Binary or metadata input used by the configured backend")
    rev_p.add_argument("--max-functions", type=_positive_int, default=None, help="Max functions per class")
    rev_p.add_argument("--max-rounds", type=_positive_int, default=None, help="Max review rounds per function")
    rev_p.add_argument("--dry-run", action="store_true", help="Show plan without executing")
    rev_p.add_argument("--skip-parity", action="store_true", help="Skip parity check after PASS")

    # parity
    par_p = _command_parser(sub, "parity", help="Run parity checks on hooked functions")
    par_p.add_argument("--address", action="append", help="Specific address (repeatable)")
    par_p.add_argument("--filter", help="Regex filter on symbol/class")
    par_p.add_argument("--limit", type=_positive_int, help="Max functions to check")
    par_p.add_argument("--skip-ghidra", action="store_true", help="Source-only checks")
    par_p.add_argument("--strict-exit", action="store_true", help="Exit 1 on RED")
    par_p.add_argument("--output", help="Output JSON report path")

    # status
    stat_p = _command_parser(sub, "status", help="Show reversal progress")
    stat_p.add_argument("--class", dest="class_name", help="Filter by class")
    stat_p.add_argument("--format", choices=["text", "json", "markdown"], default="text")

    # estimate
    estimate_p = _command_parser(sub, "estimate", help="Estimate token usage before a run")
    estimate_p.add_argument("--address", help="Single function address")
    estimate_p.add_argument("--class", dest="class_name", help="Class name to estimate")
    estimate_p.add_argument("--limit", type=_positive_int, default=50, help="Maximum functions to inspect")

    # batch
    batch_p = _command_parser(
        sub,
        "batch",
        help="Autonomous metadata discovery and evidence-ranked artifact generation",
    )
    batch_p.add_argument("--binary", help="Binary or package path")
    batch_p.add_argument("--game-name", help="Game name filter")
    batch_p.add_argument("--symbol", help="Symbol search pattern")
    batch_p.add_argument("--string", help="Target string reference")
    batch_p.add_argument("--class", dest="class_name", help="Target class name")
    batch_p.add_argument("--metadata-dir", help="Metadata directory path")
    batch_p.add_argument("--metadata", help="Path to global-metadata.dat")
    batch_p.add_argument("--il2cpp-dumper", "--dumper", dest="il2cpp_dumper", help="IL2CPP dumper executable path")
    batch_p.add_argument("--auto-discover", action="store_true", help="Automatically discover candidates")
    batch_p.add_argument("--platform", choices=_PLATFORM_CHOICES, help="Target platform filter")
    batch_p.add_argument("--goal", help="Goal prompt for candidate ranking")
    batch_p.add_argument("--output-dir", help="Output directory path")
    batch_p.add_argument("--limit", type=_positive_int, default=50, help="Max candidates")
    batch_p.add_argument("--output", help="Output file path")

    # hook
    hook_p = _command_parser(sub, "hook", help="Generate platform-specific hook scaffolding")
    hook_p.add_argument("--binary", help="Binary path")
    hook_p.add_argument("--symbol", help="Target symbol")
    hook_p.add_argument("--class", dest="class_name", help="Target class name")
    hook_p.add_argument("--address", help="Target address")
    hook_p.add_argument("--platform", help="Target platform")
    hook_p.add_argument("--pathway", help="Target pathway")
    hook_p.add_argument("--language", choices=["cpp", "rust"], default="cpp", help="Target language")
    hook_p.add_argument("--dynamic", action="store_true", help="Generate a dynamic IL2CPP/BNM resolver hook")
    hook_p.add_argument("--output", help="Output file path")

    # trace
    trace_p = _command_parser(sub, "trace", help="Generate Frida runtime trace scripts")
    trace_p.add_argument("--binary", help="Binary path")
    trace_p.add_argument("--symbol", help="Target symbol")
    trace_p.add_argument("--class", dest="class_name", help="Target class")
    trace_p.add_argument("--address", help="Target address")
    trace_p.add_argument(
        "--assembly",
        default="Assembly-CSharp",
        help="IL2CPP assembly for class tracing (default: Assembly-CSharp)",
    )
    trace_p.add_argument("--module", help="Native module containing the symbol or RVA")
    live_target = trace_p.add_mutually_exclusive_group()
    live_target.add_argument("--attach", help="Attach Frida to a running process name")
    live_target.add_argument("--spawn", help="Spawn a package/process with Frida")
    live_device = trace_p.add_mutually_exclusive_group()
    live_device.add_argument("--usb", action="store_true", help="Use the connected USB Frida device")
    live_device.add_argument("--host", help="Use a remote Frida host (HOST:PORT)")
    trace_p.add_argument("--output", help="Output file path")

    # pipeline
    pipe_p = _command_parser(sub, "pipeline", help="Run the universal analysis and packaging pipeline")
    pipe_p.add_argument("--binary", default=None, help="Target binary or package path")
    pipe_p.add_argument("--metadata-dir", default=None, help="Pre-extracted metadata directory path")
    pipe_p.add_argument("--metadata", default=None, help="Path to global-metadata.dat")
    pipe_p.add_argument(
        "--il2cpp-dumper",
        "--dumper",
        dest="il2cpp_dumper",
        default=None,
        help="Explicitly trusted IL2CPP dumper path",
    )
    pipe_p.add_argument("--platform", choices=_PLATFORM_CHOICES, help="Explicit target platform for ambiguous metadata")
    pipe_p.add_argument("--goal", help="Reversing goal description")
    pipe_p.add_argument("--output-dir", help="Output directory")
    pipe_p.add_argument("--patch-bundle", action="store_true", help="Enable bounded textual JS bundle patching")
    pipe_p.add_argument("--max-patches", type=_positive_int, default=5, help="Maximum textual bundle replacements")
    pipe_p.add_argument(
        "--embed-frida-gadget",
        action="store_true",
        help="Embed matching local Frida Gadget libraries while rebuilding an Android APK",
    )
    pipe_p.add_argument(
        "--frida-gadget-path",
        help="Override the managed/local Gadget .so/.so.xz file or ABI directory",
    )
    pipe_p.add_argument(
        "--frida-gadget-sha256",
        help="Expected SHA-256 for a single Gadget input file",
    )
    pipe_p.add_argument(
        "--frida-gadget-version",
        help="Declared Gadget version recorded for host compatibility checks",
    )
    pipe_p.add_argument(
        "--frida-gadget-on-load",
        choices=["resume", "wait"],
        help="Whether Gadget lets the app resume immediately or waits for a controller",
    )
    pipe_p.add_argument(
        "--frida-gadget-port",
        type=_port,
        help="Gadget listen port (default: 27042)",
    )
    repack_group = pipe_p.add_mutually_exclusive_group()
    repack_group.add_argument("--repack-apk", action="store_true", help="Rebuild and sign APK")
    repack_group.add_argument("--no-repack", action="store_true", help="Output hook files only")

    # doctor
    doctor_p = _command_parser(sub, "doctor", help="Check analysis, packaging, and deployment tools")
    doctor_p.add_argument("--json", action="store_true", help="Emit machine-readable tool status")

    # scan-strings
    from re_agent.cli.cmd_scan_strings import register_subparser as register_scan_strings

    register_scan_strings(sub)

    return parser


def _main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if hasattr(args, "func"):
        handler = args.func
        if callable(handler):
            return _normalize_exit_code(handler(args))
        return 1

    if args.command == "init":
        from re_agent.cli.cmd_init import cmd_init

        return cmd_init(args)

    if args.command == "reverse":
        from re_agent.cli.cmd_reverse import cmd_reverse

        return cmd_reverse(args)

    if args.command == "parity":
        from re_agent.cli.cmd_parity import cmd_parity

        return cmd_parity(args)

    if args.command == "status":
        from re_agent.cli.cmd_status import cmd_status

        return cmd_status(args)

    if args.command == "estimate":
        from re_agent.cli.cmd_estimate import cmd_estimate

        return cmd_estimate(args)

    if args.command == "batch":
        from re_agent.cli.cmd_batch import cmd_batch

        return _normalize_exit_code(cmd_batch(args))

    if args.command == "hook":
        from re_agent.cli.cmd_hook import cmd_hook

        return cmd_hook(args)

    if args.command == "trace":
        from re_agent.cli.cmd_trace import cmd_trace

        return cmd_trace(args)

    if args.command == "pipeline":
        from re_agent.cli.cmd_pipeline import cmd_pipeline

        return cmd_pipeline(args)

    if args.command == "doctor":
        from re_agent.cli.cmd_doctor import cmd_doctor

        return cmd_doctor(args)

    parser.print_help()
    return 1


def _normalize_exit_code(result: object) -> int:
    if isinstance(result, int):
        return result
    if isinstance(result, tuple) and result and isinstance(result[0], int):
        return result[0]
    return 1


def main(argv: list[str] | None = None) -> int:
    """Run the CLI with concise configuration/runtime error reporting."""
    try:
        return _main(argv)
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"[!] {exc}")
        return 2
