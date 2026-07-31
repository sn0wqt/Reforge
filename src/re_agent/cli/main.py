"""CLI entry point for re-agent."""

from __future__ import annotations

import argparse

from re_agent import __version__


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value may not be negative")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="re-agent",
        description="Autonomous reverse engineering agent",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", default="re-agent.yaml", help="Config file path")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # init
    init_p = sub.add_parser("init", help="Initialize re-agent.yaml config file")
    init_p.add_argument("--profile", default=None, help="Use a built-in project profile template")

    # reverse
    rev_p = sub.add_parser("reverse", help="Reverse engineer functions")
    rev_p.add_argument("--address", help="Single function address to reverse")
    rev_p.add_argument("--class", dest="class_name", help="Class name for class-level reversal")
    rev_p.add_argument("--max-functions", type=_positive_int, default=None, help="Max functions per class")
    rev_p.add_argument("--max-rounds", type=_positive_int, default=None, help="Max review rounds per function")
    rev_p.add_argument("--dry-run", action="store_true", help="Show plan without executing")
    rev_p.add_argument("--skip-parity", action="store_true", help="Skip parity check after PASS")

    # parity
    par_p = sub.add_parser("parity", help="Run parity checks on hooked functions")
    par_p.add_argument("--address", action="append", help="Specific address (repeatable)")
    par_p.add_argument("--filter", help="Regex filter on symbol/class")
    par_p.add_argument("--limit", type=_positive_int, help="Max functions to check")
    par_p.add_argument("--skip-ghidra", action="store_true", help="Source-only checks")
    par_p.add_argument("--strict-exit", action="store_true", help="Exit 1 on RED")
    par_p.add_argument("--output", help="Output JSON report path")

    # status
    stat_p = sub.add_parser("status", help="Show reversal progress")
    stat_p.add_argument("--class", dest="class_name", help="Filter by class")
    stat_p.add_argument("--format", choices=["text", "json", "markdown"], default="text")

    # estimate
    estimate_p = sub.add_parser("estimate", help="Estimate token usage before a run")
    estimate_p.add_argument("--address", help="Single function address")
    estimate_p.add_argument("--class", dest="class_name", help="Class name to estimate")
    estimate_p.add_argument("--limit", type=_positive_int, default=50, help="Maximum functions to inspect")

    # batch
    batch_p = sub.add_parser(
        "batch",
        help="Autonomous metadata discovery and evidence-ranked artifact generation",
    )
    batch_p.add_argument("--auto-discover", action="store_true", help="Auto discover top functions & classes")
    batch_p.add_argument("--goal", help="Natural language goal prompt (e.g. 'find currency offset')")
    batch_p.add_argument("--symbol", help="Target symbol or function name")
    batch_p.add_argument("--string", help="Target string reference")
    batch_p.add_argument("--class", dest="class_name", help="Target class name")
    batch_p.add_argument("--binary", help="APK, IPA, DEX, native binary, ZIP, or extracted directory")
    batch_p.add_argument("--metadata-dir", help="Path to metadata directory (containing script.json, il2cpp.h, etc.)")
    batch_p.add_argument("--game-name", help="Optional game title for bundled knowledge matching")
    batch_p.add_argument(
        "--limit",
        type=_positive_int,
        default=50,
        help="Maximum candidates submitted for semantic refinement; local inventory remains complete",
    )
    batch_p.add_argument("--output-dir", help="Output source directory")

    # hook
    hook_p = sub.add_parser("hook", help="Generate platform-specific C++, Obj-C++, or Rust hook scaffolding")
    hook_p.add_argument("--address", help="Target function address")
    hook_p.add_argument("--symbol", help="Target function or symbol name")
    hook_p.add_argument("--class", dest="class_name", help="Target class name")
    hook_p.add_argument("--platform", help="Target platform (ios-arm64, android-arm64, windows-x64)")
    hook_p.add_argument("--language", choices=["cpp", "rust"], default="cpp", help="Output language (cpp, rust)")
    hook_p.add_argument("--dynamic", action="store_true", help="Generate dynamic IL2CPP / BNM symbol resolver hook")
    hook_p.add_argument("--output", help="Output file path")

    # trace
    trace_p = sub.add_parser("trace", help="Generate Frida TypeScript live runtime tracing scripts")
    trace_p.add_argument("--symbol", help="Target symbol or method name")
    trace_p.add_argument("--class", dest="class_name", help="Target class name")
    trace_p.add_argument("--address", help="Target raw memory address")
    trace_p.add_argument(
        "--assembly",
        default="Assembly-CSharp",
        help="IL2CPP assembly for --class tracing (default: Assembly-CSharp)",
    )
    trace_p.add_argument("--module", help="Native module containing --symbol")
    trace_p.add_argument("--output", help="Output script file path")

    # pipeline
    pipe_p = sub.add_parser(
        "pipeline",
        help="Automated analysis, candidate ranking, and review-artifact pipeline",
    )
    pipe_p.add_argument("--binary", help="Path to executable binary (e.g. GameAssembly.dll, libil2cpp.so, etc.)")
    pipe_p.add_argument("--metadata", help="Path to global-metadata.dat file")
    pipe_p.add_argument("--metadata-dir", help="Path to metadata directory (containing script.json, il2cpp.h, etc.)")
    pipe_p.add_argument(
        "--il2cpp-dumper",
        help="Explicitly trusted Il2CppDumper executable for Unity extraction",
    )
    pipe_p.add_argument("--goal", help="Natural language goal prompt (e.g. 'give infinite coins and keys')")
    pipe_p.add_argument("--output-dir", help="Output source directory")
    pipe_p.add_argument(
        "--patch-bundle",
        action="store_true",
        help="Enable static JS bundle patching (disabled by default to prevent crashes)",
    )
    pipe_p.add_argument(
        "--max-patches",
        type=_nonnegative_int,
        default=5,
        help="Maximum number of static bundle replacements allowed (default: 5)",
    )
    repack_group = pipe_p.add_mutually_exclusive_group()
    repack_group.add_argument(
        "--repack-apk",
        action="store_true",
        help="Non-interactively rebuild and sign an Android APK",
    )
    repack_group.add_argument(
        "--no-repack",
        action="store_true",
        help="Non-interactively output reports and hook files only",
    )

    # scan-strings
    scan_p = sub.add_parser(
        "scan-strings",
        help="Scan an extracted IPA directory with exact Mach-O address mapping when available",
    )
    scan_p.add_argument("--ipa-path", required=True, help="Path to extracted IPA package or app directory")
    scan_p.add_argument("--search", default=None, help="String query to search for")
    scan_p.add_argument("--output", default=None, help="JSON output file path")

    return parser


def _main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

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

        batch_result = cmd_batch(args)
        return batch_result[0] if isinstance(batch_result, tuple) else batch_result

    if args.command == "hook":
        from re_agent.cli.cmd_hook import cmd_hook

        return cmd_hook(args)

    if args.command == "trace":
        from re_agent.cli.cmd_trace import cmd_trace

        return cmd_trace(args)

    if args.command == "pipeline":
        from re_agent.cli.cmd_pipeline import cmd_pipeline

        return cmd_pipeline(args)

    if args.command == "scan-strings":
        from re_agent.cli.cmd_scan_strings import run_scan_strings

        return run_scan_strings(args)

    parser.print_help()
    return 1


def main(argv: list[str] | None = None) -> int:
    """Run the CLI with concise configuration/runtime error reporting."""
    try:
        return _main(argv)
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"[!] {exc}")
        return 2
