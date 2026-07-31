"""CLI entry point for re-agent."""
from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="re-agent",
        description="Autonomous reverse engineering agent",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.2.0")
    parser.add_argument("--config", default="re-agent.yaml", help="Config file path")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # init
    init_p = sub.add_parser("init", help="Initialize re-agent.yaml config file")
    init_p.add_argument("--profile", default=None, help="Use a built-in project profile template")

    # reverse
    rev_p = sub.add_parser("reverse", help="Reverse engineer functions")
    rev_p.add_argument("--address", help="Single function address to reverse")
    rev_p.add_argument("--class", dest="class_name", help="Class name for class-level reversal")
    rev_p.add_argument("--metadata-dir", help="IL2CPP dump metadata directory path")
    rev_p.add_argument("--max-functions", type=int, default=None, help="Max functions per class")
    rev_p.add_argument("--max-rounds", type=int, default=None, help="Max review rounds per function")
    rev_p.add_argument("--dry-run", action="store_true", help="Show plan without executing")
    rev_p.add_argument("--skip-parity", action="store_true", help="Skip parity check after PASS")

    # parity
    par_p = sub.add_parser("parity", help="Run parity checks on hooked functions")
    par_p.add_argument("--address", action="append", help="Specific address (repeatable)")
    par_p.add_argument("--filter", help="Regex filter on symbol/class")
    par_p.add_argument("--limit", type=int, help="Max functions to check")
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
    estimate_p.add_argument("--limit", type=int, default=50, help="Maximum functions to inspect")

    # batch
    batch_p = sub.add_parser("batch", help="Run batch candidate discovery")
    batch_p.add_argument("--binary", help="Binary or package path")
    batch_p.add_argument("--game-name", help="Game name filter")
    batch_p.add_argument("--symbol", help="Symbol search pattern")
    batch_p.add_argument("--class", dest="class_name", help="Target class name")
    batch_p.add_argument("--metadata-dir", help="Metadata directory path")
    batch_p.add_argument("--il2cpp-dumper", help="IL2CPP dumper executable path")
    batch_p.add_argument("--auto-discover", action="store_true", help="Automatically discover candidates")
    batch_p.add_argument("--platform", help="Target platform filter")
    batch_p.add_argument("--goal", help="Goal prompt for candidate ranking")
    batch_p.add_argument("--output-dir", help="Output directory path")
    batch_p.add_argument("--limit", type=int, default=50, help="Max candidates")
    batch_p.add_argument("--output", help="Output file path")

    # hook
    hook_p = sub.add_parser("hook", help="Generate hook code")
    hook_p.add_argument("--binary", help="Binary path")
    hook_p.add_argument("--symbol", help="Target symbol")
    hook_p.add_argument("--address", help="Target address")
    hook_p.add_argument("--platform", help="Target platform")
    hook_p.add_argument("--pathway", help="Target pathway")
    hook_p.add_argument("--language", help="Target language")
    hook_p.add_argument("--output", help="Output file path")

    # trace
    trace_p = sub.add_parser("trace", help="Generate trace script")
    trace_p.add_argument("--binary", help="Binary path")
    trace_p.add_argument("--symbol", help="Target symbol")
    trace_p.add_argument("--class", dest="class_name", help="Target class")
    trace_p.add_argument("--address", help="Target address")
    trace_p.add_argument("--output", help="Output file path")

    # pipeline
    pipe_p = sub.add_parser("pipeline", help="Run universal pipeline")
    pipe_p.add_argument("--binary", default=None, help="Target binary or package path")
    pipe_p.add_argument("--metadata-dir", default=None, help="Pre-extracted metadata directory path")
    pipe_p.add_argument("--dumper", default=None, help="Custom IL2CPP dumper binary path")
    pipe_p.add_argument("--il2cpp-dumper", default=None, help="IL2CPP dumper executable path")
    pipe_p.add_argument("--goal", help="Reversing goal description")
    pipe_p.add_argument("--output-dir", help="Output directory")
    pipe_p.add_argument("--patch-bundle", nargs="?", const=True, default=None, help="Explicit patch bundle file")
    pipe_p.add_argument("--max-patches", type=int, default=10, help="Maximum patch candidates")
    repack_group = pipe_p.add_mutually_exclusive_group()
    repack_group.add_argument("--repack-apk", action="store_true", help="Rebuild and sign APK")
    repack_group.add_argument("--no-repack", action="store_true", help="Output hook files only")

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
        return args.func(args)

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
        return cmd_batch(args)

    if args.command == "hook":
        from re_agent.cli.cmd_hook import cmd_hook
        return cmd_hook(args)

    if args.command == "trace":
        from re_agent.cli.cmd_trace import cmd_trace
        return cmd_trace(args)

    if args.command == "pipeline":
        from re_agent.cli.cmd_pipeline import cmd_pipeline
        return cmd_pipeline(args)

    parser.print_help()
    return 1


def main(argv: list[str] | None = None) -> int:
    """Run the CLI with concise configuration/runtime error reporting."""
    try:
        return _main(argv)
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"[!] {exc}")
        return 2
