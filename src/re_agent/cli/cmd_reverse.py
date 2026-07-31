"""re-agent reverse command — single function or class reversal."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from re_agent.config.loader import load_config
from re_agent.core.models import FunctionTarget
from re_agent.reports.formatter import format_result


def cmd_reverse(args: argparse.Namespace) -> int:
    config_path = Path(args.config) if (getattr(args, "config", None) and Path(args.config).exists()) else None
    config = load_config(config_path)

    if args.max_rounds is not None:
        config.orchestrator.max_review_rounds = args.max_rounds
    if args.skip_parity:
        config.parity.enabled = False

    if args.dry_run:
        return _dry_run(args, config)
    if not args.address and not args.class_name:
        print("Error: specify --address or --class", file=sys.stderr)
        return 1

    # Lazy imports to avoid loading LLM/backend unless needed
    from re_agent.backend.registry import create_backend
    from re_agent.config.policy import require_provider_allowed
    from re_agent.core.session import Session
    from re_agent.llm.registry import create_provider
    from re_agent.verification.candidate import validation_preflight_error

    reverser_config = config.agents.reverser or config.llm
    checker_config = config.agents.checker or config.llm
    validation_error = validation_preflight_error(config.validation)
    if validation_error:
        print(
            "Error: reversal acceptance is impossible with the current "
            f"validation config: {validation_error}. Configure trusted gates "
            "or explicitly set validation.require_verified=false.",
            file=sys.stderr,
        )
        return 2
    try:
        require_provider_allowed(
            config.data_handling,
            reverser_config,
            role="reverser",
        )
        require_provider_allowed(
            config.data_handling,
            checker_config,
            role="checker",
        )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    metadata_dir = getattr(args, "metadata_dir", None) or getattr(args, "dump", None) or getattr(args, "binary", None)
    backend = create_backend(config.backend, metadata_dir=metadata_dir)
    session = Session(config.output.session_file)

    if args.address:
        from re_agent.orchestrator.single import reverse_single

        class_name = args.class_name or ""
        function_name = ""

        # Try to resolve function metadata from the backend
        try:
            dec = backend.decompile(args.address)
            if dec.name and "::" in dec.name:
                resolved_class, _, function_name = dec.name.rpartition("::")
                if not class_name:
                    class_name = resolved_class
            elif dec.name:
                function_name = dec.name
        except Exception:
            pass  # Best-effort; objective validation will reject unresolved metadata
        if not function_name:
            print(
                "Error: backend could not resolve a function name for "
                f"{args.address}; refusing to reverse an anonymous target.",
                file=sys.stderr,
            )
            return 3

        target = FunctionTarget(
            address=args.address,
            class_name=class_name,
            function_name=function_name,
        )
        reverser_llm = create_provider(reverser_config)
        checker_llm = create_provider(checker_config)
        result = reverse_single(
            target,
            config,
            backend,
            reverser_llm,
            checker_llm=checker_llm,
            session=session,
        )
        print(format_result(result))
        return 0 if result.success else 1

    if args.class_name:
        from re_agent.orchestrator.class_runner import reverse_class

        reverser_llm = create_provider(reverser_config)
        checker_llm = create_provider(checker_config)
        results = reverse_class(
            class_name=args.class_name,
            config=config,
            backend=backend,
            llm=reverser_llm,
            checker_llm=checker_llm,
            session=session,
            max_functions=args.max_functions,
        )
        for r in results:
            print(format_result(r))
            print()

        passed = sum(1 for r in results if r.success)
        total = len(results)
        if total == 0:
            print(
                f"[!] Error: 0 exported functions found for class '{args.class_name}'. "
                "Run 'ghidra-bridge export all' in Ghidra first or pass '--metadata-dir'.",
                file=sys.stderr,
            )
            return 1
        print(f"\nResults: {passed}/{total} passed")
        return 0 if total > 0 and passed == total else 1

    return 1


def _dry_run(args: argparse.Namespace, config: object) -> int:
    print("Dry run mode — no LLM calls will be made.\n")

    if args.address:
        print(f"Would reverse: {args.address}")
        if args.class_name:
            print(f"  Class: {args.class_name}")
        return 0

    if args.class_name:
        from re_agent.config.schema import ReAgentConfig

        assert isinstance(config, ReAgentConfig)
        print(f"Would reverse functions in class: {args.class_name}")
        max_fn = args.max_functions or config.orchestrator.max_functions_per_class
        print(f"  Max functions: {max_fn}")
        print(f"  Max rounds per function: {args.max_rounds or config.orchestrator.max_review_rounds}")
        return 0

    print("Error: specify --address or --class", file=sys.stderr)
    return 1
