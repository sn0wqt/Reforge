"""CLI command for IPA and Binary Asset String Scanning."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from re_agent.core.ipa_scanner import IPAScanner

logger = logging.getLogger(__name__)


def register_subparser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "scan-strings",
        help="Scan extracted IPA directory, plists, and binaries for strings with IDA base address mapping.",
    )
    parser.add_argument("--ipa-path", required=True, help="Path to extracted IPA package or app directory.")
    parser.add_argument("--search", default=None, help="String query to search for.")
    parser.add_argument("--output", default=None, help="JSON output file path.")
    parser.set_defaults(func=run_scan_strings)


def run_scan_strings(args: argparse.Namespace) -> int:
    ipa_path = Path(args.ipa_path)
    if not ipa_path.exists():
        print(f"[!] Path does not exist: {ipa_path}")
        return 2

    print(f"[*] Scanning IPA directory: {ipa_path}...")
    scanner = IPAScanner(ipa_path)
    results = scanner.scan(search_query=args.search)

    print(f"[+] Found {len(results)} string matches:")
    for r in results[:10]:
        print(f"    • [{r['type']}] {r['file']} -> {r['snippet']}")

    if args.output:
        out_p = Path(args.output)
        out_p.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"[+] Results saved to {out_p}")
    return 0
