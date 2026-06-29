#!/usr/bin/env python3
"""McpFrisk -- Security Scanner für MCP-Server (Pre-Deploy/CI-Fokus).

Usage:
    mcpfrisk scan ./pfad/zum/server
    mcpfrisk scan ./pfad/zum/server --json report.json
    mcpfrisk scan ./pfad/zum/server --fail-on high --skip TOOL_POISONING
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mcpfrisk.core.models import Severity
from mcpfrisk.core.report import print_terminal_report, write_json_report
from mcpfrisk.core.runner import run_static_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpfrisk",
        description="Security Scanner für MCP-Server -- läuft vor dem Deploy, nicht beim Endnutzer.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scannt ein MCP-Server-Repo statisch.")
    scan_parser.add_argument("path", type=Path, help="Pfad zum MCP-Server-Quellcode")
    scan_parser.add_argument(
        "--json", type=Path, default=None,
        help="Schreibt zusätzlich einen JSON-Report an den angegebenen Pfad.",
    )
    scan_parser.add_argument(
        "--fail-on", type=str, default="high",
        choices=[s.value for s in Severity],
        help="Ab welchem Severity-Level der Exit-Code != 0 sein soll (Default: high). "
             "Für CI: 'critical' wäre permissiver, 'medium' strenger.",
    )
    scan_parser.add_argument(
        "--skip", type=str, nargs="*", default=[],
        help="Check-IDs, die übersprungen werden sollen, z.B. --skip TOOL_POISONING",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)

    parser.print_help()
    return 1


def _run_scan(args: argparse.Namespace) -> int:
    target_path: Path = args.path.resolve()
    if not target_path.exists():
        print(f"Fehler: Pfad '{target_path}' existiert nicht.", file=sys.stderr)
        return 2

    result = run_static_scan(target_path, skip_checks=set(args.skip))
    print_terminal_report(result)

    if args.json:
        write_json_report(result, args.json)
        print(f"JSON-Report geschrieben nach: {args.json}")

    fail_on = Severity(args.fail_on)
    if result.has_blocking_findings(fail_on=fail_on):
        print(f"\n❌ Build markiert als FAILED (Findings >= {fail_on.value.upper()} gefunden).")
        return 1

    print("\n✅ Build markiert als PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
