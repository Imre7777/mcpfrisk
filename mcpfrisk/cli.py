#!/usr/bin/env python3
"""McpFrisk -- Security Scanner für MCP-Server (Pre-Deploy/CI-Fokus).

Usage:
    mcpfrisk scan ./pfad/zum/server
    mcpfrisk scan ./pfad/zum/server --json report.json
    mcpfrisk scan ./pfad/zum/server --fail-on high --skip TOOL_POISONING
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from mcpfrisk.core.baseline import load_baseline, split_new_vs_known, write_baseline
from mcpfrisk.core.dynamic_runner import DynamicRunner, IdentityConfig
from mcpfrisk.core.fs import iter_source_files
from mcpfrisk.core.models import DynamicScanResult, Finding, ScanResult, Severity
from mcpfrisk.core.report import (
    print_dynamic_report,
    print_terminal_report,
    write_dynamic_json_report,
    write_json_report,
)
from mcpfrisk.core.runner import run_static_scan
from mcpfrisk.core.sarif import write_sarif_report
from mcpfrisk.core.sourcetree import jsts_available

_JSTS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}


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
    scan_parser.add_argument(
        "--write-tools-baseline", action="store_true",
        help="Pinnt die aktuellen Tool-Beschreibungen als Baseline "
             "(.mcpfrisk-tools.json) für TOOL_DESCRIPTION_DRIFT und beendet ohne "
             "Scan. Die Datei ins Repo committen; bei bewusster Änderung erneut "
             "ausführen (Rug-Pull-Schutz).",
    )
    scan_parser.add_argument(
        "--baseline", type=Path, default=None, metavar="PATH",
        help="Vergleicht Findings gegen eine gespeicherte Baseline-Datei -- nur "
             "NEUE Findings zählen für --fail-on. Fehlt die Datei, gilt das als "
             "leere Baseline (kein Fehler).",
    )
    scan_parser.add_argument(
        "--write-baseline", type=Path, default=None, metavar="PATH",
        help="Schreibt die aktuellen Findings als neue Baseline-Datei (z.B. "
             "nach Review, um den Stand als 'akzeptiert' festzuschreiben).",
    )
    scan_parser.add_argument(
        "--sarif", type=Path, default=None, metavar="PATH",
        help="Schreibt zusätzlich einen SARIF-2.1.0-Report (GitHub Code Scanning).",
    )

    probe_parser = subparsers.add_parser(
        "probe",
        help="Prüft einen LAUFENDEN MCP-Server dynamisch (Tier 2, z.B. AUTH_BOUNDARY).",
    )
    target_group = probe_parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--server", type=str, default=None,
        help="URL des laufenden MCP-HTTP-Endpunkts, z.B. http://localhost:8000/mcp",
    )
    target_group.add_argument(
        "--stdio", type=str, default=None, metavar="COMMAND",
        help="Startkommando eines stdio-MCP-Servers, z.B. --stdio \"python -m my_server\". "
             "ACHTUNG: führt den Befehl aus (Code-Ausführung) -- nur gegen Server "
             "richten, denen du vertraust bzw. die du gerade testest.",
    )
    probe_parser.add_argument(
        "--timeout", type=float, default=5.0,
        help="Maximale Wartezeit pro Anfrage in Sekunden (Default: 5).",
    )
    probe_parser.add_argument(
        "--fail-on", type=str, default="high",
        choices=[s.value for s in Severity],
        help="Ab welchem Severity-Level der Exit-Code != 0 sein soll (Default: high).",
    )
    probe_parser.add_argument(
        "--json", type=Path, default=None,
        help="Schreibt zusätzlich einen JSON-Report an den angegebenen Pfad.",
    )
    probe_parser.add_argument(
        "--skip", type=str, nargs="*", default=[],
        help="Check-IDs, die übersprungen werden sollen, z.B. --skip AUTH_BOUNDARY",
    )
    probe_parser.add_argument(
        "--identity", action="append", default=[], metavar="NAME=CRED",
        help="Aufrufer-Identität für RBAC_CROSS_TENANT, wiederholbar (die ersten "
             "zwei sind A/B). CRED darf 'env:VARNAME' sein -- empfohlen, damit "
             "Secrets nicht in argv/Shell-History landen. Beispiel: "
             "--identity \"A=env:TOKEN_A\" --identity \"B=env:TOKEN_B\".",
    )
    probe_parser.add_argument(
        "--auth-header", type=str, default="Authorization", metavar="NAME",
        help="HTTP-Header, über den die Identität angebunden wird (Default: "
             "Authorization -> 'Bearer <cred>'; bei Custom-Header wird <cred> verbatim gesendet).",
    )
    probe_parser.add_argument(
        "--identity-env", type=str, default="MCP_AUTH_TOKEN", metavar="VAR",
        help="stdio: Name der Env-Variable, die je Identitäts-Prozess auf das "
             "Credential gesetzt wird (Default: MCP_AUTH_TOKEN).",
    )
    probe_parser.add_argument(
        "--baseline", type=Path, default=None, metavar="PATH",
        help="Vergleicht Findings gegen eine gespeicherte Baseline-Datei -- nur "
             "NEUE Findings zählen für --fail-on. Fehlt die Datei, gilt das als "
             "leere Baseline (kein Fehler).",
    )
    probe_parser.add_argument(
        "--write-baseline", type=Path, default=None, metavar="PATH",
        help="Schreibt die aktuellen Findings als neue Baseline-Datei.",
    )

    return parser


def _make_output_utf8_safe() -> None:
    """Prevent UnicodeEncodeError on legacy consoles (e.g. Windows cp1252).

    The report uses non-ASCII status glyphs; on a non-UTF-8 console writing them
    would raise and crash the run. Reconfigure to UTF-8 with replacement so output
    degrades gracefully instead of aborting.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _make_output_utf8_safe()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)
    if args.command == "probe":
        return _run_probe(args)

    parser.print_help()
    return 1


def _apply_baseline(
    findings: list[Finding],
    target_path: Path | None,
    baseline_path: Path | None,
    write_baseline_path: Path | None,
) -> list[Finding]:
    """Wendet --baseline/--write-baseline an. Gibt die Findings zurück, die
    gegen --fail-on zählen sollen (mit --baseline: nur die neuen, sonst alle
    unverändert). Bekannte Findings bleiben im bereits gedruckten Report
    sichtbar (Prinzip III: nie kommentarlos verschwinden) -- diese Funktion
    entscheidet nur, was BLOCKIEREN darf, nie was angezeigt wird."""
    blocking = findings
    if baseline_path is not None:
        baseline = load_baseline(baseline_path)
        new, known = split_new_vs_known(findings, baseline, target_path)
        blocking = new
        if known:
            print(
                f"ℹ {len(known)} bekannte(s) Finding(s) aus der Baseline "
                f"({baseline_path}) zählen nicht für --fail-on, bleiben aber "
                "oben im Report sichtbar."
            )
    if write_baseline_path is not None:
        write_baseline(write_baseline_path, findings, target_path)
        print(f"Baseline geschrieben nach: {write_baseline_path} ({len(findings)} Finding(s)).")
    return blocking


def _run_scan(args: argparse.Namespace) -> int:
    target_path: Path = args.path.resolve()
    if not target_path.exists():
        print(f"Fehler: Pfad '{target_path}' existiert nicht.", file=sys.stderr)
        return 2

    # Pin-Aktion (kein Scan-Gate): den aktuellen Tool-Beschreibungs-Snapshot als
    # Baseline für TOOL_DESCRIPTION_DRIFT schreiben und beenden.
    if args.write_tools_baseline:
        from mcpfrisk.core import tool_baseline

        path = tool_baseline.baseline_path(target_path)
        snap = tool_baseline.snapshot(target_path)
        tool_baseline.write(path, snap)
        print(f"✅ Tool-Beschreibungs-Baseline gepinnt ({len(snap)} Tool(s)): {path}")
        print("   Die Datei ins Repo committen. Bei bewusster Änderung erneut ausführen.")
        return 0

    _warn_if_jsts_missing(target_path)
    result = run_static_scan(target_path, skip_checks=set(args.skip))
    print_terminal_report(result)

    if args.json:
        write_json_report(result, args.json)
        print(f"JSON-Report geschrieben nach: {args.json}")

    if args.sarif:
        write_sarif_report(result, args.sarif)
        print(f"SARIF-Report geschrieben nach: {args.sarif}")

    blocking_findings = _apply_baseline(
        result.findings, target_path, args.baseline, args.write_baseline
    )

    fail_on = Severity(args.fail_on)
    if ScanResult(target_path=target_path, findings=blocking_findings).has_blocking_findings(fail_on=fail_on):
        print(f"\n❌ Build markiert als FAILED (Findings >= {fail_on.value.upper()} gefunden).")
        return 1

    print("\n✅ Build markiert als PASSED.")
    return 0


def _warn_if_jsts_missing(target_path: Path) -> None:
    """Einmaliger Hinweis, wenn JS/TS-Code vorliegt, aber das jsts-Extra fehlt.

    Ohne den Parser werden JS/TS-Dateien nur eingeschränkt (bzw. gar nicht)
    geprüft -- das soll sichtbar sein, statt still als unauffällig durchzugehen
    (Prinzip III: nie stilles 'clean')."""
    if jsts_available():
        return
    if any(p.suffix.lower() in _JSTS_SUFFIXES for p in iter_source_files(target_path)):
        print(
            "ℹ JS/TS-Dateien gefunden, aber das jsts-Extra fehlt -- diese Dateien "
            "werden nur eingeschränkt geprüft (kein AST). Für volle Analyse:\n"
            "  pip install mcpfrisk[jsts]",
            file=sys.stderr,
        )


def _parse_identities(specs: list[str]) -> IdentityConfig | None:
    """Baut die IdentityConfig aus --identity NAME=CRED (mit env:-Indirektion).
    Gibt None zurück, wenn eine Angabe ungültig ist (Aufrufer bricht dann ab)."""
    identities: dict[str, str] = {}
    for spec in specs:
        if "=" not in spec:
            print(f"Fehler: --identity erwartet NAME=CRED, bekam '{spec}'.", file=sys.stderr)
            return None
        name, cred = spec.split("=", 1)
        name = name.strip()
        if not name:
            print(f"Fehler: leerer Identitäts-Name in '{spec}'.", file=sys.stderr)
            return None
        if cred.startswith("env:"):
            var = cred[len("env:"):]
            resolved = os.environ.get(var)
            if not resolved:
                print(
                    f"Fehler: Umgebungsvariable '{var}' für Identität '{name}' "
                    "ist nicht gesetzt/leer.",
                    file=sys.stderr,
                )
                return None
            cred = resolved
        identities[name] = cred
    return IdentityConfig(identities=identities)


def _run_probe(args: argparse.Namespace) -> int:
    # Genau eines von --server/--stdio ist gesetzt (mutually exclusive, required).
    # Ein nacktes Kommando ohne http(s):// wird vom Transport-Factory als stdio
    # erkannt; ein 'stdio:'-Präfix macht die Absicht im Report explizit.
    target = args.server if args.server is not None else f"stdio:{args.stdio}"

    identity_config = _parse_identities(args.identity)
    if identity_config is None:
        return 2
    identity_config.auth_header = args.auth_header
    identity_config.identity_env = args.identity_env

    runner = DynamicRunner(timeout_s=args.timeout, identity_config=identity_config)
    result = runner.run(target, skip_checks=set(args.skip))
    print_dynamic_report(result)

    if args.json:
        write_dynamic_json_report(result, args.json)
        print(f"JSON-Report geschrieben nach: {args.json}")

    blocking_findings = _apply_baseline(result.findings, None, args.baseline, args.write_baseline)

    fail_on = Severity(args.fail_on)
    if DynamicScanResult(target=target, findings=blocking_findings).has_blocking_findings(fail_on=fail_on):
        print(f"\n❌ Build markiert als FAILED (Findings >= {fail_on.value.upper()} gefunden).")
        return 1

    # INCONCLUSIVE zählt bewusst NICHT als Fehler -- aber auch nicht als Pass.
    if result.checks_run:
        print("\n✅ Build markiert als PASSED.")
    else:
        print("\nℹ Kein durchsetzbares Urteil (alle Checks inconclusive) -- kein Fehler, aber kein Pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
