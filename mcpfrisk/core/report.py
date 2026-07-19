"""Formatiert ScanResult für Terminal-Ausgabe (CI-freundlich) und JSON-Export."""
from __future__ import annotations

import json
from pathlib import Path

from mcpfrisk.core.models import (
    BoundaryOutcome,
    DynamicScanResult,
    ScanResult,
    Severity,
)

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def print_terminal_report(result: ScanResult) -> None:
    findings = result.sorted_findings()

    print(f"\nMcpFrisk -- Scan von {result.target_path}\n")
    print(f"Checks ausgeführt: {', '.join(result.checks_run) or '(keine)'}")
    if result.checks_skipped:
        print(f"Checks übersprungen: {', '.join(result.checks_skipped)}")
    print()

    if not findings:
        print("✅ Keine Findings. (Das ersetzt keine vollständige Sicherheitsprüfung!)\n")
        return

    counts = {sev: len(result.by_severity(sev)) for sev in Severity}
    summary = "  ".join(
        f"{SEVERITY_ICONS[sev]} {sev.value.upper()}: {counts[sev]}"
        for sev in Severity
        if counts[sev] > 0
    )
    print(f"Zusammenfassung: {summary}\n")
    print("-" * 70)

    for finding in findings:
        icon = SEVERITY_ICONS[finding.severity]
        location = ""
        if finding.file_path:
            location = f"{finding.file_path}"
            if finding.line_number:
                location += f":{finding.line_number}"

        print(f"\n{icon} [{finding.severity.value.upper()}] {finding.title}")
        if location:
            print(f"   📍 {location}")
        if finding.owasp_mcp_ref:
            print(f"   📋 OWASP MCP Top 10: {finding.owasp_mcp_ref}  |  CWE: {finding.cwe_ref or '-'}")
        print(f"   {finding.description}")
        if finding.snippet:
            print(f"   > {finding.snippet}")
        if finding.remediation:
            print(f"   💡 Fix: {finding.remediation}")

    print("\n" + "-" * 70)
    print(f"\nGesamt: {len(findings)} Finding(s)\n")


def print_dynamic_report(result: DynamicScanResult) -> None:
    """Terminal-Ausgabe für einen dynamischen (Tier-2-)Scan."""
    findings = result.sorted_findings()

    print(f"\nMcpFrisk (dynamisch) -- Probe von {result.target}\n")
    print(f"Checks ausgeführt: {', '.join(result.checks_run) or '(keine)'}")
    if result.checks_inconclusive:
        print(f"Checks ohne Urteil (inconclusive): {', '.join(result.checks_inconclusive)}")
    print()

    if findings:
        counts = {sev: len(result.by_severity(sev)) for sev in Severity}
        summary = "  ".join(
            f"{SEVERITY_ICONS[sev]} {sev.value.upper()}: {counts[sev]}"
            for sev in Severity
            if counts[sev] > 0
        )
        print(f"Zusammenfassung: {summary}\n")
        print("-" * 70)
        for finding in findings:
            icon = SEVERITY_ICONS[finding.severity]
            print(f"\n{icon} [{finding.severity.value.upper()}] {finding.title}")
            if finding.owasp_mcp_ref:
                print(f"   📋 OWASP MCP Top 10: {finding.owasp_mcp_ref}  |  CWE: {finding.cwe_ref or '-'}")
            print(f"   {finding.description}")
            if finding.snippet:
                print(f"   > {finding.snippet}")
            if finding.remediation:
                print(f"   💡 Fix: {finding.remediation}")
        print("\n" + "-" * 70)
        print(f"\nGesamt: {len(findings)} Finding(s)\n")
    elif result.checks_run:
        # Mindestens ein Check kam zu einem Urteil und fand nichts.
        print(f"✅ Keine Findings ({', '.join(result.checks_run)}).\n")

    _print_inconclusive_details(result)


def _print_inconclusive_details(result: DynamicScanResult) -> None:
    inconclusive = [
        b for b in result.boundary_results if b.outcome == BoundaryOutcome.INCONCLUSIVE
    ]
    if not inconclusive:
        return
    print("Hinweise (inconclusive -- weder Pass noch Finding):")
    for boundary in inconclusive:
        reasons = "; ".join(p.observed for p in boundary.probes) or "kein Ergebnis"
        print(f"  ℹ {boundary.check_id} @ {boundary.target}: {reasons}")
    print()


def write_dynamic_json_report(result: DynamicScanResult, output_path: Path) -> None:
    data = {
        "target": result.target,
        "checks_run": result.checks_run,
        "checks_inconclusive": result.checks_inconclusive,
        "findings": [f.to_dict() for f in result.sorted_findings()],
        "boundary_results": [b.to_dict() for b in result.boundary_results],
        "summary": {sev.value: len(result.by_severity(sev)) for sev in Severity},
    }
    # ensure_ascii=False lässt nicht-ASCII (deutsche Finding-Texte) als echte
    # Zeichen; dann MUSS explizit UTF-8 geschrieben werden -- sonst nimmt
    # write_text die Plattform-Default-Kodierung (cp1252 auf Windows) und der
    # Report ist kein gültiges UTF-8.
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_json_report(result: ScanResult, output_path: Path) -> None:
    data = {
        "target": str(result.target_path),
        "checks_run": result.checks_run,
        "checks_skipped": result.checks_skipped,
        "findings": [f.to_dict() for f in result.sorted_findings()],
        "summary": {
            sev.value: len(result.by_severity(sev)) for sev in Severity
        },
    }
    # UTF-8 explizit (siehe write_dynamic_json_report): sonst cp1252 auf Windows.
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
