"""Formatiert ScanResult für Terminal-Ausgabe (CI-freundlich) und JSON-Export."""
from __future__ import annotations

import json
from pathlib import Path

from mcpfrisk.core.models import ScanResult, Severity

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
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
