"""Orchestriert die Ausführung aller statischen Checks über ein Zielverzeichnis."""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.checks.registry import get_all_static_checks
from mcpfrisk.core.models import ScanResult


def run_static_scan(target_path: Path, skip_checks: set[str] | None = None) -> ScanResult:
    """Führt alle registrierten statischen Checks gegen target_path aus.

    skip_checks: Menge von check_id-Strings, die übersprungen werden sollen
    (z.B. wenn ein Team einen Check bewusst nicht will -- per .sentinelignore
    oder CLI-Flag steuerbar).
    """
    skip_checks = skip_checks or set()
    result = ScanResult(target_path=target_path)

    for check in get_all_static_checks():
        if check.check_id in skip_checks:
            result.checks_skipped.append(check.check_id)
            continue

        if not check.applies_to(target_path):
            result.checks_skipped.append(check.check_id)
            continue

        findings = check.run(target_path)
        result.add(findings)
        result.checks_run.append(check.check_id)

    return result
