"""Orchestriert die Ausführung aller statischen Checks über ein Zielverzeichnis."""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.checks.registry import get_all_static_checks
from mcpfrisk.core.fs import exclude_context
from mcpfrisk.core.models import ScanResult


def run_static_scan(
    target_path: Path,
    skip_checks: set[str] | None = None,
    exclude: set[str] | None = None,
) -> ScanResult:
    """Führt alle registrierten statischen Checks gegen target_path aus.

    skip_checks: Menge von check_id-Strings, die übersprungen werden sollen
    (z.B. wenn ein Team einen Check bewusst nicht will -- per CLI-Flag).

    exclude: zusätzliche `--exclude`-Pfadmuster (gitignore-artig). Werden für
    die Dauer des Scans via ContextVar gesetzt, damit `fs.is_excluded()` sie in
    jedem Check sieht -- ohne die run()-Signatur anzufassen. Kombiniert additiv
    mit den Defaults und einer etwaigen `.mcpfriskignore`.
    """
    skip_checks = skip_checks or set()
    result = ScanResult(target_path=target_path)

    with exclude_context(tuple(sorted(exclude or ()))):
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
