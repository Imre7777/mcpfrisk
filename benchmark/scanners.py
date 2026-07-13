"""Scanner-Adapter für den Benchmark.

Jeder Adapter kapselt EIN Werkzeug hinter einer gemeinsamen Schnittstelle
(`available()` + `scan(sample_dir) -> ScanOutput`). McpFrisk läuft direkt über
die Bibliothek; die Wettbewerber (Semgrep, agent-audit) werden als Subprozess
aufgerufen, FALLS installiert -- sonst meldet der Adapter `available() == False`
und die Report-Spalte bleibt ehrlich leer statt erfunden.

Fairness beim Cross-Tool-Vergleich: verschiedene Tools nutzen verschiedene
Regel-IDs, daher wird tool-übergreifend NUR die Sample-Detection gemessen
(hat das Tool auf einem verwundbaren Sample überhaupt etwas gemeldet, und auf
einem sauberen Sample geschwiegen?). McpFrisks eigene check_id-Auflösung wird
zusätzlich für die per-Check-Metrik genutzt.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanOutput:
    findings: list[str] = field(default_factory=list)  # opake Finding-Kennungen (McpFrisk: check_ids)
    ok: bool = True                                    # lief der Scan sauber durch?
    note: str = ""

    @property
    def flagged(self) -> bool:
        return bool(self.findings)


class Scanner:
    name = "scanner"

    def available(self) -> bool:
        raise NotImplementedError

    def scan(self, sample_dir: Path) -> ScanOutput:
        raise NotImplementedError


class McpFriskScanner(Scanner):
    name = "McpFrisk"

    def available(self) -> bool:
        return True

    def scan(self, sample_dir: Path) -> ScanOutput:
        # Import lokal, damit metrics/das Korpus ohne mcpfrisk nutzbar bleiben.
        from mcpfrisk.core.runner import run_static_scan

        result = run_static_scan(sample_dir)
        # Nur echte Befunde zählen -- INFO ist ein Transparenz-Hinweis (z.B.
        # "Tool nicht installiert"), kein Sicherheits-Finding.
        findings = [f.check_id for f in result.findings if f.severity.value != "info"]
        return ScanOutput(findings=findings, ok=True)


class SemgrepScanner(Scanner):
    """Semgrep als Wettbewerber. Nutzt ein lokales Ruleset (kein Netz nötig)."""

    name = "Semgrep"

    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, sample_dir: Path) -> ScanOutput:
        exe = shutil.which("semgrep")
        if not exe:
            return ScanOutput(ok=False, note="semgrep nicht im PATH")
        try:
            proc = subprocess.run(
                [exe, "scan", "--json", "--quiet", "--config", "p/python", "--config", "p/javascript", str(sample_dir)],
                capture_output=True, text=True, timeout=180,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return ScanOutput(ok=False, note=f"semgrep-Fehler: {exc}")
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return ScanOutput(ok=False, note="semgrep-Ausgabe kein JSON")
        results = data.get("results") if isinstance(data, dict) else None
        findings = [r.get("check_id", "?") for r in results] if isinstance(results, list) else []
        return ScanOutput(findings=findings, ok=True)


class AgentAuditScanner(Scanner):
    """agent-audit (HeadyZhang) als direkter Wettbewerber, falls installiert."""

    name = "agent-audit"

    def available(self) -> bool:
        return shutil.which("agent-audit") is not None

    def scan(self, sample_dir: Path) -> ScanOutput:
        exe = shutil.which("agent-audit")
        if not exe:
            return ScanOutput(ok=False, note="agent-audit nicht im PATH")
        try:
            proc = subprocess.run(
                [exe, "scan", "--format", "json", str(sample_dir)],
                capture_output=True, text=True, timeout=180,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return ScanOutput(ok=False, note=f"agent-audit-Fehler: {exc}")
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return ScanOutput(ok=False, note="agent-audit-Ausgabe kein JSON (CLI-Schema prüfen)")
        # Defensive: verschiedene mögliche Schlüssel für die Finding-Liste.
        results = None
        if isinstance(data, dict):
            for key in ("findings", "results", "issues", "vulnerabilities"):
                if isinstance(data.get(key), list):
                    results = data[key]
                    break
        elif isinstance(data, list):
            results = data
        findings = [str(r.get("id", r.get("rule", "?")) if isinstance(r, dict) else r) for r in (results or [])]
        return ScanOutput(findings=findings, ok=True)


ALL_SCANNERS: list[Scanner] = [McpFriskScanner(), SemgrepScanner(), AgentAuditScanner()]
