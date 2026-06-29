"""Kern-Datenmodelle für McpFrisk.

Jeder Check produziert eine Liste von Finding-Objekten. Das hält die
Architektur erweiterbar: ein neuer Check muss nur Findings zurückgeben,
der Rest (Report, Exit-Code, CI-Integration) bleibt unverändert.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "critical"   # RCE, Auth-Bypass, Secret-Leak -> Build muss failen
    HIGH = "high"            # Path Traversal, SSRF, fehlende Authn
    MEDIUM = "medium"        # Fehlende Input-Validierung, schwache Defaults
    LOW = "low"              # Stil/Best-Practice, kein direkter Exploit-Pfad
    INFO = "info"            # Beobachtung ohne Sicherheitsrelevanz


# Reihenfolge für Sortierung in Reports (kritischste zuerst)
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    """Ein einzelner Sicherheitsbefund."""

    check_id: str            # z.B. "CMD_INJECTION"
    severity: Severity
    title: str
    description: str
    file_path: Path | None = None
    line_number: int | None = None
    snippet: str | None = None
    owasp_mcp_ref: str | None = None   # z.B. "MCP05" (OWASP MCP Top 10 Mapping)
    cwe_ref: str | None = None         # z.B. "CWE-78"
    remediation: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file": str(self.file_path) if self.file_path else None,
            "line": self.line_number,
            "snippet": self.snippet,
            "owasp_mcp_ref": self.owasp_mcp_ref,
            "cwe_ref": self.cwe_ref,
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass
class ScanResult:
    """Gesamtergebnis eines Scan-Laufs über alle Checks."""

    target_path: Path
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)

    def add(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def has_blocking_findings(self, fail_on: Severity = Severity.HIGH) -> bool:
        """Für CI: soll der Build failen?"""
        threshold = SEVERITY_ORDER[fail_on]
        return any(SEVERITY_ORDER[f.severity] <= threshold for f in self.findings)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])
