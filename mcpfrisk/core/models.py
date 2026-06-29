"""Kern-Datenmodelle für McpFrisk.

Jeder Check produziert eine Liste von Finding-Objekten. Das hält die
Architektur erweiterbar: ein neuer Check muss nur Findings zurückgeben,
der Rest (Report, Exit-Code, CI-Integration) bleibt unverändert.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable


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


# ---------------------------------------------------------------------------
# Tier 2 (dynamische Checks): Modelle für das Prüfen eines laufenden Servers.
# ---------------------------------------------------------------------------


class CredentialCondition(str, Enum):
    """Mit welchem Credential-Zustand eine Probe gesendet wird."""

    NONE = "none"        # gar kein Authorization-Header
    INVALID = "invalid"  # syntaktisch vorhanden, aber offensichtlich ungültig
    VALID = "valid"      # echtes Credential (reserviert, in v1 nicht genutzt)


class BoundaryOutcome(str, Enum):
    """Verdikt einer Probe bzw. (aggregiert) des Servers."""

    ENFORCED = "enforced"            # Server lehnt ab (401/403) -> kein Finding
    NOT_ENFORCED = "not_enforced"    # Server beantwortet die Anfrage -> Finding
    INCONCLUSIVE = "inconclusive"    # nicht erreichbar/Timeout/Crash/stdio -> kein Pass, kein Finding


@dataclass
class AuthProbe:
    """Ein einzelner Versuch gegen den Server."""

    operation: str                  # z.B. "tools/list"
    condition: CredentialCondition
    outcome: BoundaryOutcome
    observed: str                   # kurze, secret-bereinigte Zusammenfassung der Antwort

    def to_dict(self) -> dict:
        return {
            "operation": self.operation,
            "condition": self.condition.value,
            "outcome": self.outcome.value,
            "observed": self.observed,
        }


class ProbeClass(str, Enum):
    """Welche Art Ziel einem URL-akzeptierenden Tool untergeschoben wird --
    also *was* eine SSRF-Probe jeweils beweist."""

    CALLBACK = "callback"  # http://127.0.0.1:<listener>/<token> -> Server holt beliebige URL
    METADATA = "metadata"  # 169.254.169.254/... -> Versuch auf Cloud-Metadata
    LOOPBACK = "loopback"  # 127.0.0.1:<reserved> -> Versuch auf Loopback-Dienst
    REDIRECT = "redirect"  # öffentliche URL, die auf den Callback umleitet (Redirect-Bypass)


@dataclass
class UrlFetchProbe:
    """Ein einzelner SSRF-Versuch gegen ein Tool/einen Parameter.

    Strukturell kompatibel zu AuthProbe (besitzt `outcome` + `to_dict()`), damit
    BoundaryResult beide Probe-Arten ohne Sonderfall aggregieren kann."""

    tool: str
    parameter: str
    probe_class: ProbeClass
    outcome: BoundaryOutcome
    observed: str  # kurze, secret-bereinigte Zusammenfassung (Prinzip V)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "parameter": self.parameter,
            "probe_class": self.probe_class.value,
            "outcome": self.outcome.value,
            "observed": self.observed,
        }


@runtime_checkable
class DynamicProbe(Protocol):
    """Gemeinsames Minimal-Interface aller Tier-2-Proben (AuthProbe, UrlFetchProbe):
    ein `outcome` und eine serialisierbare Form. So bleibt BoundaryResult generisch."""

    outcome: BoundaryOutcome

    def to_dict(self) -> dict: ...


@dataclass
class BoundaryResult:
    """Aggregiertes Verdikt für einen Ziel-Server, plus die Belege (Probes)."""

    target: str
    check_id: str = ""
    probes: list[DynamicProbe] = field(default_factory=list)
    outcome: BoundaryOutcome = field(init=False)

    def __post_init__(self) -> None:
        self.outcome = self._aggregate()

    def _aggregate(self) -> BoundaryOutcome:
        # Worst-case gewinnt (Prinzip III: lieber Finding als stiller Pass).
        if any(p.outcome == BoundaryOutcome.NOT_ENFORCED for p in self.probes):
            return BoundaryOutcome.NOT_ENFORCED
        if self.probes and all(p.outcome == BoundaryOutcome.ENFORCED for p in self.probes):
            return BoundaryOutcome.ENFORCED
        return BoundaryOutcome.INCONCLUSIVE

    def failing_probe(self) -> DynamicProbe | None:
        for p in self.probes:
            if p.outcome == BoundaryOutcome.NOT_ENFORCED:
                return p
        return None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "check_id": self.check_id,
            "outcome": self.outcome.value,
            "probes": [p.to_dict() for p in self.probes],
        }


@dataclass
class DynamicScanResult:
    """Gesamtergebnis eines dynamischen Scans (analog zu ScanResult)."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    checks_inconclusive: list[str] = field(default_factory=list)
    boundary_results: list[BoundaryResult] = field(default_factory=list)

    def add(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def has_blocking_findings(self, fail_on: Severity = Severity.HIGH) -> bool:
        threshold = SEVERITY_ORDER[fail_on]
        return any(SEVERITY_ORDER[f.severity] <= threshold for f in self.findings)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])
