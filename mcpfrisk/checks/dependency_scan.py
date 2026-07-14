"""DEPENDENCY_SCAN (Tier 1, statisch, tool-gestützt): meldet bekannte verwundbare
Dependency-Versionen (CVEs) -- durch **Delegation an `osv-scanner`**, nicht durch
einen eigenen CVE-Datenbank-Nachbau.

Hintergrund (Design-Prinzip 3, Stand 2026-07-12): McpFrisks Prinzip ist explizit
„Don't reinvent existing good tools." Für Dependency-Scanning gibt es osv-scanner
(Google OSV, multi-Ökosystem, stabiles JSON-Schema, selbst-enthaltenes Binary).
McpFrisk ruft es auf und **vereinheitlicht** dessen Ergebnisse mit den MCP-
spezifischen Findings -- EIN CI-Gate, EIN Report, EIN Exit-Code, dieselbe
Baseline-/SARIF-Mechanik.

Zero-Dep-Kern (Prinzip IV): osv-scanner ist NICHT gebündelt -- der Check erkennt
das Binary über den PATH. Fehlt es, ist der Check sauber „skipped" (kein Crash,
kein stiller „clean"). Der Tool-Runner ist injizierbar (DI), damit die
Übersetzungs-Logik ohne installiertes Tool und ohne Netz testbar ist.

Nie werfen, nie stiller Clean (Prinzip III): `run()` fängt alles ab. Exit-Code 1
= Vulns gefunden (osv-Konvention, kein Fehler -> JSON wird geparst). Anderer Exit/
Timeout/kein JSON -> ein einzelnes INFO-Finding (transparent). OWASP MCP04.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Protocol

from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import is_excluded, rglob_or_file
from mcpfrisk.core.models import Finding, Severity

# Manifeste/Lockfiles, die osv-scanner versteht -- Präsenz eines davon ist die
# `applies_to`-Bedingung (neben der Tool-Verfügbarkeit).
_MANIFESTS = (
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "poetry.lock", "pyproject.toml", "Pipfile", "Pipfile.lock",
    "go.mod", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock",
)
_SCAN_TIMEOUT_S = 120

_LABEL_TO_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def cvss_to_severity(score: float | None) -> Severity:
    """Bildet einen CVSS-Basis-Score auf McpFrisks Skala ab. Unbekannt/None ->
    MEDIUM (konservativer Default, nie stiller „harmlos")."""
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.MEDIUM


class ToolRunner(Protocol):
    """Port: was DEPENDENCY_SCAN von einem externen Scanner braucht."""

    def available(self) -> bool: ...

    def scan(self, target: Path) -> tuple[str, bool]: ...


class _OsvScannerRunner:
    """Default-Runner: ruft `osv-scanner` als Subprozess auf (falls im PATH)."""

    def available(self) -> bool:
        return shutil.which("osv-scanner") is not None

    def scan(self, target: Path) -> tuple[str, bool]:
        exe = shutil.which("osv-scanner")
        if not exe:
            return "", False
        try:
            proc = subprocess.run(  # noqa: S603 - fester, vertrauenswürdiger Tool-Aufruf
                [exe, "--format", "json", "--recursive", str(target)],
                capture_output=True,
                text=True,
                timeout=_SCAN_TIMEOUT_S,
            )
        except (subprocess.TimeoutExpired, OSError):
            return "", False
        # Exit 0 = keine Vulns, 1 = Vulns gefunden (beide liefern gültiges JSON);
        # alles andere ist ein echter Tool-Fehler.
        ok = proc.returncode in (0, 1)
        return proc.stdout or "", ok


def _parse_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _severity_for(vuln: dict, group_max: object) -> Severity:
    score = _parse_float(group_max)
    if score is not None:
        return cvss_to_severity(score)
    dbs = vuln.get("database_specific")
    if isinstance(dbs, dict):
        label = dbs.get("severity")
        if isinstance(label, str):
            return _LABEL_TO_SEVERITY.get(label.upper(), Severity.MEDIUM)
    return Severity.MEDIUM


def _fixed_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    return event["fixed"]
    return None


def _references(vuln: dict, display_id: str) -> list[str]:
    refs: list[str] = []
    for ref in vuln.get("references") or []:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            refs.append(ref["url"])
    osv_id = vuln.get("id")
    if isinstance(osv_id, str) and osv_id:
        refs.append(f"https://osv.dev/vulnerability/{osv_id}")
    if display_id.startswith("CVE-"):
        refs.append(f"https://nvd.nist.gov/vuln/detail/{display_id}")
    # dedupe, Reihenfolge bewahren
    seen: set[str] = set()
    return [r for r in refs if not (r in seen or seen.add(r))]


def translate_osv_report(data: dict) -> list[Finding]:
    """Reine Übersetzung eines osv-scanner-JSON-Reports in McpFrisk-Findings.
    Defensiv: fehlende/typfremde Felder werden übersprungen, nie ein Crash.
    Dedup je (Paket, Version, Vuln-ID)."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return findings
    for result in results:
        if not isinstance(result, dict):
            continue
        for pkg in result.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            info = pkg.get("package") if isinstance(pkg.get("package"), dict) else {}
            name = info.get("name") if isinstance(info.get("name"), str) else "?"
            version = info.get("version") if isinstance(info.get("version"), str) else "?"
            ecosystem = info.get("ecosystem") if isinstance(info.get("ecosystem"), str) else ""
            group_max: dict[str, object] = {}
            for group in pkg.get("groups") or []:
                if not isinstance(group, dict):
                    continue
                ms = group.get("max_severity")
                for vid in group.get("ids") or []:
                    if isinstance(vid, str):
                        group_max[vid] = ms
            for vuln in pkg.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                osv_id = vuln.get("id") if isinstance(vuln.get("id"), str) else ""
                aliases = [a for a in (vuln.get("aliases") or []) if isinstance(a, str)]
                cve = next((a for a in aliases if a.startswith("CVE-")), None)
                display_id = cve or osv_id or "?"
                key = (name, version, display_id)
                if key in seen:
                    continue
                seen.add(key)
                severity = _severity_for(vuln, group_max.get(osv_id) or group_max.get(cve or ""))
                fixed = _fixed_version(vuln)
                findings.append(
                    _build_finding(name, version, ecosystem, display_id, vuln, severity, fixed)
                )
    return findings


def _build_finding(
    name: str, version: str, ecosystem: str, display_id: str,
    vuln: dict, severity: Severity, fixed: str | None,
) -> Finding:
    summary = vuln.get("summary") if isinstance(vuln.get("summary"), str) else ""
    eco = f"{ecosystem}-" if ecosystem else ""
    fix_hint = (
        f"Auf die gefixte Version {fixed} (oder höher) aktualisieren."
        if fixed else
        "Auf eine nicht betroffene Version aktualisieren (siehe Advisory)."
    )
    return Finding(
        check_id="DEPENDENCY_SCAN",
        severity=severity,
        title=f"Verwundbare Dependency: {name} {version} ({display_id})",
        description=(
            f"Die {eco}Dependency '{name}' in Version {version} ist von einer "
            f"bekannten Schwachstelle betroffen ({display_id})"
            + (f": {summary}" if summary else ".")
            + " Gemeldet von osv-scanner (OSV-Datenbank)."
        ),
        file_path=None,
        line_number=None,
        snippet=f"{name}@{version} -> {display_id}" + (f" (fixed: {fixed})" if fixed else ""),
        owasp_mcp_ref="MCP04",
        cwe_ref=None,  # die konkrete Referenz ist die CVE-/OSV-ID (siehe references)
        remediation=fix_hint,
        references=_references(vuln, display_id),
    )


class DependencyScanCheck(BaseCheck):
    check_id = "DEPENDENCY_SCAN"
    name = "Vulnerable Dependency Scan (osv-scanner)"
    description = (
        "Delegiert an osv-scanner (falls installiert) und meldet bekannte "
        "verwundbare Dependency-Versionen (CVEs) im einheitlichen Report."
    )

    def __init__(self, runner: ToolRunner | None = None) -> None:
        self._runner = runner if runner is not None else _OsvScannerRunner()

    def _has_manifest(self, target_path: Path) -> bool:
        for pattern in _MANIFESTS:
            for path in rglob_or_file(target_path, pattern):
                if not is_excluded(path, target_path):
                    return True
        return False

    def applies_to(self, target_path: Path) -> bool:
        # Nur laufen, wenn das Tool verfügbar IST und ein scanbares Manifest
        # existiert -- sonst sauber „skipped" (transparent, kein stiller Pass).
        return self._runner.available() and self._has_manifest(target_path)

    def run(self, target_path: Path) -> list[Finding]:
        try:
            stdout, ok = self._runner.scan(target_path)
        except Exception as exc:  # noqa: BLE001 - der Check darf NIE werfen
            return [self._info(f"osv-scanner-Aufruf fehlgeschlagen ({type(exc).__name__}).")]
        if not ok:
            return [self._info("osv-scanner brach ab oder lieferte keinen verwertbaren Output.")]
        text = (stdout or "").strip()
        if not text:
            return []  # ok + kein Output -> keine Vulns
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return [self._info("osv-scanner-Ausgabe war kein gültiges JSON.")]
        try:
            return translate_osv_report(data)
        except Exception as exc:  # noqa: BLE001 - defensiv, nie werfen
            return [self._info(f"osv-Report nicht auswertbar ({type(exc).__name__}).")]

    @staticmethod
    def _info(reason: str) -> Finding:
        return Finding(
            check_id="DEPENDENCY_SCAN",
            severity=Severity.INFO,
            title="Dependency-Scan nicht abgeschlossen",
            description=(
                f"Der Dependency-Scan (osv-scanner) konnte nicht ausgewertet werden: "
                f"{reason} Es wurde KEINE Aussage über verwundbare Dependencies "
                "getroffen (kein stiller Fehl-Pass)."
            ),
            file_path=None,
            line_number=None,
            snippet=None,
            owasp_mcp_ref=None,
            cwe_ref=None,
            remediation=(
                "osv-scanner installieren/aktualisieren (https://osv.dev/) und den "
                "Scan erneut ausführen. INFO-Findings blockieren den Build nicht."
            ),
        )
