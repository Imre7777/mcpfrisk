"""PACKAGE_PROVENANCE (Tier 1, statisch, tool-gestützt): meldet npm-Dependencies
mit ungültiger oder fehlender Registry-Signatur -- durch Delegation an
`npm audit signatures`, nicht durch einen eigenen Signatur-Verifizierer.

Hintergrund (Research-Pass 2026-07-12, siehe specs/021-package-provenance): die
npm-Registry signiert Paket-Artefakte kryptografisch; `npm audit signatures`
verifiziert die Signaturen der installierten Dependencies gegen die Registry und
meldet Pakete mit ungültiger (manipulierter) oder fehlender Signatur. Eine
ungültige Signatur ist ein starkes Integritäts-/Tampering-Signal.

Bewusste FP-Entscheidung (Prinzip III): fehlende **Provenance-Attestation** wird
NICHT geflaggt (Adoption noch gering -> reines Rauschen). Nur die belastbaren
Signale: `invalid` -> HIGH (Tampering, CWE-347), `missing` -> LOW.

Architektur identisch zu DEPENDENCY_SCAN (019): DI-Runner (offline testbar),
Zero-Dep-Kern (npm über PATH erkannt, sonst „skipped"), `run()` wirft nie,
Tool-Fehler -> INFO. OWASP MCP04.
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

_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
_SCAN_TIMEOUT_S = 120


class ToolRunner(Protocol):
    def available(self) -> bool: ...

    def scan(self, target: Path) -> tuple[str, bool]: ...


class _NpmSignaturesRunner:
    """Default-Runner: `npm audit signatures --json` (falls npm im PATH)."""

    def available(self) -> bool:
        return shutil.which("npm") is not None

    def scan(self, target: Path) -> tuple[str, bool]:
        exe = shutil.which("npm")
        if not exe:
            return "", False
        try:
            proc = subprocess.run(  # noqa: S603 - fester, vertrauenswürdiger Tool-Aufruf
                [exe, "audit", "signatures", "--json"],
                cwd=str(target if target.is_dir() else target.parent),
                capture_output=True,
                text=True,
                timeout=_SCAN_TIMEOUT_S,
            )
        except (subprocess.TimeoutExpired, OSError):
            return "", False
        # npm exit != 0, wenn Beanstandungen gefunden wurden -- das ist kein
        # Fehler; der JSON-Output auf stdout wird trotzdem geparst. Ohne stdout
        # (echter Aufruf-Fehler) -> ok=False.
        ok = bool(proc.stdout and proc.stdout.strip())
        return proc.stdout or "", ok


def _entry_name_version(entry: object) -> tuple[str, str] | None:
    if not isinstance(entry, dict):
        return None
    name = entry.get("name")
    version = entry.get("version")
    if not isinstance(name, str) or not name:
        return None
    return name, version if isinstance(version, str) and version else "?"


def translate_signatures_report(data: dict) -> list[Finding]:
    """Reine Übersetzung eines `npm audit signatures --json`-Reports.
    `invalid` -> HIGH (CWE-347), `missing` -> LOW. Defensiv, nie Crash; Dedup je
    (Paket, Version, Klasse). Fehlende Provenance wird NICHT ausgewertet."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    if not isinstance(data, dict):
        return findings
    for kind, severity in (("invalid", Severity.HIGH), ("missing", Severity.LOW)):
        entries = data.get(kind)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            nv = _entry_name_version(entry)
            if nv is None:
                continue
            name, version = nv
            key = (name, version, kind)
            if key in seen:
                continue
            seen.add(key)
            reason = entry.get("code") if isinstance(entry, dict) else None
            findings.append(_build_finding(name, version, kind, severity, reason))
    return findings


def _build_finding(name: str, version: str, kind: str, severity: Severity, reason: object) -> Finding:
    if kind == "invalid":
        what = (
            f"Die npm-Dependency '{name}@{version}' hat eine UNGÜLTIGE Registry-"
            "Signatur: das installierte Artefakt weicht von dem ab, was die "
            "npm-Registry signiert hat (Integritäts-/Tampering-Signal)."
        )
        fix = (
            "Sofort prüfen: Paket neu installieren aus einer sauberen Quelle, "
            "Lockfile-Integrität (`integrity`-Hash) verifizieren, ggf. den "
            "Registry-Spiegel/Proxy prüfen. Ein manipuliertes Artefakt darf nicht "
            "ins Deployment."
        )
    else:  # missing
        what = (
            f"Die npm-Dependency '{name}@{version}' trägt keine Registry-Signatur "
            "-- ihre Herkunft/Integrität ist nicht kryptografisch verifizierbar."
        )
        fix = (
            "Prüfen, ob eine signierte Version verfügbar ist; Herausgeber und "
            "Bezugsquelle verifizieren. Schwächeres Signal als eine ungültige "
            "Signatur, aber notabel."
        )
    reason_txt = f" (Code: {reason})" if isinstance(reason, str) and reason else ""
    return Finding(
        check_id="PACKAGE_PROVENANCE",
        severity=severity,
        title=f"{'Ungültige' if kind == 'invalid' else 'Fehlende'} npm-Signatur: {name}@{version}",
        description=what + " Gemeldet von `npm audit signatures`." + reason_txt,
        file_path=None,
        line_number=None,
        snippet=f"{name}@{version} -> npm-Signatur {kind}",
        owasp_mcp_ref="MCP04",
        cwe_ref="CWE-347",
        remediation=fix,
        references=[
            "https://docs.npmjs.com/cli/commands/npm-audit",
            "https://cwe.mitre.org/data/definitions/347.html",
        ],
    )


class PackageProvenanceCheck(BaseCheck):
    check_id = "PACKAGE_PROVENANCE"
    name = "npm Package Signature / Provenance"
    description = (
        "Delegiert an `npm audit signatures` (falls npm installiert) und meldet "
        "Dependencies mit ungültiger (HIGH) oder fehlender (LOW) Registry-Signatur."
    )

    def __init__(self, runner: ToolRunner | None = None) -> None:
        self._runner = runner if runner is not None else _NpmSignaturesRunner()

    def _has_lockfile(self, target_path: Path) -> bool:
        for pattern in _LOCKFILES:
            for path in rglob_or_file(target_path, pattern):
                if not is_excluded(path, target_path):
                    return True
        return False

    def applies_to(self, target_path: Path) -> bool:
        return self._runner.available() and self._has_lockfile(target_path)

    def run(self, target_path: Path) -> list[Finding]:
        try:
            stdout, ok = self._runner.scan(target_path)
        except Exception as exc:  # noqa: BLE001 - der Check darf NIE werfen
            return [self._info(f"npm-Aufruf fehlgeschlagen ({type(exc).__name__}).")]
        if not ok:
            return [self._info("npm audit signatures brach ab oder lieferte keinen Output.")]
        text = (stdout or "").strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return [self._info("npm-Ausgabe war kein gültiges JSON.")]
        try:
            return translate_signatures_report(data)
        except Exception as exc:  # noqa: BLE001 - defensiv, nie werfen
            return [self._info(f"Signatur-Report nicht auswertbar ({type(exc).__name__}).")]

    @staticmethod
    def _info(reason: str) -> Finding:
        return Finding(
            check_id="PACKAGE_PROVENANCE",
            severity=Severity.INFO,
            title="Signatur-Prüfung nicht abgeschlossen",
            description=(
                f"Die npm-Signaturprüfung konnte nicht ausgewertet werden: {reason} "
                "Es wurde KEINE Aussage über Paket-Signaturen getroffen (kein "
                "stiller Fehl-Pass)."
            ),
            file_path=None,
            line_number=None,
            snippet=None,
            owasp_mcp_ref=None,
            cwe_ref=None,
            remediation=(
                "npm installieren/aktualisieren und `npm audit signatures` "
                "manuell ausführen. INFO-Findings blockieren den Build nicht."
            ),
        )
