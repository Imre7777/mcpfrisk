"""TOOL_DESCRIPTION_DRIFT (Tier 1, statisch, baseline-basiert): erkennt stille
Änderungen an Tool-Beschreibungen gegenüber einem gepinnten, reviewten Stand
(Rug-Pull / Silent Redefinition).

Hintergrund (Research-Pass 2026-07-05, siehe specs/015-tool-description-drift):
Der Rug-Pull (CVE-2025-54136) ist eine formalisierte MCP-Bedrohungsklasse
(Cisco): ein Server zeigt zunächst harmlose Tools für die einmalige Freigabe
und ändert danach STILL die Definition/Beschreibung -- der Agent ruft ein Tool
weiter auf, dessen Bedeutung sich verschoben hat. Die MCP-Spec kennt kein
Pinning und keine Notification bei Änderung. McpFrisk pinnt daher die reviewten
Beschreibungen als Baseline (`.mcpfrisk-tools.json`, wie eine Lockfile) und
flaggt jede spätere Abweichung in CI.

Der Check ist OPT-IN: ohne gepinnten Baseline läuft er nicht (applies_to). Er
komponiert mit TOOL_POISONING -- jener sagt, OB der neue Text bösartig ist;
dieser sagt, DASS er sich seit dem Review geändert hat. OWASP MCP04 (Supply
Chain / Tampering), CWE-471 (Modification of Assumed-Immutable Data).
"""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.core import tool_baseline
from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import iter_source_files
from mcpfrisk.core.models import Finding, Severity
from mcpfrisk.core.sourcetree import analyze

_SNIPPET_MAX = 200


def _truncate(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _SNIPPET_MAX else text[:_SNIPPET_MAX] + "…"


class ToolDescriptionDriftCheck(BaseCheck):
    check_id = "TOOL_DESCRIPTION_DRIFT"
    name = "Tool Description Drift (Rug-Pull Pinning)"
    description = (
        "Vergleicht die Tool-Beschreibungen gegen einen gepinnten, reviewten "
        "Baseline (.mcpfrisk-tools.json) und flaggt stille Änderungen -- das "
        "Kernmuster eines Rug-Pull-/Silent-Redefinition-Angriffs."
    )

    def applies_to(self, target_path: Path) -> bool:
        # Opt-in: nur mit einem gepinnten Baseline gibt es eine belastbare
        # Drift-Referenz. Ohne ihn: skipped (kein FP, kein Rauschen).
        return tool_baseline.baseline_path(target_path).exists()

    def run(self, target_path: Path) -> list[Finding]:
        baseline = tool_baseline.load(tool_baseline.baseline_path(target_path))
        if not baseline:
            return []  # kein/leerer/malformter Pin -> nichts behaupten

        # Aktuelle Tool-Definitionen mit Belegdetails (Datei/Zeile/Text).
        defs: dict[str, tuple[Path, int, str]] = {}
        for file_path in iter_source_files(target_path):
            model = analyze(file_path)
            if model is None or not model.ok:
                continue
            for tool in model.tool_definitions():
                if isinstance(tool.name, str) and tool.name:
                    defs[tool.name] = (model.path, tool.line, tool.description or "")

        current = {name: tool_baseline.hash_description(d[2]) for name, d in defs.items()}
        changed, new = tool_baseline.diff(baseline, current)

        findings: list[Finding] = []
        for name in changed:
            path, line, desc = defs[name]
            findings.append(self._changed_finding(name, path, line, desc))
        for name in new:
            path, line, desc = defs[name]
            findings.append(self._new_finding(name, path, line, desc))
        return findings

    def _changed_finding(self, name: str, path: Path, line: int, desc: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=Severity.MEDIUM,
            title=f"Tool-Beschreibung geändert seit dem Pin ('{name}')",
            description=(
                f"Die Beschreibung des Tools '{name}' hat sich gegenüber dem "
                "gepinnten, reviewten Stand (.mcpfrisk-tools.json) geändert. Der "
                "stille Wechsel einer bereits freigegebenen Tool-Beschreibung ist "
                "das Kernmuster eines Rug-Pull-/Silent-Redefinition-Angriffs "
                "(CVE-2025-54136). Den aktuellen Text prüfen (siehe TOOL_POISONING) "
                "und, falls beabsichtigt, neu pinnen."
            ),
            file_path=path,
            line_number=line,
            snippet=f"{name}: {_truncate(desc)}",
            owasp_mcp_ref="MCP04",
            cwe_ref="CWE-471",
            remediation=(
                "Die geänderte Beschreibung im Review verifizieren (auf versteckte "
                "Instruktionen prüfen). Ist die Änderung legitim, den Baseline neu "
                "setzen: `mcpfrisk scan <ziel> --write-tools-baseline`. Für "
                "Drittanbieter-Server zusätzlich signierte/immutable Tool-"
                "Definitionen bevorzugen."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/471.html",
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )

    def _new_finding(self, name: str, path: Path, line: int, desc: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=Severity.LOW,
            title=f"Neues, nicht gepinntes Tool ('{name}')",
            description=(
                f"Das Tool '{name}' steht nicht im gepinnten Baseline -- es wurde "
                "nie reviewt/freigegeben. Ein untergeschobenes Tool ist ein "
                "Rug-Pull-/Supply-Chain-Vektor. Bitte prüfen und, falls "
                "beabsichtigt, den Baseline neu setzen."
            ),
            file_path=path,
            line_number=line,
            snippet=f"{name}: {_truncate(desc)}",
            owasp_mcp_ref="MCP04",
            cwe_ref="CWE-829",
            remediation=(
                "Das neue Tool und seine Beschreibung reviewen; ist es legitim, "
                "den Baseline aktualisieren (`--write-tools-baseline`)."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/829.html",
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )
