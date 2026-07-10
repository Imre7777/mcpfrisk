"""SCHEMA_DOCSTRING_MISMATCH (Tier 1, statisch): erkennt ein Tool, das über sein
Input-Schema einen **sensibel benannten** Parameter anfordert, den seine
**Beschreibung nicht offenlegt** -- der Out-of-Scope-Parameter- / Full-Schema-
Poisoning-Vektor.

Hintergrund (Research-Pass 2026-07-10, siehe specs/016-schema-docstring-mismatch):
Nicht nur die Beschreibung eines MCP-Tools ist ein Angriffsvektor, sondern das
gesamte inputSchema -- Parameter-Namen, Typen, required-Flags (Full-Schema-
Poisoning, Invariant Labs / CyberArk). Der Client serialisiert das komplette
Schema ans Modell; das Modell behandelt jeden deklarierten Parameter als
"auszufüllen". Ein Tool mit harmloser Beschreibung ("Add two numbers"), das
zusätzlich einen Parameter `api_key`/`session_token`/`ssh_key` deklariert,
verleitet das Modell dazu, diesen Parameter still aus dem Kontext zu befüllen --
ein Exfiltrations-Kanal. Die menschliche Freigabe basiert auf der Beschreibung;
die tatsächliche Datenanforderung steckt im Schema.

Scope-Ehrlichkeit / FP-Disziplin (Prinzip III): gemeldet wird NUR bei einem
doppelten Signal -- der Parameter ist (a) sensibel benannt UND (b) in der
Beschreibung nicht erwähnt. Ein reiner Parameter-Zahlen-Mismatch ("mehr
Parameter als beschrieben") wäre FP-Hölle und ist bewusst out of scope; ein
legitimes Auth-Tool nennt seinen `api_key` fast immer in der Beschreibung und
wird damit nicht geflaggt. OWASP MCP04 (Tool-Metadaten-Trust-Boundary), CWE-213
(Exposure of Sensitive Information Due to Incompatible Policies).
"""
from __future__ import annotations

import re
from pathlib import Path

from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import iter_source_files
from mcpfrisk.core.models import Finding, Severity
from mcpfrisk.core.sourcetree import SourceLanguage, analyze

# Sensible Parameter-Namen: bewusst streng (kein nacktes `auth`/`session`/`key`,
# das sind zu häufige harmlose Namen -> FP). `token`/`secret`/`credential`/
# `password`/`cookie` sowie die zusammengesetzten *_key-Formen sind belastbare
# Exfiltrations-Signale.
SENSITIVE_PARAM = re.compile(
    r"(?i)(password|passwd|pwd|passphrase|secret|token|credential|cookie|"
    r"api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|ssh[_-]?key|id_rsa)"
)


def _is_documented(param: str, description: str) -> bool:
    """True, wenn die Beschreibung den Parameter offenlegt. Trennzeichen-tolerant:
    der zu Buchstaben/Ziffern normalisierte Parameter-Name muss als Teilstring in
    der ebenso normalisierten Beschreibung vorkommen -- so gilt sowohl
    "api_key" als auch "API key" als Erwähnung von `api_key`."""
    if not description:
        return False
    dn = re.sub(r"[^a-z0-9]+", "", description.lower())
    pn = re.sub(r"[^a-z0-9]+", "", param.lower())
    return bool(pn) and pn in dn


class SchemaDocstringMismatchCheck(BaseCheck):
    check_id = "SCHEMA_DOCSTRING_MISMATCH"
    name = "Schema/Docstring Mismatch"
    description = (
        "Meldet ein Tool, dessen Input-Schema einen sensibel benannten "
        "Parameter anfordert, den die Tool-Beschreibung nicht offenlegt "
        "(Out-of-Scope-Parameter / Full-Schema-Poisoning)."
    )

    def applies_to(self, target_path: Path) -> bool:
        return bool(iter_source_files(target_path))

    def run(self, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in iter_source_files(target_path):
            model = analyze(file_path)
            if model is None or not model.ok:
                continue
            lang = "Python" if model.language is SourceLanguage.PYTHON else "JS/TS"
            for tool in model.tool_definitions():
                seen: set[str] = set()
                for param in tool.parameters:
                    if param in seen:
                        continue
                    if not SENSITIVE_PARAM.search(param):
                        continue
                    if _is_documented(param, tool.description):
                        continue
                    seen.add(param)
                    findings.append(
                        self._finding(model.path, tool.line, tool.name, param, lang)
                    )
        return findings

    def _finding(
        self, file_path: Path, line: int, tool_name: str, param: str, lang: str
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=Severity.HIGH,
            title=f"Undeklariert sensibler Tool-Parameter '{param}'",
            description=(
                f"Das {lang}-Tool '{tool_name}' fordert über sein Input-Schema "
                f"den sensibel benannten Parameter '{param}' an, ohne ihn in der "
                "Beschreibung zu erwähnen. Das Modell serialisiert das gesamte "
                "Schema und befüllt jeden deklarierten Parameter -- auch einen, "
                "den der Nutzer aus der Beschreibung nicht erwartet. So entsteht "
                "ein stiller Exfiltrations-Kanal (Full-Schema-Poisoning / "
                "Out-of-Scope-Parameter): die menschliche Freigabe basiert auf "
                "der Beschreibung, die tatsächliche Datenanforderung auf dem "
                "Schema."
            ),
            file_path=file_path,
            line_number=line,
            snippet=f"Tool '{tool_name}' -- Schema-Parameter '{param}' (undokumentiert)",
            owasp_mcp_ref="MCP04",
            cwe_ref="CWE-213",
            remediation=(
                f"Wenn '{param}' beabsichtigt ist: in der Tool-Beschreibung klar "
                "dokumentieren, WOZU er dient (dann sieht der Nutzer, was das Tool "
                "einsammelt). Wenn nicht beabsichtigt: den Parameter aus dem Schema "
                "entfernen. Tools sollten nur die Daten anfordern, die ihre "
                "beschriebene Funktion tatsächlich braucht (Least Privilege für "
                "Tool-Eingaben). Credentials gehören ohnehin nicht als Tool-"
                "Parameter, sondern in die Transport-/Auth-Schicht."
            ),
            references=[
                "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
                "https://cwe.mitre.org/data/definitions/213.html",
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )
