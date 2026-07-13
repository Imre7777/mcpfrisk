"""TOOL_NAME_COLLISION (Tier 1, statisch): erkennt gleichnamige bzw.
verwechselbar ähnliche Tool-Namen INNERHALB eines gescannten MCP-Servers.

Hintergrund (Research-Pass 2026-07-05, siehe specs/011-tool-name-collision):
Tool-Name-Collision / Tool-Shadowing ist eine dokumentierte MCP-Angriffsklasse
(Invariant Labs Cross-Server-Shadowing, Akto MCP Attack Matrix "Tool
Shadowing", Mend.io "Shadow MCP", MSB-Benchmark "Name-Collision"). Ohne
Namespacing hängt bei gleichnamigen Tools das Verhalten von der Client-
Implementierung und Verbindungsreihenfolge ab -- ein Tool überschattet still
ein anderes.

Scope-Ehrlichkeit (Prinzip V): der eigentliche Angriff ist *cross-server*.
McpFrisk scannt EINEN Server und kann daher nur *intra-repo*-Kollisionen
belegen: exakte Namensduplikate (undefiniertes Client-Verhalten, plausibler
Shadowing-Vektor -> MEDIUM) und near-duplicate-Namen (Agent-Verwechslungs-
risiko -> LOW). Cross-Server-Kollision ist bewusst out of scope; der
Finding-Text macht diese Grenze transparent. CWE-706 (Use of Incorrectly-
Resolved Name or Reference), OWASP MCP03.
"""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.checks._name_similarity import levenshtein_le_1
from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import iter_source_files
from mcpfrisk.core.models import Finding, Severity
from mcpfrisk.core.sourcetree import analyze

# Namen <= dieser Länge werden von der Near-Duplicate-Prüfung ausgenommen
# (Edit-Distanz 1 wäre bei sehr kurzen Namen fast immer erfüllt -> FP-Quelle).
# Exakte Duplikate werden unabhängig davon immer gemeldet.
_MIN_NEAR_DUP_LEN = 3
# Präfix-Beziehung gilt nur als near-duplicate, wenn der Rest kurz ist
# (z.B. Plural-"s": get_item / get_items) -- nicht bei get / get_user_profile.
_MAX_PREFIX_TAIL = 2


def _normalize(name: str) -> str:
    """Case- und Separator-neutrale Form: send_mail / sendMail / send-mail
    kollabieren auf denselben Wert."""
    return name.lower().replace("_", "").replace("-", "").replace(" ", "")


def _is_near_duplicate(a: str, b: str) -> bool:
    if a == b:
        return False  # das ist ein EXAKTES Duplikat, kein near-duplicate
    if len(a) < _MIN_NEAR_DUP_LEN or len(b) < _MIN_NEAR_DUP_LEN:
        return False
    # (a) Gleichheit nach Case/Separator-Normalisierung.
    if _normalize(a) == _normalize(b):
        return True
    # (b) Edit-Distanz 1 auf den Rohnamen.
    if levenshtein_le_1(a, b):
        return True
    # (c) Präfix-Beziehung mit kurzem Rest (z.B. Plural-"s").
    shorter, longer = (a, b) if len(a) < len(b) else (b, a)
    if longer.startswith(shorter) and (len(longer) - len(shorter)) <= _MAX_PREFIX_TAIL:
        return True
    return False


class _Occurrence:
    __slots__ = ("name", "file", "line")

    def __init__(self, name: str, file: Path, line: int) -> None:
        self.name = name
        self.file = file
        self.line = line

    def loc(self) -> str:
        return f"{self.file}:{self.line}"


class ToolNameCollisionCheck(BaseCheck):
    check_id = "TOOL_NAME_COLLISION"
    name = "Tool Name Collision / Shadowing"
    description = (
        "Sucht innerhalb des gescannten MCP-Servers nach gleichnamigen oder "
        "verwechselbar ähnlichen Tool-Namen -- ein Tool kann so ein anderes "
        "still überschatten (Tool-Shadowing-Risiko)."
    )

    def applies_to(self, target_path: Path) -> bool:
        return bool(iter_source_files(target_path))

    def run(self, target_path: Path) -> list[Finding]:
        occurrences = self._collect_occurrences(target_path)
        if len(occurrences) < 2:
            return []
        findings: list[Finding] = []
        findings.extend(self._exact_findings(occurrences))
        findings.extend(self._near_duplicate_findings(occurrences))
        return findings

    def _collect_occurrences(self, target_path: Path) -> list[_Occurrence]:
        out: list[_Occurrence] = []
        for file_path in iter_source_files(target_path):
            model = analyze(file_path)
            if model is None or not model.ok:
                continue
            for tool in model.tool_definitions():
                if isinstance(tool.name, str) and tool.name:
                    out.append(_Occurrence(tool.name, model.path, tool.line))
        return out

    def _exact_findings(self, occurrences: list[_Occurrence]) -> list[Finding]:
        by_name: dict[str, list[_Occurrence]] = {}
        for occ in occurrences:
            by_name.setdefault(occ.name, []).append(occ)
        findings: list[Finding] = []
        for name, occs in by_name.items():
            if len(occs) < 2:
                continue
            findings.append(self._exact_finding(name, occs))
        return findings

    def _near_duplicate_findings(self, occurrences: list[_Occurrence]) -> list[Finding]:
        # Ein Vorkommen pro eindeutigem Namen genügt für den Namensvergleich
        # (Zeile für den Beleg mitführen). Exakte Duplikate deckt bereits
        # _exact_findings ab -> hier nur echte Near-Duplicates.
        first_by_name: dict[str, _Occurrence] = {}
        for occ in occurrences:
            first_by_name.setdefault(occ.name, occ)
        names = sorted(first_by_name)
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                if not _is_near_duplicate(a, b):
                    continue
                key = (a, b)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    self._near_finding(first_by_name[a], first_by_name[b])
                )
        return findings

    def _exact_finding(self, name: str, occs: list[_Occurrence]) -> Finding:
        locs = ", ".join(o.loc() for o in occs)
        primary = occs[0]
        return Finding(
            check_id=self.check_id,
            severity=Severity.MEDIUM,
            title=f"Doppelt registrierter Tool-Name '{name}'",
            description=(
                f"Der Tool-Name '{name}' wird an {len(occs)} Stellen registriert "
                f"({locs}). Welche Registrierung ein MCP-Client verwendet, ist ohne "
                "Namespacing undefiniert -- eine überschattet still die andere "
                "(Tool-Shadowing). Ein verstecktes Duplikat kann ein harmlos "
                "wirkendes Tool verdecken. (Hinweis: geprüft wird nur DIESER "
                "Server; Kollisionen mit fremden Servern sieht McpFrisk nicht.)"
            ),
            file_path=primary.file,
            line_number=primary.line,
            snippet=f"'{name}' @ {locs}",
            owasp_mcp_ref="MCP03",
            cwe_ref="CWE-706",
            remediation=(
                "Jeden Tool-Namen im Server eindeutig vergeben. Keine zwei "
                "Registrierungen unter demselben Namen -- auch nicht über "
                "eingebettete Dependencies, die selbst Tools registrieren. "
                "Tool-Namen präfixieren/namespacen (z.B. 'myserver.get_item'), "
                "um Kollisionen mit anderen Servern vorzubeugen."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/706.html",
                "https://owasp.org/www-project-mcp-top-10/",
                "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
            ],
        )

    def _near_finding(self, a: _Occurrence, b: _Occurrence) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=Severity.LOW,
            title=f"Verwechselbar ähnliche Tool-Namen '{a.name}' / '{b.name}'",
            description=(
                f"Die Tool-Namen '{a.name}' ({a.loc()}) und '{b.name}' ({b.loc()}) "
                "unterscheiden sich nur minimal (Groß/Kleinschreibung, Trennzeichen, "
                "ein Zeichen oder ein Plural). Ein Agent kann sie verwechseln -- "
                "dieselbe Confusion, die Tool-Shadowing ausnutzt. Bitte prüfen, ob "
                "beide Namen wirklich beabsichtigt sind."
            ),
            file_path=a.file,
            line_number=a.line,
            snippet=f"'{a.name}' @ {a.loc()}  ~  '{b.name}' @ {b.loc()}",
            owasp_mcp_ref="MCP03",
            cwe_ref="CWE-706",
            remediation=(
                "Tool-Namen klar unterscheidbar wählen (nicht nur durch "
                "Groß/Kleinschreibung, Trennzeichen oder ein Plural-'s'). "
                "Konsistente Namenskonvention im gesamten Server verwenden."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/706.html",
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )
