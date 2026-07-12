"""FALSE_ERROR_ESCALATION (Tier 1, statisch): erkennt Server-Text, der den Agenten/
Nutzer dazu verleiten soll, Sicherheitsabfragen zu deaktivieren oder Privilegien
zu eskalieren -- der Consent-Confused-Deputy- / False-Error-Escalation-Vektor.

Hintergrund (Research-Pass 2026-07-12, siehe specs/020-false-error-escalation):
Ein (bösartiges/kompromittiertes) Tool gibt Text zurück, der eine Zustimmungs-/
Sicherheits-Grenze senkt: „to continue, disable the confirmation prompt",
„approve all future requests", „re-run with sudo to grant admin access". Der
Mensch/Agent in der Schleife eskaliert dann Rechte oder schaltet Schutz ab. Das
ist der klassische Confused-Deputy (CWE-441); der Übertragungsweg ist Text, den
der Agent als vertrauenswürdig behandelt (Prompt-Injection-Klasse, OWASP MCP01).

Abgrenzung zu TOOL_POISONING (004): jener sucht Exfiltrations-/Geheimhaltungs-
Muster; DIESER sucht Consent-/Eskalations-Manipulation. Beide komponieren (kein
Check-zu-Check-Import).

FP-Disziplin (Prinzip III -- Stretch-Gate): geflaggt wird NUR ein kombiniertes
Signal -- ein Eskalations-Verb UND ein Sicherheits-/Consent-Objekt in einem
kurzen Textfenster. Eine bloße Fehlermeldung („Permission denied") triggert nie.
Die Muster werden zur Laufzeit aus Wortlisten gebaut, damit die Check-Quelle
nicht sich selbst matcht (Selbst-FP-Schutz beim Dogfood).
"""
from __future__ import annotations

import re
from pathlib import Path

from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import iter_source_files
from mcpfrisk.core.models import Finding, Severity
from mcpfrisk.core.sourcetree import analyze

# --- Wortlisten (die Muster werden daraus zur Laufzeit zusammengesetzt) --------
_VERB_DISABLE = ("disable", "turn off", "bypass", "skip", "ignore", "suppress", "override")
_OBJ_SAFETY = (
    "confirmation", "approval", "consent", "safety", "guardrail", "guardrails",
    "sandbox", "security check", "permission prompt", "human review", "verification",
)
_VERB_APPROVE = ("approve", "allow", "enable", "auto-approve", "auto approve", "whitelist", "trust")
_NOUN_ACTIONS = (
    "request", "requests", "tool", "tools", "action", "actions",
    "command", "commands", "call", "calls", "operation", "operations",
)
_VERB_GRANT = ("grant", "give", "enable", "escalate to", "elevate to")
_ADJ_ELEVATED = ("full", "admin", "administrator", "root", "elevated", "superuser")
_NOUN_ACCESS = ("access", "privilege", "privileges", "permission", "permissions", "right", "rights")
_VERB_RERUN = ("re-run", "rerun", "run again", "retry")
_TOK_ELEVATED_RUN = (
    "sudo", "--force", "--yes", "as admin", "as administrator",
    "with admin", "with administrator", "elevated", "as root",
)
_PROCEED = ("to continue", "to proceed", "to fix this", "in order to continue", "in order to proceed")


def _alt(words: tuple[str, ...]) -> str:
    # Mehrwort-Begriffe: Leerzeichen als flexibler Whitespace matchen.
    return "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in words)


def _gap(n: int) -> str:
    return r"[\w\s,'\"()./:;-]{0," + str(n) + r"}?"


def _combo(*parts: object) -> re.Pattern:
    """Baut ein Verb+…+Objekt-Muster: alternierende Wortgruppen (str-Tupel),
    verbunden durch Lücken (int = max. Zeichenabstand). Zur Laufzeit assembliert,
    daher enthält die Check-Quelle keine Verb+Objekt-Adjazenz (Selbst-FP-Schutz)."""
    pattern = r"(?i)"
    for part in parts:
        if isinstance(part, tuple):
            pattern += r"\b(?:" + _alt(part) + r")\b"
        else:  # int -> Lücke
            pattern += _gap(int(part))
    return re.compile(pattern)


# Fünf benannte Kategorien -- jede verlangt Verb UND Sicherheits-/Consent-Objekt.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("disable_safety", _combo(_VERB_DISABLE, 30, _OBJ_SAFETY)),
    ("approve_all", _combo(_VERB_APPROVE, 15, ("all",), 15, _NOUN_ACTIONS)),
    ("grant_elevated", _combo(_VERB_GRANT, 15, _ADJ_ELEVATED, 15, _NOUN_ACCESS)),
    ("rerun_elevated", _combo(_VERB_RERUN, 20, _TOK_ELEVATED_RUN)),
    ("proceed_escalate", _combo(_PROCEED, 30, _VERB_DISABLE + _VERB_APPROVE + _VERB_GRANT)),
]

_SNIPPET_MAX = 200


class FalseErrorEscalationCheck(BaseCheck):
    check_id = "FALSE_ERROR_ESCALATION"
    name = "False Error Escalation / Consent-Confused Deputy"
    description = (
        "Sucht in Server-Text (Tool-Beschreibungen, Fehler-/Return-Strings) nach "
        "Aufforderungen, Sicherheitsabfragen zu deaktivieren oder Privilegien zu "
        "eskalieren -- Consent-Manipulation, die den Agenten/Nutzer zum "
        "Confused Deputy macht."
    )

    def applies_to(self, target_path: Path) -> bool:
        return bool(iter_source_files(target_path))

    def run(self, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for file_path in iter_source_files(target_path):
            model = analyze(file_path)
            if model is None or not model.ok:
                continue
            # Nur Dateien mit echten Tool-Definitionen betrachten: der Angriff
            # betrifft TOOL-Text (Beschreibung/Fehler-/Return-String), der ans
            # Modell geht -- nicht beliebige Modul-Docstrings. Das schärft die
            # Präzision UND verhindert Selbst-FP (Security-Tools dokumentieren
            # solche Phrasen naturgemäß in ihrer eigenen Prosa).
            if not model.tool_definitions():
                continue
            for literal in model.string_literals():
                text = literal.value
                if not isinstance(text, str) or len(text) < 12:
                    continue
                category = self._first_match(text)
                if category is None:
                    continue
                key = (str(model.path), literal.line, text)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._finding(model.path, literal.line, text, category))
        return findings

    @staticmethod
    def _first_match(text: str) -> str | None:
        for name, pattern in _PATTERNS:
            if pattern.search(text):
                return name
        return None

    def _finding(self, file_path: Path, line: int, text: str, category: str) -> Finding:
        snippet = " ".join(text.split())[:_SNIPPET_MAX]
        return Finding(
            check_id=self.check_id,
            severity=Severity.MEDIUM,
            title="Mögliche Consent-/Eskalations-Manipulation in Server-Text",
            description=(
                "Ein an das Modell/den Nutzer gehender Text fordert dazu auf, eine "
                "Sicherheits-/Bestätigungsabfrage zu deaktivieren oder Privilegien "
                "zu eskalieren (Kategorie: "
                f"{category}). Ein bösartiges/kompromittiertes Tool kann so den "
                "Agenten oder Menschen dazu bringen, in seinem Namen eine "
                "Zustimmungs-/Sicherheitsgrenze zu senken (Confused Deputy) -- "
                "getarnt als harmlose Fehler- oder Bedienhinweis-Meldung."
            ),
            file_path=file_path,
            line_number=line,
            snippet=snippet,
            owasp_mcp_ref="MCP01",  # Prompt Injection (manipulierter Text an den Agenten)
            cwe_ref="CWE-441",       # Unintended Proxy or Intermediary ('Confused Deputy')
            remediation=(
                "Tool-/Fehlertexte dürfen den Nutzer oder Agenten NIE auffordern, "
                "Bestätigungen abzuschalten, alle Anfragen pauschal zu genehmigen "
                "oder mit erhöhten Rechten (sudo/admin/root) neu auszuführen. "
                "Fehlermeldungen sachlich und ohne Handlungsdruck formulieren; "
                "Privilegien-Eskalation muss eine bewusste, separate Nutzer-"
                "entscheidung bleiben, nie eine Nebenwirkung eines Tool-Aufrufs."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/441.html",
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )
