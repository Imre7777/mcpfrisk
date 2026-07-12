"""PROTOCOL_COMPLIANCE (Tier 2, dynamisch): prüft, ob ein laufender MCP-Server
auf eine unbekannte JSON-RPC-Methode mit dem korrekten, strukturierten
JSON-RPC-2.0-Fehler antwortet -- oder Erfolg vortäuscht (fail-open), einen
falschen Code oder ein malformtes Fehler-/Envelope-Objekt liefert.

Hintergrund (Research-Pass 2026-07-12, siehe specs/017-protocol-compliance):
MCP baut auf JSON-RPC 2.0 auf. Für eine unbekannte Methode schreibt JSON-RPC 2.0
zwingend einen Fehler mit `code == -32601` ("Method not found") vor; das
`error`-Objekt MUSS ein ganzzahliges `code`- und ein String-`message`-Feld
tragen, und jede Antwort MUSS `"jsonrpc": "2.0"` führen. Antwortet ein Server
stattdessen mit einem `result` (fail-open), kann der aufrufende Agent/Client
nicht zwischen "fehlgeschlagen" und "erfolgreich" unterscheiden und läuft weiter,
als sei der Aufruf geglückt -- die klassische Improper-Handling-of-Exceptional-
Conditions-Lücke (CWE-703).

Ehrliche Einordnung (Prinzip V): primär ein Protokoll-Korrektheits-/Robustheits-
Check mit konkretem Sicherheits-Winkel (fail-open). Severities moderat: fail-open
= MEDIUM, falscher Code / malformtes Fehler- bzw. Envelope-Objekt = LOW. Das
OWASP-MCP-Top-10 hat (Stand 2026-07-12) KEINE passende Kategorie -- der Check
trägt bewusst keinen owasp_mcp_ref (wie RATE_LIMITING), CWE-703 ist präzise.

Read-only per Konstruktion: der Check sendet ausschließlich EINE garantiert
unbekannte Top-Level-Methode und ruft nie ein Tool -> nie eine Mutation. Nur die
eindeutige Method-not-found-Semantik wird geprüft (andere Fehlerpfade sind gegen
MCP-Tool-Result-Fehler `isError` mehrdeutig -> bewusst out of scope, FP-Disziplin).
"""
from __future__ import annotations

import json
import uuid

from mcpfrisk.core.base_check import BaseDynamicCheck
from mcpfrisk.core.dynamic_runner import DynamicSession, DynamicTransportError
from mcpfrisk.core.models import (
    BoundaryOutcome,
    BoundaryResult,
    Finding,
    ProtocolProbe,
    ProtocolProbeClass,
    Severity,
)

_METHOD_NOT_FOUND = -32601
_MAX_OBSERVED = 300


def _truncate(text: str, limit: int = _MAX_OBSERVED) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class ProtocolComplianceCheck(BaseDynamicCheck):
    check_id = "PROTOCOL_COMPLIANCE"
    name = "JSON-RPC / MCP Protocol Compliance"
    description = (
        "Sendet eine unbekannte JSON-RPC-Methode an einen laufenden MCP-Server "
        "und prüft, ob er mit dem korrekten strukturierten Fehler (-32601) "
        "antwortet statt Erfolg vorzutäuschen (fail-open) oder einen falschen/ "
        "malformten Fehler zu liefern."
    )
    severity = Severity.MEDIUM  # Obergrenze; to_finding stuft je Abweichung ab

    def run_against_server(self, session: DynamicSession) -> BoundaryResult:
        method = f"mcpfrisk/probe_{uuid.uuid4().hex[:12]}"
        try:
            payload = session.call_response(method, {}, timeout_s=session.timeout_s)
        except DynamicTransportError as exc:
            return self._inconclusive(session, method, f"nicht auswertbar: {exc}")

        if not isinstance(payload, dict) or not payload:
            # Leere/unlesbare Antwort -> nicht auswertbar, kein stiller Pass,
            # aber auch kein Finding (Prinzip III: fehlende Evidenz != Abweichung).
            return self._inconclusive(session, method, "leere/unlesbare Antwort")

        probe_class = self._classify(payload)
        observed = _truncate(json.dumps(payload, ensure_ascii=False))
        if probe_class is None:
            probe = ProtocolProbe(
                method, ProtocolProbeClass.MISSING_ERROR, BoundaryOutcome.ENFORCED,
                f"konformer -32601-Fehler: {observed}",
            )
        else:
            probe = ProtocolProbe(
                method, probe_class, BoundaryOutcome.NOT_ENFORCED,
                f"{probe_class.value}: {observed}",
            )
        return BoundaryResult(target=session.target, check_id=self.check_id, probes=[probe])

    @staticmethod
    def _classify(payload: dict) -> ProtocolProbeClass | None:
        """Bewertet die Antwort auf eine unbekannte Methode gegen JSON-RPC 2.0.
        Reihenfolge = Schwere (worst-case gewinnt). None = konform (ENFORCED)."""
        error = payload.get("error")
        if error is None:
            # kein Fehler-Objekt: der Server täuscht Erfolg vor (fail-open).
            return ProtocolProbeClass.MISSING_ERROR
        if not isinstance(error, dict):
            return ProtocolProbeClass.MALFORMED_ERROR
        code = error.get("code")
        message = error.get("message")
        if isinstance(code, bool) or not isinstance(code, int) or not isinstance(message, str) or not message:
            return ProtocolProbeClass.MALFORMED_ERROR
        if code != _METHOD_NOT_FOUND:
            return ProtocolProbeClass.WRONG_ERROR_CODE
        if payload.get("jsonrpc") != "2.0":
            return ProtocolProbeClass.MALFORMED_ENVELOPE
        return None

    def _inconclusive(self, session: DynamicSession, method: str, reason: str) -> BoundaryResult:
        return BoundaryResult(
            target=session.target,
            check_id=self.check_id,
            probes=[ProtocolProbe(
                method, ProtocolProbeClass.MISSING_ERROR, BoundaryOutcome.INCONCLUSIVE, reason
            )],
        )

    # -- finding -----------------------------------------------------------
    def to_finding(self, result: BoundaryResult) -> Finding | None:
        if result.outcome != BoundaryOutcome.NOT_ENFORCED:
            return None
        probe = result.failing_probe()
        assert isinstance(probe, ProtocolProbe)  # NOT_ENFORCED impliziert eine Treffer-Probe

        detail, severity = {
            ProtocolProbeClass.MISSING_ERROR: (
                "gab KEIN JSON-RPC-Fehler-Objekt zurück, sondern täuschte Erfolg vor "
                "(fail-open). Ein aufrufender Agent kann so nicht erkennen, dass der "
                "Aufruf nie ausgeführt wurde, und läuft weiter, als sei er geglückt.",
                Severity.MEDIUM,
            ),
            ProtocolProbeClass.WRONG_ERROR_CODE: (
                "gab einen Fehler mit einem anderen Code als dem "
                "JSON-RPC-2.0-vorgeschriebenen -32601 ('Method not found') zurück.",
                Severity.LOW,
            ),
            ProtocolProbeClass.MALFORMED_ERROR: (
                "gab ein malformtes Fehler-Objekt zurück (kein ganzzahliges 'code' "
                "oder keine String-'message'), entgegen JSON-RPC 2.0.",
                Severity.LOW,
            ),
            ProtocolProbeClass.MALFORMED_ENVELOPE: (
                "gab eine Antwort ohne das JSON-RPC-2.0-Pflichtfeld \"jsonrpc\": \"2.0\" "
                "zurück.",
                Severity.LOW,
            ),
        }[probe.probe_class]

        return Finding(
            check_id=self.check_id,
            severity=severity,
            title="JSON-RPC / MCP Protocol Compliance (PROTOCOL_COMPLIANCE)",
            description=(
                f"Auf eine unbekannte JSON-RPC-Methode {detail} Beobachtet: "
                f"{probe.observed}."
            ),
            file_path=None,
            line_number=None,
            snippet=f"{probe.method} -> {probe.observed}",
            # OWASP-MCP-Top-10 kennt (Stand 2026-07-12) keine dedizierte Kategorie
            # für JSON-RPC-Protokoll-Konformität -- CWE-703 ist die präzise Referenz.
            owasp_mcp_ref=None,
            cwe_ref="CWE-703",
            remediation=(
                "Jede unbekannte Top-Level-Methode MUSS als strukturierter "
                "JSON-RPC-2.0-Fehler mit code -32601 ('Method not found') und einer "
                "String-'message' beantwortet werden, in einem \"jsonrpc\": \"2.0\"-"
                "Envelope -- niemals als scheinbarer Erfolg (kein 'result' ohne "
                "'error'). Fehlerhafte Parameter -> -32602, Parse-Fehler -> -32700. "
                "So kann der aufrufende Agent Fehlschläge zuverlässig erkennen."
            ),
            references=[
                "https://www.jsonrpc.org/specification#error_object",
                "https://modelcontextprotocol.io/specification",
                "https://cwe.mitre.org/data/definitions/703.html",
            ],
        )
