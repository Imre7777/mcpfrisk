"""AUTH_BOUNDARY (Tier 2, dynamisch): prüft, ob ein laufender MCP-Server
Anfragen ohne gültige Authentifizierung wirklich ablehnt.

Hintergrund (Research-Pass 2026-06-29, siehe specs/001-auth-boundary/research.md):
MCP-Auth liegt auf Transport-Ebene. HTTP-Transport-Server MÜSSEN bei fehlendem/
ungültigem Token mit HTTP 401 (bzw. 403 bei Scope-Problemen) antworten. Ein
Januar-2026-Scan führte ~13% Auth-Bypass v.a. auf fehlende/falsche
Audience-Validierung zurück; ältere Daten: 38-41% der registrierten Server ganz
ohne wirksame Authentifizierung. Damit ist das der Tier-2-Check mit der größten
Hebelwirkung.

Der Check sendet zwei Proben gegen dieselbe repräsentative Operation:
- P1: ohne Credentials   -> erwartet 401
- P2: mit Junk-Credential -> erwartet 401 (fängt "prüft nur Präsenz, validiert
  aber nie"-Server)
Antwortet der Server stattdessen mit 2xx, gilt der Boundary als NICHT durchgesetzt.
"""
from __future__ import annotations

from mcpfrisk.core.base_check import BaseDynamicCheck
from mcpfrisk.core.dynamic_runner import DynamicSession
from mcpfrisk.core.models import (
    BoundaryOutcome,
    BoundaryResult,
    CredentialCondition,
    Finding,
    Severity,
)

_PROBE_OPERATION = "tools/list"


class AuthBoundaryCheck(BaseDynamicCheck):
    check_id = "AUTH_BOUNDARY"
    name = "Authentication Boundary"
    description = (
        "Prüft an einem laufenden HTTP-MCP-Server, ob Anfragen ohne bzw. mit "
        "ungültigem Token abgelehnt werden (401/403) statt bearbeitet zu werden."
    )
    severity = Severity.HIGH

    def run_against_server(self, session: DynamicSession) -> BoundaryResult:
        probes = [
            session.probe(_PROBE_OPERATION, CredentialCondition.NONE),
            session.probe(_PROBE_OPERATION, CredentialCondition.INVALID),
        ]
        return BoundaryResult(target=session.target, check_id=self.check_id, probes=probes)

    def to_finding(self, result: BoundaryResult) -> Finding | None:
        if result.outcome != BoundaryOutcome.NOT_ENFORCED:
            return None
        probe = result.failing_probe()
        assert probe is not None  # NOT_ENFORCED impliziert eine durchgelassene Probe
        condition_desc = {
            CredentialCondition.NONE: "ohne jegliche Credentials",
            CredentialCondition.INVALID: "mit einem offensichtlich ungültigen Token",
            CredentialCondition.VALID: "mit gültigen Credentials",
        }[probe.condition]
        return Finding(
            check_id=self.check_id,
            severity=self.severity,
            title="Fehlende Authentifizierungs-Durchsetzung (AUTH_BOUNDARY)",
            description=(
                f"Der Server beantwortete die Operation '{probe.operation}' "
                f"{condition_desc} mit einer Erfolgsantwort ({probe.observed}), "
                "statt sie mit 401/403 abzulehnen. Ein abgesicherter HTTP-MCP-"
                "Server muss unauthentifizierte/ungültige Anfragen auf "
                "Transport-Ebene zurückweisen."
            ),
            file_path=None,
            line_number=None,
            snippet=f"{probe.operation} [{probe.condition.value}] -> {probe.observed}",
            owasp_mcp_ref="MCP07",  # Insufficient Authentication
            cwe_ref="CWE-306",       # Missing Authentication for Critical Function
            remediation=(
                "Authentifizierung auf Transport-Ebene erzwingen: bei fehlendem/"
                "ungültigem Token mit HTTP 401 antworten (inkl. WWW-Authenticate "
                "-> Protected Resource Metadata, RFC 9728) und Tokens gegen die "
                "eigene Audience validieren (RFC 8707). Für stdio-Server "
                "Credentials aus der Umgebung beziehen."
            ),
            references=[
                "https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization",
                "https://owasp.org/www-project-mcp-top-10/",
                "https://cwe.mitre.org/data/definitions/306.html",
            ],
        )
