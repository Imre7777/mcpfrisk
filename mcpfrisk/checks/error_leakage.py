"""ERROR_LEAKAGE (Tier 2, dynamisch): beweist Interna-Leaks in Fehlerantworten
eines laufenden MCP-Servers -- ausgelöst durch drei "natürliche", schema-
KONFORME Trigger, nicht durch adversariale Payloads.

Hintergrund (Research-Pass 2026-07-02, siehe specs/008-error-leakage/spec.md):
Best-Practice-Leitfäden für MCP-Server warnen explizit davor, Upstream-Fehler
(DB-Treiber, ORMs, HTTP-Clients) ungefiltert an den Client durchzureichen
(mcpcat.io Error-Handling-Guide, 2026). CVE-2026-20205 (Splunk MCP Server) ist
eine reale Information-Disclosure-Schwachstelle durch unzureichend
sanitisiertes Fehler-/Log-Handling. CWE-209 (Information Exposure Through an
Error Message) ist die präzise Referenz; die offizielle OWASP-MCP-Top-10-
Kategorienliste (Stand 2026-07-02) hat KEINE dedizierte Kategorie dafür --
`owasp_mcp_ref="MCP08"` (Lack of Audit and Telemetry) ist hier bewusst nur ein
Best-Effort-Näherungswert, kein exaktes Match (siehe plan.md, Entschiedener
Design-Punkt 1).

Abgrenzung zu SCHEMA_FUZZING (007): jener Check probt schema-VERLETZENDE
Payloads mit Fokus auf Crash-Nachweis (Leak nur als Nebensignal). Dieser Check
probt ausschließlich schema-KONFORME, harmlose Werte gegen drei Fehlerpfade,
die jede/r normale Nutzer:in im Alltag auslösen kann (Tippfehler, veraltete
Tool-Referenz, gelöschte Ressource) -- und hat GENAU EIN Signal (Interna-Leak,
CWE-209). Es gibt bewusst KEINEN eigenen Crash-Nachweis hier (kein
Liveness-Recheck) -- das bleibt SCHEMA_FUZZINGs Verantwortung (Prinzip II:
keine Redundanz zwischen Checks). Ein Transportfehler während einer Probe
macht nur diese Probe nicht auswertbar, nie ein eigenständiges Finding.

Die drei Probe-Klassen:
- **UNKNOWN_TOOL** (US1): `tools/call` mit einem garantiert nicht
  existenten, eindeutigen Tool-Namen -- sicher auf JEDEM Server, auch ohne
  echte Tools.
- **UNKNOWN_METHOD** (US2): eine garantiert unbekannte Top-Level-JSON-RPC-
  Methode -- Protokoll-Ebene, ebenso universell sicher.
- **NONEXISTENT_RESOURCE** (US3): bei einem lesenden Tool mit ID-artigem
  Pflichtparameter ein schema-valider, aber garantiert nicht-existenter Wert
  ("record not found"-Pfad). Entfällt ohne passendes Tool, ohne das
  Gesamtergebnis zu beeinträchtigen (US1/US2 laufen unabhängig davon).
"""
from __future__ import annotations

import json
import uuid

from mcpfrisk.checks._dynamic_helpers import (
    find_leak,
    is_read_tool,
    tool_properties,
    tool_required,
    truncate,
)
from mcpfrisk.core.base_check import BaseDynamicCheck
from mcpfrisk.core.dynamic_runner import DynamicSession, DynamicTransportError
from mcpfrisk.core.models import (
    BoundaryOutcome,
    BoundaryResult,
    ErrorProbe,
    ErrorProbeClass,
    Finding,
    Severity,
)

# Tool-Klassifikation + Leak-Marker sind in _dynamic_helpers konsolidiert
# (geteilt mit SCHEMA_FUZZING/RBAC_CROSS_TENANT/RATE_LIMITING, Feature 013).
# ID-Hints sind ERROR_LEAKAGE-spezifisch (US3) und bleiben lokal.
_ID_HINTS = frozenset({"id", "key", "uuid", "record_id", "recordid", "resource_id", "ref", "slug"})


class ErrorLeakageCheck(BaseDynamicCheck):
    check_id = "ERROR_LEAKAGE"
    name = "Error Response Internals Leakage"
    description = (
        "Sendet drei 'natürliche', schema-konforme Fehlerauslöser (unbekannter "
        "Tool-Name, unbekannte JSON-RPC-Methode, nicht-existente Ressourcen-ID) "
        "an einen laufenden MCP-Server und prüft die Antworten auf "
        "Stacktrace-/Interna-Leaks -- ohne adversariale Payloads."
    )
    severity = Severity.MEDIUM

    def run_against_server(self, session: DynamicSession) -> BoundaryResult:
        probes: list[ErrorProbe] = []

        p1 = self._probe_unknown_tool(session)
        if p1 is not None:
            probes.append(p1)

        p2 = self._probe_unknown_method(session)
        if p2 is not None:
            probes.append(p2)

        id_tool = self._find_id_tool(session)
        if id_tool is not None:
            p3 = self._probe_nonexistent_resource(session, id_tool)
            if p3 is not None:
                probes.append(p3)

        if not probes:
            return self._inconclusive(
                session, "keine der drei Proben war auswertbar (Server nicht erreichbar?)."
            )
        return BoundaryResult(target=session.target, check_id=self.check_id, probes=probes)

    # -- US1: unbekannter Tool-Name --------------------------------------
    def _probe_unknown_tool(self, session: DynamicSession) -> ErrorProbe | None:
        sentinel = f"__mcpfrisk_unknown_tool_probe_{uuid.uuid4().hex[:12]}__"
        try:
            response = session.call(
                "tools/call", {"name": sentinel, "arguments": {}}, timeout_s=session.timeout_s
            )
        except DynamicTransportError:
            return None  # nicht auswertbar -- kein eigenes Finding daraus
        return self._verdict(sentinel, "", ErrorProbeClass.UNKNOWN_TOOL, response)

    # -- US2: unbekannte JSON-RPC-Methode --------------------------------
    def _probe_unknown_method(self, session: DynamicSession) -> ErrorProbe | None:
        method = f"mcpfrisk/probe_{uuid.uuid4().hex[:12]}"
        try:
            response = session.call(method, {}, timeout_s=session.timeout_s)
        except DynamicTransportError:
            return None
        return self._verdict(method, "", ErrorProbeClass.UNKNOWN_METHOD, response)

    # -- US3: nicht-existente Ressourcen-ID -------------------------------
    def _find_id_tool(self, session: DynamicSession) -> tuple[str, str] | None:
        try:
            result = session.call("tools/list")
        except DynamicTransportError:
            return None
        tools = result.get("tools")
        if not isinstance(tools, list):
            return None
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name")
            if not isinstance(name, str) or not is_read_tool(name):
                continue
            props = tool_properties(tool)
            for param in tool_required(tool):
                if not isinstance(param, str) or param.lower() not in _ID_HINTS:
                    continue
                pdef = props.get(param)
                declared_type = pdef.get("type") if isinstance(pdef, dict) else None
                if declared_type in (None, "string"):
                    return name, param
        return None

    def _probe_nonexistent_resource(
        self, session: DynamicSession, id_tool: tuple[str, str]
    ) -> ErrorProbe | None:
        name, param = id_tool
        fake_id = f"mcpfrisk-does-not-exist-{uuid.uuid4().hex}"
        try:
            response = session.call(
                "tools/call", {"name": name, "arguments": {param: fake_id}}, timeout_s=session.timeout_s
            )
        except DynamicTransportError:
            return None
        return self._verdict(name, param, ErrorProbeClass.NONEXISTENT_RESOURCE, response)

    def _verdict(
        self, tool: str, param: str, probe_class: ErrorProbeClass, response: dict
    ) -> ErrorProbe:
        text = json.dumps(response, ensure_ascii=False)
        leak = find_leak(text)
        if leak:
            return ErrorProbe(
                tool, param, probe_class, BoundaryOutcome.NOT_ENFORCED,
                f"Fehlerantwort enthaelt Interna-Marker: '{truncate(leak, 80)}' "
                f"(Ausschnitt: {truncate(text)})",
            )
        return ErrorProbe(
            tool, param, probe_class, BoundaryOutcome.ENFORCED, "kein Interna-Leak beobachtet"
        )

    def _inconclusive(self, session: DynamicSession, reason: str) -> BoundaryResult:
        return BoundaryResult(
            target=session.target,
            check_id=self.check_id,
            probes=[ErrorProbe("", "", ErrorProbeClass.UNKNOWN_TOOL, BoundaryOutcome.INCONCLUSIVE, reason)],
        )

    # -- finding -----------------------------------------------------------
    def to_finding(self, result: BoundaryResult) -> Finding | None:
        if result.outcome != BoundaryOutcome.NOT_ENFORCED:
            return None
        probe = result.failing_probe()
        assert isinstance(probe, ErrorProbe)  # NOT_ENFORCED impliziert eine Treffer-Probe

        trigger = {
            ErrorProbeClass.UNKNOWN_TOOL: "eines Aufrufs eines nicht-existenten Tool-Namens",
            ErrorProbeClass.UNKNOWN_METHOD: "eines Aufrufs einer unbekannten JSON-RPC-Methode",
            ErrorProbeClass.NONEXISTENT_RESOURCE: "einer Abfrage nach einer nicht-existenten Ressourcen-ID",
        }[probe.probe_class]

        return Finding(
            check_id=self.check_id,
            severity=Severity.MEDIUM,
            title="Error Response Internals Leakage (ERROR_LEAKAGE)",
            description=(
                f"Der Server antwortete auf {trigger} mit einer Fehlermeldung, die "
                f"interne Details preisgibt ({probe.observed}). Das erleichtert "
                "Folge-Angriffe (Pfade, Exception-Typen, evtl. SQL-Details) und kann "
                "durch ganz alltägliche, nicht-adversariale Eingaben ausgelöst werden."
            ),
            file_path=None,
            line_number=None,
            snippet=f"{probe.tool or probe.probe_class.value}({probe.parameter}) -> {probe.observed}",
            # OWASP-MCP-Top-10 kennt keine dedizierte "Info-Disclosure via Error"-
            # Kategorie (Stand 2026-07-02) -- MCP08 ist ein Best-Effort-Näherungswert,
            # CWE-209 ist die eigentlich präzise Referenz.
            owasp_mcp_ref="MCP08",
            cwe_ref="CWE-209",
            remediation=(
                "Handler-Exceptions UND Upstream-Fehler (DB-Treiber, ORMs, HTTP-Clients) "
                "serverseitig abfangen und dem Client NUR eine generische, strukturierte "
                "Fehlermeldung zurückgeben -- ohne Traceback, Exception-Klassennamen, "
                "Dateipfade oder SQL-Fehlertexte. Unbekannte Tool-Namen/Methoden IMMER "
                "als strukturierten JSON-RPC-Fehler (-32602/-32601) melden. Details "
                "ausschließlich serverseitig loggen, niemals in der Client-Antwort."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/209.html",
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )
