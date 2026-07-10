"""SCHEMA_FUZZING (Tier 2, dynamisch): beweist fehlende Eingabe-Validierung an
einem laufenden MCP-Server durch schema-abgeleitetes Fuzzing.

Hintergrund (Research-Pass 2026-07-02, siehe specs/007-schema-fuzzing/spec.md):
unbeschränkte Schema-Parameter ("type": "string" ohne maxLength/pattern/enum/
format) sind die häufigste Wurzel realer MCP-CVEs (CVE-2026-32871 FastMCP
OpenAPI-Provider, CVE-2025-6514 mcp-remote, VIPER-MCP-Taint-Flows). OWASP
MCP05 (Command Injection & Execution) setzt fehlende Validierung voraus.
CWE-20 (Improper Input Validation), CWE-248 (Uncaught Exception), CWE-400
(Uncontrolled Resource Consumption), CWE-209 (Information Exposure).

Nachweis-Prinzip (Prinzip V -- Beleg statt Vermutung): McpFrisk liest die
deklarierten Tool-Schemata (tools/list), bestätigt zuerst einen gesunden
Baseline-Call, und sendet dann pro lesendem Tool/Parameter eine kleine Menge
schema-abgeleiteter Payloads (Typ-Mismatch, Übergröße, fehlendes Pflichtfeld,
formatverletzend). Ein Finding entsteht NUR bei zwei harten Signalen:
- **Crash**: ein Liveness-Recheck (tools/list) nach dem Payload schlägt fehl
  (Prozess-/Verbindungstod) -> NOT_ENFORCED, Severity HIGH.
- **Interna-Leak**: die Antwort enthält einen Traceback-/Exception-/Pfad-/
  SQL-Marker -> NOT_ENFORCED, Severity MEDIUM (CWE-209).
Ein Timeout/Hang OHNE fehlschlagenden Liveness-Recheck ist KEIN Crash (der
Server lebt, das eine Tool hing nur) -> INCONCLUSIVE + Triage, kein Finding.
Ein strukturierter Fehler ohne Leak, Server lebt -> ENFORCED. Ausschließlich
LESENDE Tools werden gefuzzt; keine Injection-Payloads (das ist CMD_INJECTION/
SSRF_CHECK-Scope).
"""
from __future__ import annotations

import json

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
    Finding,
    FuzzProbe,
    FuzzProbeClass,
    Severity,
)

# Tool-Klassifikation + Leak-Marker sind in _dynamic_helpers konsolidiert
# (geteilt mit ERROR_LEAKAGE/RBAC_CROSS_TENANT/RATE_LIMITING, Feature 013).
_MAX_TOOLS = 6
_MAX_PAYLOADS_PER_TOOL = 8
_PROBE_TIMEOUT_S = 1.5
_OVERSIZED_STRING_LEN = 50_000

_CRASH_TAG = "[CRASH]"
_LEAK_TAG = "[LEAK]"


def _benign_value(pdef: object) -> object:
    t = pdef.get("type") if isinstance(pdef, dict) else None
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "object":
        return {}
    return "test"


def _alt_type_value(declared_type: str | None) -> object | None:
    """Ein Wert eines ANDEREN JSON-Typs als deklariert (TYPE_MISMATCH)."""
    if declared_type == "string":
        return 12345
    if declared_type in ("integer", "number"):
        return "not-a-number"
    if declared_type == "boolean":
        return "not-a-boolean"
    if declared_type == "array":
        return "not-an-array"
    if declared_type == "object":
        return "not-an-object"
    return None  # kein deklarierter Typ -> keine sinnvolle Mismatch-Probe


def _oversized_value(declared_type: str | None) -> object | None:
    if declared_type in (None, "string"):
        return "A" * _OVERSIZED_STRING_LEN
    if declared_type == "array":
        return [0] * 10_000
    if declared_type == "object":
        return {f"k{i}": i for i in range(2_000)}
    return None  # numerische/boolesche "Übergröße" ist kein sinnvolles Signal


class SchemaFuzzingCheck(BaseDynamicCheck):
    check_id = "SCHEMA_FUZZING"
    name = "Schema Fuzzing (Input Validation Robustness)"
    description = (
        "Sendet schema-abgeleitete, malformte/übergroße/typ-fremde Payloads an "
        "lesende Tools eines laufenden MCP-Servers und prüft auf Crashes (per "
        "Liveness-Recheck belegt) oder Stacktrace-/Interna-Leaks in Fehlerantworten."
    )
    severity = Severity.HIGH  # Default-Attribut; to_finding() differenziert HIGH/MEDIUM

    def run_against_server(self, session: DynamicSession) -> BoundaryResult:
        try:
            tools = self._read_tools(session)
        except DynamicTransportError as exc:
            return self._inconclusive(session, f"Server nicht erreichbar: {exc}")
        if not tools:
            return self._inconclusive(
                session, "kein lesendes/fuzzbares Tool entdeckt (nichts sicher prüfbar)."
            )

        probes: list[FuzzProbe] = []
        probed_any_tool = False
        for tool in tools[:_MAX_TOOLS]:
            name = tool.get("name")
            if not isinstance(name, str):
                continue
            benign_args = self._benign_args(tool)

            # FR-002: gesunder Baseline-Call MUSS bestätigt werden, bevor gefuzzt wird.
            try:
                session.call(
                    "tools/call", {"name": name, "arguments": benign_args}, timeout_s=session.timeout_s
                )
            except DynamicTransportError:
                continue  # roter Baseline fuer DIESES Tool -- naechstes Tool versuchen
            probed_any_tool = True

            payloads = self._generate_payloads(tool, benign_args)
            for probe_class, param, args in payloads[:_MAX_PAYLOADS_PER_TOOL]:
                probe = self._send_probe(session, name, param, probe_class, args)
                probes.append(probe)
                if probe.outcome == BoundaryOutcome.NOT_ENFORCED:
                    # Ein Beweis genuegt (Fail-Fast: keine verwaisten stdio-Prozesse, CI-schnell).
                    return BoundaryResult(target=session.target, check_id=self.check_id, probes=probes)

        if not probed_any_tool:
            return self._inconclusive(
                session, "kein lesendes Tool mit gesundem Baseline-Call (roter Baseline)."
            )
        if not probes:
            return self._inconclusive(
                session, "keine schema-abgeleiteten Payloads erzeugbar (keine Parameter)."
            )
        return BoundaryResult(target=session.target, check_id=self.check_id, probes=probes)

    # -- discovery -----------------------------------------------------
    def _read_tools(self, session: DynamicSession) -> list[dict]:
        result = session.call("tools/list")
        tools = result.get("tools")
        if not isinstance(tools, list):
            return []
        return [
            t for t in tools
            if isinstance(t, dict) and isinstance(t.get("name"), str) and is_read_tool(t["name"])
        ]

    def _benign_args(self, tool: dict) -> dict:
        return {p: _benign_value(pdef) for p, pdef in tool_properties(tool).items()}

    # -- payload generation (FR-001) ------------------------------------
    def _generate_payloads(
        self, tool: dict, benign_args: dict
    ) -> list[tuple[FuzzProbeClass, str, dict]]:
        props = tool_properties(tool)
        required = tool_required(tool)
        payloads: list[tuple[FuzzProbeClass, str, dict]] = []
        for param, pdef in props.items():
            declared_type = pdef.get("type") if isinstance(pdef, dict) else None

            alt = _alt_type_value(declared_type)
            if alt is not None:
                payloads.append((FuzzProbeClass.TYPE_MISMATCH, param, {**benign_args, param: alt}))

            oversized = _oversized_value(declared_type)
            if oversized is not None:
                payloads.append((FuzzProbeClass.OVERSIZED, param, {**benign_args, param: oversized}))

            if param in required:
                missing = {k: v for k, v in benign_args.items() if k != param}
                payloads.append((FuzzProbeClass.MISSING_REQUIRED, param, missing))

            fmt = pdef.get("format") if isinstance(pdef, dict) else None
            if isinstance(fmt, str) and fmt:
                payloads.append((
                    FuzzProbeClass.MALFORMED_FORMAT, param,
                    {**benign_args, param: f"not a valid {fmt} !!"},
                ))
        return payloads

    # -- probing (FR-002/003/004/005) ------------------------------------
    def _send_probe(
        self,
        session: DynamicSession,
        tool: str,
        param: str,
        probe_class: FuzzProbeClass,
        args: dict,
    ) -> FuzzProbe:
        probe_timeout = min(_PROBE_TIMEOUT_S, session.timeout_s)
        try:
            response = session.call(
                "tools/call", {"name": tool, "arguments": args}, timeout_s=probe_timeout
            )
        except DynamicTransportError as exc:
            return self._after_transport_failure(session, tool, param, probe_class, exc)

        text = json.dumps(response, ensure_ascii=False)
        leak = find_leak(text)
        if leak:
            return FuzzProbe(
                tool, param, probe_class, BoundaryOutcome.NOT_ENFORCED,
                f"{_LEAK_TAG} Fehlerantwort enthaelt Interna-Marker: '{truncate(leak, 80)}' "
                f"(Ausschnitt: {truncate(text)})",
            )
        return FuzzProbe(
            tool, param, probe_class, BoundaryOutcome.ENFORCED,
            "kein Crash, kein Interna-Leak beobachtet",
        )

    def _after_transport_failure(
        self,
        session: DynamicSession,
        tool: str,
        param: str,
        probe_class: FuzzProbeClass,
        exc: Exception,
    ) -> FuzzProbe:
        """Payload-Call scheiterte (Timeout/Verbindung) -- per Liveness-Recheck
        (FR-003) zwischen echtem Crash und bloßem Hang unterscheiden."""
        try:
            session.call("tools/list", timeout_s=session.timeout_s)
        except DynamicTransportError:
            return FuzzProbe(
                tool, param, probe_class, BoundaryOutcome.NOT_ENFORCED,
                f"{_CRASH_TAG} Payload fuehrte zu {type(exc).__name__} ({exc}); Liveness-Recheck "
                "(tools/list) schlug danach ebenfalls fehl -- Server/Prozess reagiert nicht mehr.",
            )
        return FuzzProbe(
            tool, param, probe_class, BoundaryOutcome.INCONCLUSIVE,
            f"Payload fuehrte zu Timeout/Fehler ({exc}), aber Liveness-Recheck (tools/list) war "
            "danach erfolgreich -- kein Crash, evtl. Hang. Triage: moeglicher DoS, manuell verifizieren.",
        )

    def _inconclusive(self, session: DynamicSession, reason: str) -> BoundaryResult:
        return BoundaryResult(
            target=session.target,
            check_id=self.check_id,
            probes=[FuzzProbe("", "", FuzzProbeClass.TYPE_MISMATCH, BoundaryOutcome.INCONCLUSIVE, reason)],
        )

    # -- finding -----------------------------------------------------------
    def to_finding(self, result: BoundaryResult) -> Finding | None:
        if result.outcome != BoundaryOutcome.NOT_ENFORCED:
            return None
        probe = result.failing_probe()
        assert isinstance(probe, FuzzProbe)  # NOT_ENFORCED impliziert eine Treffer-Probe

        if probe.observed.startswith(_CRASH_TAG):
            return Finding(
                check_id=self.check_id,
                severity=Severity.HIGH,
                title="Unhandled Crash on Malformed Input (SCHEMA_FUZZING)",
                description=(
                    f"Das Tool '{probe.tool}' (Parameter '{probe.parameter}', Payload-Klasse "
                    f"{probe.probe_class.value}) brachte den Server zum Absturz bzw. machte ihn "
                    f"unerreichbar ({probe.observed}). Das belegt fehlende Eingabe-Validierung -- "
                    "ein Angreifer kann den Server per malformter Eingabe zum Absturz bringen (DoS)."
                ),
                file_path=None,
                line_number=None,
                snippet=f"{probe.tool}({probe.parameter}=<{probe.probe_class.value}>) -> {probe.observed}",
                owasp_mcp_ref="MCP05",
                cwe_ref="CWE-20",
                remediation=(
                    "Jeden Tool-Parameter serverseitig gegen sein Schema validieren, BEVOR er den "
                    "Handler erreicht (Typ, maxLength/minLength, pattern, enum, format). Handler-"
                    "Exceptions IMMER abfangen und als strukturierten JSON-RPC-Fehler (-32602 Invalid "
                    "params) melden statt den Prozess/die Verbindung sterben zu lassen. "
                    "Ressourcenlimits (max. Payload-/String-/Array-Größe) deny-by-default durchsetzen."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/20.html",
                    "https://cwe.mitre.org/data/definitions/248.html",
                    "https://owasp.org/www-project-mcp-top-10/",
                ],
            )

        return Finding(
            check_id=self.check_id,
            severity=Severity.MEDIUM,
            title="Stacktrace/Internals Leak on Malformed Input (SCHEMA_FUZZING)",
            description=(
                f"Das Tool '{probe.tool}' (Parameter '{probe.parameter}', Payload-Klasse "
                f"{probe.probe_class.value}) antwortete auf eine malformte Eingabe mit einer "
                f"Fehlermeldung, die interne Details preisgibt ({probe.observed}). Das erleichtert "
                "Folge-Angriffe (Pfade, Exception-Typen, evtl. SQL-Details)."
            ),
            file_path=None,
            line_number=None,
            snippet=f"{probe.tool}({probe.parameter}=<{probe.probe_class.value}>) -> {probe.observed}",
            owasp_mcp_ref="MCP05",
            cwe_ref="CWE-209",
            remediation=(
                "Handler-Exceptions serverseitig abfangen und dem Client NUR eine generische, "
                "strukturierte Fehlermeldung (JSON-RPC -32602 Invalid params) zurückgeben -- ohne "
                "Traceback, Exception-Klassennamen, Dateipfade oder SQL-Fehlertexte. Details "
                "ausschließlich serverseitig loggen, niemals in der Client-Antwort."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/209.html",
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )
