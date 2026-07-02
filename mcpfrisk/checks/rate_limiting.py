"""RATE_LIMITING (Tier 2, dynamisch): beweist fehlende Rate-Limiting-/
Concurrency-Kontrolle an einem laufenden MCP-Server durch einen kurzen,
begrenzten Aufruf-Burst.

Hintergrund (Research-Pass 2026-07-02, siehe specs/009-rate-limiting/spec.md):
Das MCP-Protokoll definiert selbst kein Rate-Limiting, kein Execution-Budget
und keine Loop-Detection -- Ökosystem-Analysen sind eindeutig, dass MCP-Server
standardmäßig ohne jedes Limit laufen und ein einzelner Client die gesamte
Deployment lahmlegen kann. CWE-400 (Uncontrolled Resource Consumption) und
CWE-770 (Allocation of Resources Without Limits or Throttling) sind die
präzisen Referenzen (dieselbe Klasse wie z.B. CVE-2026-53522). Die offizielle
OWASP-MCP-Top-10-Kategorienliste (Stand 2026-07-02) hat KEINE Kategorie mit
erkennbarem Bezug zu Resource-Exhaustion/DoS -- `owasp_mcp_ref` bleibt daher
bewusst `None` (siehe plan.md, Entschiedener Design-Punkt 2), anders als bei
ERROR_LEAKAGE (MCP08 als zumindest lose Näherung).

Nachweis-Prinzip (Prinzip V -- Beleg statt Vermutung): McpFrisk misst zuerst
eine Baseline-Latenz mit einem einzelnen Aufruf, sendet dann einen kurzen,
bewusst begrenzten, SCHNELLEN SEQUENZIELLEN Burst an dasselbe lesende Tool
(v1 bewusst ohne echte Multi-Thread-Parallelität -- StdioTransports
gemeinsamer Subprozess-Kanal wäre dafür nicht thread-sicher, siehe plan.md)
und wertet ausschließlich harte Signale:
- Ein expliziter Drossel-Hinweis (429/"rate limit"-Text) irgendwo im Burst
  -> sofort ENFORCED (Rate-Limiting ist vorhanden), unabhängig vom Rest.
- **Crash**: ein Liveness-Recheck (tools/list) nach einem gescheiterten
  Burst-Aufruf schlägt ebenfalls fehl -> NOT_ENFORCED, Severity HIGH.
- **Degradation**: kein Crash, kein Drossel-Signal, aber ein Burst-Aufruf
  überschreitet einen klar definierten Vielfachen-Schwellenwert der
  Baseline-Latenz -> NOT_ENFORCED, Severity MEDIUM, mit den konkreten
  Latenzwerten als Beleg.
Weder Crash noch Degradation noch Drossel-Signal -> ENFORCED. Kein
auswertbarer Burst-Fehler (Server lebt laut Liveness, aber der einzelne
Aufruf scheiterte unklar) -> INCONCLUSIVE, kein Finding. Ausschließlich
LESENDE Tools werden belastet; der Burst-Umfang bleibt fest und klein
(CI-tauglich, kein andauernder Last-Test).
"""
from __future__ import annotations

import json
import re
import time

from mcpfrisk.core.base_check import BaseDynamicCheck
from mcpfrisk.core.dynamic_runner import DynamicSession, DynamicTransportError
from mcpfrisk.core.models import (
    BoundaryOutcome,
    BoundaryResult,
    Finding,
    RateLimitProbe,
    RateLimitProbeClass,
    Severity,
)

# Tool-Heuristik (analog RBAC_CROSS_TENANT/SCHEMA_FUZZING/ERROR_LEAKAGE): der
# Burst zielt nie auf ein mutierendes Tool.
_READ_HINTS = ("get", "list", "read", "fetch", "search", "view", "show", "find", "query", "describe")
_MUTATE_HINTS = (
    "create", "update", "delete", "write", "set", "remove", "patch", "put",
    "add", "insert", "modify", "drop", "revoke", "grant", "upload",
)

_BURST_SIZE = 10
_DEGRADATION_RATIO = 5.0
_DEGRADATION_MIN_ABS_S = 0.2
_MIN_BASELINE_S = 0.005  # Floor gegen Divisions-/Mess-Rauschen bei einem quasi-0s-Baseline
_EVIDENCE_MAX = 200

_THROTTLE_RE = re.compile(
    r"rate.?limit|too many requests|quota exceeded|slow down|retry.?after|\b429\b",
    re.IGNORECASE,
)


def _truncate(text: str, limit: int = _EVIDENCE_MAX) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


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


class RateLimitingCheck(BaseDynamicCheck):
    check_id = "RATE_LIMITING"
    name = "Rate Limiting / Resource Exhaustion"
    description = (
        "Misst eine Baseline-Latenz und sendet danach einen kurzen, begrenzten "
        "Aufruf-Burst an ein lesendes Tool eines laufenden MCP-Servers. Prüft "
        "auf Absturz (per Liveness-Recheck belegt) oder messbare Latenz-"
        "Degradation ohne jede Drosselung."
    )
    severity = Severity.HIGH  # Default-Attribut; to_finding() differenziert HIGH/MEDIUM

    def run_against_server(self, session: DynamicSession) -> BoundaryResult:
        try:
            tool = self._find_read_tool(session)
        except DynamicTransportError as exc:
            return self._inconclusive(session, f"Server nicht erreichbar: {exc}")
        if tool is None:
            return self._inconclusive(
                session, "kein lesendes Tool gefunden (nichts sicher belastbar)."
            )
        name = tool["name"]
        args = self._benign_args(tool)

        baseline_elapsed, _baseline_response, baseline_error = self._timed_call(session, name, args)
        if baseline_error is not None:
            return self._inconclusive(session, f"Baseline-Call fehlgeschlagen: {baseline_error}")
        baseline_s = max(baseline_elapsed, _MIN_BASELINE_S)

        for call_index in range(1, _BURST_SIZE + 1):
            elapsed, response, error = self._timed_call(session, name, args)
            if error is not None:
                try:
                    session.call("tools/list", timeout_s=session.timeout_s)
                except DynamicTransportError:
                    return self._crash_result(session, name, call_index, error)
                return self._inconclusive(
                    session,
                    f"Burst-Aufruf {call_index}/{_BURST_SIZE} scheiterte ({error}), Liveness-Recheck "
                    "danach aber erfolgreich -- kein eindeutiger Beleg (weder Crash noch auswertbare "
                    "Degradation).",
                )
            if self._is_throttle_signal(response):
                return self._enforced_result(session, name, call_index, "Drossel-Signal beobachtet")
            if elapsed >= baseline_s * _DEGRADATION_RATIO and elapsed >= _DEGRADATION_MIN_ABS_S:
                return self._degradation_result(session, name, call_index, baseline_s, elapsed)

        return self._enforced_result(
            session, name, _BURST_SIZE, "kein Crash, kein Drossel-Signal, keine signifikante Degradation"
        )

    # -- discovery -----------------------------------------------------
    def _find_read_tool(self, session: DynamicSession) -> dict | None:
        result = session.call("tools/list")
        tools = result.get("tools")
        if not isinstance(tools, list):
            return None
        for t in tools:
            if isinstance(t, dict) and isinstance(t.get("name"), str) and self._is_read_tool(t["name"]):
                return t
        return None

    @staticmethod
    def _is_read_tool(name: str) -> bool:
        n = name.lower()
        if any(h in n for h in _MUTATE_HINTS):
            return False  # konservativ: nie ein potenziell mutierendes Tool belasten
        return any(h in n for h in _READ_HINTS)

    @staticmethod
    def _properties(tool: dict) -> dict:
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        props = schema.get("properties") if isinstance(schema, dict) else None
        return props if isinstance(props, dict) else {}

    def _benign_args(self, tool: dict) -> dict:
        return {p: _benign_value(pdef) for p, pdef in self._properties(tool).items()}

    # -- probing ---------------------------------------------------------
    def _timed_call(
        self, session: DynamicSession, name: str, args: dict
    ) -> tuple[float, dict | None, Exception | None]:
        start = time.monotonic()
        try:
            response = session.call(
                "tools/call", {"name": name, "arguments": args}, timeout_s=session.timeout_s
            )
        except DynamicTransportError as exc:
            return time.monotonic() - start, None, exc
        return time.monotonic() - start, response, None

    @staticmethod
    def _is_throttle_signal(response: dict) -> bool:
        text = json.dumps(response, ensure_ascii=False)
        return bool(_THROTTLE_RE.search(text))

    def _crash_result(
        self, session: DynamicSession, tool: str, call_index: int, error: Exception
    ) -> BoundaryResult:
        probe = RateLimitProbe(
            tool, "", RateLimitProbeClass.BURST_CRASH, BoundaryOutcome.NOT_ENFORCED,
            f"Burst-Aufruf {call_index}/{_BURST_SIZE} fuehrte zu {type(error).__name__} ({error}); "
            "Liveness-Recheck (tools/list) schlug danach ebenfalls fehl -- Server/Prozess reagiert "
            "nicht mehr.",
        )
        return BoundaryResult(target=session.target, check_id=self.check_id, probes=[probe])

    def _degradation_result(
        self, session: DynamicSession, tool: str, call_index: int, baseline_s: float, elapsed_s: float
    ) -> BoundaryResult:
        ratio = elapsed_s / baseline_s
        probe = RateLimitProbe(
            tool, "", RateLimitProbeClass.BURST_DEGRADATION, BoundaryOutcome.NOT_ENFORCED,
            f"Burst-Aufruf {call_index}/{_BURST_SIZE} brauchte {elapsed_s:.3f}s gegenueber "
            f"{baseline_s:.3f}s Baseline ({ratio:.1f}x) -- keine Drosselung beobachtet, Server "
            "bleibt am Leben.",
        )
        return BoundaryResult(target=session.target, check_id=self.check_id, probes=[probe])

    def _enforced_result(
        self, session: DynamicSession, tool: str, call_index: int, note: str
    ) -> BoundaryResult:
        probe = RateLimitProbe(
            tool, "", RateLimitProbeClass.BURST_DEGRADATION, BoundaryOutcome.ENFORCED,
            f"Burst von {call_index} Aufrufen ohne belegten Schaden ({note}).",
        )
        return BoundaryResult(target=session.target, check_id=self.check_id, probes=[probe])

    def _inconclusive(self, session: DynamicSession, reason: str) -> BoundaryResult:
        return BoundaryResult(
            target=session.target,
            check_id=self.check_id,
            probes=[RateLimitProbe("", "", RateLimitProbeClass.BURST_CRASH, BoundaryOutcome.INCONCLUSIVE, reason)],
        )

    # -- finding -----------------------------------------------------------
    def to_finding(self, result: BoundaryResult) -> Finding | None:
        if result.outcome != BoundaryOutcome.NOT_ENFORCED:
            return None
        probe = result.failing_probe()
        assert isinstance(probe, RateLimitProbe)  # NOT_ENFORCED impliziert eine Treffer-Probe

        if probe.probe_class == RateLimitProbeClass.BURST_CRASH:
            return Finding(
                check_id=self.check_id,
                severity=Severity.HIGH,
                title="Denial of Service Under Burst Load (RATE_LIMITING)",
                description=(
                    f"Das Tool '{probe.tool}' brachte den Server unter einem kurzen, begrenzten "
                    f"Aufruf-Burst zum Absturz bzw. machte ihn unerreichbar ({_truncate(probe.observed)}). "
                    "Das belegt fehlendes Rate-Limiting/Concurrency-Management -- ein Client (auch ein "
                    "versehentlich looping Agent) kann den Server per einfacher Aufruf-Serie lahmlegen."
                ),
                file_path=None,
                line_number=None,
                snippet=f"{probe.tool}() burst -> {_truncate(probe.observed)}",
                owasp_mcp_ref=None,  # keine passende OWASP-MCP-Top-10-Kategorie, siehe plan.md
                cwe_ref="CWE-400",
                remediation=(
                    "Rate-Limiting-Middleware pro Client-Identität/-Verbindung einführen (z.B. Token-"
                    "Bucket), Concurrency-Caps für gleichzeitige Tool-Ausführungen setzen, Request-"
                    "Timeouts erzwingen und bei Überschreitung strukturiert mit 429/Backoff-Hinweis "
                    "antworten statt Ressourcen unbegrenzt zu binden."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/400.html",
                    "https://cwe.mitre.org/data/definitions/770.html",
                ],
            )

        return Finding(
            check_id=self.check_id,
            severity=Severity.MEDIUM,
            title="Unbounded Resource Consumption Under Burst Load (RATE_LIMITING)",
            description=(
                f"Das Tool '{probe.tool}' zeigte unter einem kurzen Aufruf-Burst eine deutliche, "
                f"gemessene Latenz-Degradation ohne jede Drosselung ({_truncate(probe.observed)}). "
                "Der Server bleibt zwar am Leben, verarbeitet aber jede zusätzliche Last ohne "
                "erkennbare Gegenmaßnahme -- ein Vorbote von Ressourcen-Erschöpfung unter echter Last."
            ),
            file_path=None,
            line_number=None,
            snippet=f"{probe.tool}() burst -> {_truncate(probe.observed)}",
            owasp_mcp_ref=None,  # keine passende OWASP-MCP-Top-10-Kategorie, siehe plan.md
            cwe_ref="CWE-400 / CWE-770",
            remediation=(
                "Rate-Limiting-Middleware pro Client-Identität/-Verbindung einführen (z.B. Token-"
                "Bucket), Concurrency-Caps für gleichzeitige Tool-Ausführungen setzen, Request-"
                "Timeouts erzwingen und bei Überschreitung strukturiert mit 429/Backoff-Hinweis "
                "antworten statt Ressourcen unbegrenzt zu binden."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/400.html",
                "https://cwe.mitre.org/data/definitions/770.html",
            ],
        )
