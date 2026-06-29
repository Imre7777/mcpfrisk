"""SSRF_CHECK (Tier 2, dynamisch): prüft, ob ein laufender MCP-Server dazu
gebracht werden kann, von McpFrisk kontrollierte / interne URLs abzurufen.

Hintergrund (Research-Pass 2026-06-29, siehe specs/003-ssrf-check/research.md):
Mehrere MCP-Server (u.a. das Referenz-`mcp-server-fetch`, `playwright-mcp`,
`fetch-mcp`) holen beliebige, vom Agent gelieferte URLs ohne Schema-Allowlist,
Host-Denylist oder Post-DNS-IP-Prüfung. Auf Cloud-Hosts erreicht ein
prompt-injizierter Agent darüber `http://169.254.169.254/latest/meta-data/...`
und exfiltriert IAM-Credentials (CVSS 7.5-9.1, CWE-918).

Nachweis-Prinzip (out-of-band): McpFrisk startet einen einmaligen Loopback-
Callback-Listener, gibt jedem URL-akzeptierenden Tool eine eindeutige Callback-
URL und wertet einen eingehenden Treffer als *Beweis*, dass der Server einen
ausgehenden Request in McpFrisks Auftrag ausgeführt hat. Kein Treffer für eine
zustellbare Probe => der Boundary gilt als durchgesetzt (kein Finding).

US1 (MVP): die CALLBACK-Probe (Loopback). METADATA/LOOPBACK/REDIRECT-Proben
folgen in US3.
"""
from __future__ import annotations

from mcpfrisk.checks._ssrf_callback import CallbackListener
from mcpfrisk.core.base_check import BaseDynamicCheck
from mcpfrisk.core.dynamic_runner import DynamicSession, DynamicTransportError
from mcpfrisk.core.models import (
    BoundaryOutcome,
    BoundaryResult,
    Finding,
    ProbeClass,
    Severity,
    UrlFetchProbe,
)

# Parameter-Namen, die typischerweise eine URL tragen.
_URL_PARAM_HINTS = frozenset({
    "url", "uri", "href", "link", "endpoint", "webhook", "src",
    "target", "callback", "location", "address", "resource",
})
# Wie viele Kandidaten maximal geprobt werden (gegen ausartende Tool-Listen).
_MAX_CANDIDATES = 12


class SsrfCheck(BaseDynamicCheck):
    check_id = "SSRF_CHECK"
    name = "Server-Side Request Forgery"
    description = (
        "Prüft an einem laufenden MCP-Server, ob URL-akzeptierende Tools dazu "
        "gebracht werden können, von McpFrisk kontrollierte bzw. interne/Cloud-"
        "Metadata-Ziele abzurufen (out-of-band Callback-Nachweis)."
    )
    severity = Severity.HIGH

    def run_against_server(self, session: DynamicSession) -> BoundaryResult:
        try:
            candidates = self._discover_url_params(session)
        except DynamicTransportError as exc:
            return self._inconclusive(session, f"Server nicht erreichbar: {exc}")

        if not candidates:
            return self._inconclusive(
                session, "kein URL-akzeptierendes Tool gefunden (nichts zu prüfen)"
            )

        probes: list[UrlFetchProbe] = []
        with CallbackListener() as listener:
            for tool, parameter in candidates:
                probes.append(self._callback_probe(session, listener, tool, parameter))
        return BoundaryResult(target=session.target, check_id=self.check_id, probes=probes)

    # -- discovery ---------------------------------------------------------
    def _discover_url_params(self, session: DynamicSession) -> list[tuple[str, str]]:
        result = session.call("tools/list")
        tools = result.get("tools")
        if not isinstance(tools, list):
            return []
        candidates: list[tuple[str, str]] = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name")
            schema = tool.get("inputSchema") or tool.get("input_schema") or {}
            props = schema.get("properties") if isinstance(schema, dict) else None
            if not isinstance(name, str) or not isinstance(props, dict):
                continue
            for param, pdef in props.items():
                if not isinstance(param, str):
                    continue
                fmt = pdef.get("format") if isinstance(pdef, dict) else None
                if param.lower() in _URL_PARAM_HINTS or fmt == "uri":
                    candidates.append((name, param))
                    if len(candidates) >= _MAX_CANDIDATES:
                        return candidates
        return candidates

    # -- probes ------------------------------------------------------------
    def _callback_probe(
        self,
        session: DynamicSession,
        listener: CallbackListener,
        tool: str,
        parameter: str,
    ) -> UrlFetchProbe:
        token, url = listener.new_probe_url()
        try:
            session.call("tools/call", {"name": tool, "arguments": {parameter: url}})
        except DynamicTransportError as exc:
            # Der Aufruf selbst scheiterte -- der Server koennte dennoch gefetcht
            # haben, also kurz auf den Callback warten, bevor wir aufgeben.
            hit = listener.received(token, min(0.5, session.timeout_s))
            if hit is not None:
                return self._hit_probe(tool, parameter, token)
            return UrlFetchProbe(
                tool, parameter, ProbeClass.CALLBACK, BoundaryOutcome.INCONCLUSIVE,
                f"tools/call fehlgeschlagen: {exc}",
            )

        hit = listener.received(token, session.timeout_s)
        if hit is not None:
            return self._hit_probe(tool, parameter, token)
        return UrlFetchProbe(
            tool, parameter, ProbeClass.CALLBACK, BoundaryOutcome.ENFORCED,
            "kein Callback beobachtet (Ziel offenbar abgelehnt)",
        )

    @staticmethod
    def _hit_probe(tool: str, parameter: str, token: str) -> UrlFetchProbe:
        return UrlFetchProbe(
            tool, parameter, ProbeClass.CALLBACK, BoundaryOutcome.NOT_ENFORCED,
            f"Server holte die Callback-URL (Token …{token[-8:]})",
        )

    def _inconclusive(self, session: DynamicSession, reason: str) -> BoundaryResult:
        return BoundaryResult(
            target=session.target,
            check_id=self.check_id,
            probes=[UrlFetchProbe("", "", ProbeClass.CALLBACK, BoundaryOutcome.INCONCLUSIVE, reason)],
        )

    # -- finding -----------------------------------------------------------
    def to_finding(self, result: BoundaryResult) -> Finding | None:
        if result.outcome != BoundaryOutcome.NOT_ENFORCED:
            return None
        probe = result.failing_probe()
        assert isinstance(probe, UrlFetchProbe)  # NOT_ENFORCED impliziert eine Treffer-Probe
        return Finding(
            check_id=self.check_id,
            severity=self.severity,
            title="Server-Side Request Forgery (SSRF_CHECK)",
            description=(
                f"Das Tool '{probe.tool}' holte über den Parameter '{probe.parameter}' "
                "eine von McpFrisk kontrollierte URL ab, ohne das Ziel zu prüfen "
                f"({probe.observed}). Ein Angreifer kann den Server so zu Requests "
                "gegen interne Dienste oder den Cloud-Metadata-Endpoint "
                "(169.254.169.254 -> IAM-Credentials) zwingen."
            ),
            file_path=None,
            line_number=None,
            snippet=f"{probe.tool}({probe.parameter}=<callback>) [{probe.probe_class.value}] -> {probe.observed}",
            owasp_mcp_ref="MCP01",  # Unvalidierte/unsichere Tool-Eingaben
            cwe_ref="CWE-918",       # Server-Side Request Forgery
            remediation=(
                "URL-Eingaben vor dem Abruf validieren: nur http/https zulassen; "
                "den Host auflösen und JEDE resultierende IP gegen eine Denylist "
                "prüfen (Loopback 127.0.0.0/8 + ::1, Link-Local 169.254.0.0/16 "
                "inkl. Cloud-Metadata, RFC1918 10/172.16/192.168, 0.0.0.0); "
                "Redirects nicht blind folgen, sondern jedes Ziel erneut prüfen "
                "(DNS-Rebinding/Redirect-Bypass); auf Cloud-Hosts IMDSv2 erzwingen."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/918.html",
                "https://owasp.org/www-project-mcp-top-10/",
                "https://github.com/modelcontextprotocol/servers/issues/4205",
            ],
        )
