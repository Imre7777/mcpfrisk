"""RBAC_CROSS_TENANT (Tier 2, dynamisch): beweist tenant-/rollenübergreifende
Datenleckage an einem laufenden MCP-Server.

Hintergrund (Research-Pass 2026-06-29, siehe specs/006-rbac-cross-tenant):
Cross-Tenant-Leckage ist *Broken Access Control* (OWASP MCP07). Reale Fälle:
Asana-MCP (Confused Deputy, gecachte Antworten ohne Tenant-Recheck) und
CVE-2026-54052 (n8n-mcp: Queries nicht nach verifizierter tenant_id gescoped).
CWE-639 (IDOR), CWE-863/862 (Incorrect/Missing Authorization), CWE-441
(Confused Deputy).

Nachweis-Prinzip (Prinzip V -- Beleg statt Heuristik): McpFrisk agiert als ZWEI
Aufrufer-Identitäten (A, B). Es erhebt zunächst *A-private* Fingerprints (lange,
inhaltliche Marker, die A sieht, B aber in seiner eigenen legitimen Sicht NICHT
sieht) und versucht dann als B an A's Daten zu gelangen -- per IDOR-Replay (US1:
A's Ressourcen-ID unter B abrufen) und per Tenant-Argument-Injection (US2: A's
Tenant-Wert in ein tenant-artiges Argument schieben). Ein Finding entsteht NUR,
wenn ein A-privater Marker in B's Antwort auftaucht. Alles Mehrdeutige/Fehler ->
INCONCLUSIVE (Prinzip III). Ausschließlich LESENDE Operationen (kein create/
delete), um Fremd-Daten nicht zu verändern.
"""
from __future__ import annotations

import json

from mcpfrisk.checks._dynamic_helpers import (
    is_read_tool,
    tool_properties,
    tool_required,
)
from mcpfrisk.core.base_check import BaseDynamicCheck
from mcpfrisk.core.dynamic_runner import DynamicSession, DynamicTransportError
from mcpfrisk.core.models import (
    BoundaryOutcome,
    BoundaryResult,
    Finding,
    RbacProbe,
    RbacProbeClass,
    Severity,
)

# Tool-Klassifikation (READ/MUTATE) ist in _dynamic_helpers konsolidiert
# (Feature 013). Die ID-/Tenant-Parameter-Hints sind RBAC-spezifisch, bleiben lokal.
_ID_HINTS = frozenset({"id", "key", "uuid", "record_id", "recordid", "resource_id", "ref", "slug"})
_TENANT_HINTS = frozenset({
    "tenant", "tenant_id", "tenantid", "owner", "org", "organization", "account",
    "user", "user_id", "userid", "namespace", "workspace", "group",
})

# Ein "A-privater" Marker muss inhaltlich genug sein, um ein zufälliges/geteiltes
# Vorkommen unwahrscheinlich zu machen (keine kurzen Labels wie "tenant-a").
_MARKER_MIN_LEN = 10


class RbacCrossTenantCheck(BaseDynamicCheck):
    check_id = "RBAC_CROSS_TENANT"
    name = "Cross-Tenant / RBAC Data Leakage"
    description = (
        "Prüft an einem laufenden MCP-Server, ob ein Aufrufer (B) an Daten eines "
        "anderen Tenants/Rolle (A) gelangt -- per IDOR-Replay einer Ressourcen-ID "
        "oder durch Vertrauen in ein client-geliefertes Tenant-Argument. Nachweis "
        "über einen A-privaten Fingerprint in B's Antwort (out-of-context)."
    )
    severity = Severity.HIGH

    def run_against_server(self, session: DynamicSession) -> BoundaryResult:
        labels = session.identity_labels
        if len(labels) < 2:
            return self._inconclusive(
                session,
                "weniger als zwei Aufrufer-Identitäten übergeben -- ein Cross-Tenant-"
                "Test braucht mindestens zwei (--identity A=... --identity B=...).",
            )
        a, b = labels[0], labels[1]

        try:
            tools = self._read_tools(session, a)
        except DynamicTransportError as exc:
            return self._inconclusive(session, f"Server nicht erreichbar: {exc}")
        if not tools:
            return self._inconclusive(
                session, "keine lesenden Tools entdeckt (nichts sicher prüfbar)."
            )

        # Discovery: A-private Fingerprints + A's Ressourcen-ID/Tenant-Wert.
        try:
            disc = self._discover(session, a, b, tools)
        except DynamicTransportError as exc:
            return self._inconclusive(session, f"Discovery fehlgeschlagen: {exc}")

        if not disc["private_markers"]:
            return self._inconclusive(
                session,
                "unter A keine eindeutig A-private Ressource gefunden (kein belegbarer "
                "Fingerprint) -- Server evtl. nicht multi-tenant oder rein geteilte Daten.",
            )

        probes: list[RbacProbe] = []
        p1 = self._idor_probe(session, a, b, disc)
        if p1 is not None:
            probes.append(p1)
        p2 = self._tenant_arg_probe(session, a, b, disc)
        if p2 is not None:
            probes.append(p2)

        if not probes:
            return self._inconclusive(
                session,
                "kein per-ID- oder tenant-argument-basiertes Lese-Tool gefunden, das "
                "sich sicher proben lässt.",
            )
        return BoundaryResult(target=session.target, check_id=self.check_id, probes=probes)

    # -- discovery ---------------------------------------------------------
    def _read_tools(self, session: DynamicSession, identity: str) -> list[dict]:
        result = session.call("tools/list", identity=identity)
        tools = result.get("tools")
        if not isinstance(tools, list):
            return []
        return [
            t for t in tools
            if isinstance(t, dict) and isinstance(t.get("name"), str) and is_read_tool(t["name"])
        ]

    def _discover(self, session: DynamicSession, a: str, b: str, tools: list[dict]) -> dict:
        """Erhebt A-private Marker (in A sichtbar, in B's Eigen-Sicht nicht) sowie
        A's Ressourcen-ID und Tenant-Wert über ein ohne Pflichtargumente
        aufrufbares Lese-Tool ('Listing')."""
        listing = next((t for t in tools if not tool_required(t)), None)
        markers_a: set[str] = set()
        markers_b: set[str] = set()
        a_ids: list[str] = []
        a_tenants: list[str] = []

        if listing is not None:
            res_a = session.call("tools/call", {"name": listing["name"], "arguments": {}}, identity=a)
            res_b = session.call("tools/call", {"name": listing["name"], "arguments": {}}, identity=b)
            markers_a = self._markers(res_a)
            markers_b = self._markers(res_b)
            a_ids = self._keyed_values(res_a, _ID_HINTS)
            a_tenants = self._keyed_values(res_a, _TENANT_HINTS)

        return {
            "tools": tools,
            "listing": listing,
            "private_markers": markers_a - markers_b,  # nur A, nicht in B's Eigensicht
            "a_id": a_ids[0] if a_ids else None,
            "a_tenant": a_tenants[0] if a_tenants else None,
        }

    @staticmethod
    def _markers(obj: object) -> set[str]:
        """Alle hinreichend langen String-Werte (potenzielle inhaltliche Marker)."""
        out: set[str] = set()

        def walk(o: object) -> None:
            if isinstance(o, str):
                if len(o) >= _MARKER_MIN_LEN:
                    out.add(o)
            elif isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)

        walk(obj)
        return out

    @staticmethod
    def _keyed_values(obj: object, hint_keys: frozenset[str]) -> list[str]:
        """String-Werte, deren Schlüssel eine ID-/Tenant-Andeutung ist."""
        out: list[str] = []

        def walk(o: object) -> None:
            if isinstance(o, dict):
                for k, v in o.items():
                    if isinstance(v, str) and isinstance(k, str) and k.lower() in hint_keys:
                        out.append(v)
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)

        walk(obj)
        return out

    # -- probes ------------------------------------------------------------
    def _idor_probe(self, session: DynamicSession, a: str, b: str, disc: dict) -> RbacProbe | None:
        """US1: B ruft eine unter A entdeckte Ressourcen-ID über ein per-ID-Lese-Tool ab."""
        resource_id = disc["a_id"]
        if resource_id is None:
            return None
        tool = self._tool_with_param(disc["tools"], _ID_HINTS)
        if tool is None:
            return None
        name, param = tool
        try:
            res_b = session.call(
                "tools/call", {"name": name, "arguments": {param: resource_id}}, identity=b
            )
        except DynamicTransportError as exc:
            return RbacProbe(
                name, param, RbacProbeClass.IDOR_REPLAY, BoundaryOutcome.INCONCLUSIVE,
                f"tools/call fehlgeschlagen: {exc}", identity_from=a, identity_to=b,
            )
        return self._verdict(
            name, param, RbacProbeClass.IDOR_REPLAY, disc["private_markers"],
            exclude={resource_id}, response=res_b, a=a, b=b,
            leak_note=f"B rief A's Ressourcen-ID '{resource_id}' ab und erhielt A-private Daten",
            safe_note=f"B's Abruf von A's ID '{resource_id}' lieferte keine A-privaten Daten",
        )

    def _tenant_arg_probe(self, session: DynamicSession, a: str, b: str, disc: dict) -> RbacProbe | None:
        """US2: B injiziert A's Tenant-Wert in ein tenant-artiges Argument."""
        a_tenant = disc["a_tenant"]
        if a_tenant is None:
            return None
        tool = self._tool_with_param(disc["tools"], _TENANT_HINTS)
        if tool is None:
            return None
        name, param = tool
        try:
            res_b = session.call(
                "tools/call", {"name": name, "arguments": {param: a_tenant}}, identity=b
            )
        except DynamicTransportError as exc:
            return RbacProbe(
                name, param, RbacProbeClass.TENANT_ARG, BoundaryOutcome.INCONCLUSIVE,
                f"tools/call fehlgeschlagen: {exc}", identity_from=a, identity_to=b,
            )
        return self._verdict(
            name, param, RbacProbeClass.TENANT_ARG, disc["private_markers"],
            exclude={a_tenant}, response=res_b, a=a, b=b,
            leak_note=f"B setzte {param}='{a_tenant}' (A's Tenant) und erhielt A-private Daten",
            safe_note=f"B's {param}='{a_tenant}' lieferte keine A-privaten Daten (Argument ignoriert)",
        )

    def _tool_with_param(self, tools: list[dict], hints: frozenset[str]) -> tuple[str, str] | None:
        for tool in tools:
            for param in tool_properties(tool):
                if isinstance(param, str) and param.lower() in hints:
                    return tool["name"], param
        return None

    def _verdict(
        self,
        tool: str,
        param: str,
        probe_class: RbacProbeClass,
        private_markers: set[str],
        *,
        exclude: set[str],
        response: dict,
        a: str,
        b: str,
        leak_note: str,
        safe_note: str,
    ) -> RbacProbe:
        text = json.dumps(response, ensure_ascii=False)
        leaked = sorted(
            m for m in private_markers if m not in exclude and m in text
        )
        if leaked:
            sample = leaked[0]
            shown = sample if len(sample) <= 24 else sample[:12] + "…" + sample[-4:]
            return RbacProbe(
                tool, param, probe_class, BoundaryOutcome.NOT_ENFORCED,
                f"{leak_note} (A-privater Marker in B's Antwort: '{shown}')",
                identity_from=a, identity_to=b,
            )
        return RbacProbe(
            tool, param, probe_class, BoundaryOutcome.ENFORCED, safe_note,
            identity_from=a, identity_to=b,
        )

    def _inconclusive(self, session: DynamicSession, reason: str) -> BoundaryResult:
        return BoundaryResult(
            target=session.target,
            check_id=self.check_id,
            probes=[RbacProbe("", "", RbacProbeClass.IDOR_REPLAY, BoundaryOutcome.INCONCLUSIVE, reason)],
        )

    # -- finding -----------------------------------------------------------
    def to_finding(self, result: BoundaryResult) -> Finding | None:
        if result.outcome != BoundaryOutcome.NOT_ENFORCED:
            return None
        probe = result.failing_probe()
        assert isinstance(probe, RbacProbe)  # NOT_ENFORCED impliziert eine Treffer-Probe
        variant = (
            "eine unter einer anderen Identität entdeckte Ressourcen-ID (IDOR)"
            if probe.probe_class == RbacProbeClass.IDOR_REPLAY
            else "ein client-geliefertes Tenant-/Owner-Argument"
        )
        return Finding(
            check_id=self.check_id,
            severity=self.severity,
            title="Cross-Tenant Data Leakage (RBAC_CROSS_TENANT)",
            description=(
                f"Aufrufer '{probe.identity_to}' erhielt über das Tool '{probe.tool}' "
                f"(Parameter '{probe.parameter}') nachweislich Daten von Identität "
                f"'{probe.identity_from}', indem {variant} verwendet wurde "
                f"({probe.observed}). Der Server setzt die Tenant-/Rollen-Isolation "
                "nicht durch -- ein Aufrufer kann Daten eines anderen Tenants lesen."
            ),
            file_path=None,
            line_number=None,
            snippet=(
                f"{probe.tool}({probe.parameter}=<{probe.identity_from}'s Wert>) "
                f"[{probe.probe_class.value}] als {probe.identity_to} -> {probe.observed}"
            ),
            owasp_mcp_ref="MCP07",  # Insufficient Authentication & Authorization
            cwe_ref="CWE-639",       # Authorization Bypass Through User-Controlled Key (IDOR)
            remediation=(
                "Die Tenant-/Nutzer-Identität IMMER aus der verifizierten Session "
                "ableiten (z.B. JWT-Claim), niemals aus Tool-Argumenten oder Client-"
                "Headern. Jeden Ressourcen-Zugriff per zusammengesetztem Schlüssel "
                "prüfen (Ownership: `resource_id AND tenant_id`) und die Prüfung in "
                "der Datenzugriffsschicht erzwingen, nicht nur an der API. Tokens per "
                "RFC 8707 an den Ziel-Server binden (audience) und Tenant-IDs aus "
                "Client-Eingaben niemals vertrauen."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/639.html",
                "https://owasp.org/www-project-mcp-top-10/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html",
            ],
        )
