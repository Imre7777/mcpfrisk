"""Orchestriert dynamische (Tier-2-)Checks gegen einen laufenden MCP-Server.

Pendant zu core/runner.py für statische Checks. Der DynamicRunner öffnet eine
DynamicSession zum Ziel und lässt jeden registrierten dynamischen Check dagegen
laufen, wandelt NOT_ENFORCED-Ergebnisse in Findings und hält INCONCLUSIVE-
Ergebnisse separat (sie sind weder Pass noch Finding).

Die Auth-Boundary-Frage -- "antwortet der Server auf eine Anfrage ohne gültiges
Token mit 401/403 statt sie zu bearbeiten?" -- wird auf HTTP-Ebene beantwortet
(ein abgesicherter MCP-Server erzwingt den Schutz im Transport-Layer, bevor
JSON-RPC/MCP überhaupt verarbeitet wird). Das reicht ein stdlib-`urllib`-Request,
ohne externe Abhängigkeit -- selbst dieser Tier-2-Check bleibt dependency-frei.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from mcpfrisk.core.models import (
    AuthProbe,
    BoundaryOutcome,
    CredentialCondition,
    DynamicScanResult,
)

_INVALID_TOKEN = "Bearer not-a-real-token"
_HTTP_SCHEMES = ("http://", "https://")


class DynamicTransportError(Exception):
    """Der Ziel-Server war nicht erreichbar / antwortete nicht verwertbar.

    Bewusst eine eigene Klasse, damit dynamische Checks Transportfehler gezielt
    abfangen und als INCONCLUSIVE einordnen können (Prinzip III: ein Fehler ist
    nie ein 'sicher')."""


class DynamicSession:
    """Dünner Handle auf den Ziel-Server mit einer zeitbegrenzten Probe-Methode."""

    def __init__(self, target: str, timeout_s: float = 5.0) -> None:
        self.target = target
        self.timeout_s = timeout_s

    @property
    def is_http(self) -> bool:
        return self.target.lower().startswith(_HTTP_SCHEMES)

    def probe(self, operation: str, condition: CredentialCondition) -> AuthProbe:
        """Sendet eine JSON-RPC-Anfrage und klassifiziert die Antwort.

        401/403 -> ENFORCED, 2xx -> NOT_ENFORCED, alles andere/Fehler ->
        INCONCLUSIVE. Wirft nie (Prinzip III: ein Fehler ist keine Durchsetzung)."""
        if not self.is_http:
            return AuthProbe(
                operation, condition, BoundaryOutcome.INCONCLUSIVE,
                "non-HTTP target (z.B. stdio): kein Transport-Auth-Boundary zum Prüfen",
            )

        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": operation, "params": {}}
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if condition == CredentialCondition.INVALID:
            headers["Authorization"] = _INVALID_TOKEN

        request = urllib.request.Request(  # noqa: S310 - scheme validated above
            self.target, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code  # 4xx/5xx kommen hier an
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            return AuthProbe(
                operation, condition, BoundaryOutcome.INCONCLUSIVE,
                f"nicht erreichbar/Timeout: {type(exc).__name__} ({reason})",
            )

        if status in (401, 403):
            return AuthProbe(operation, condition, BoundaryOutcome.ENFORCED, f"HTTP {status}")
        if 200 <= status < 300:
            return AuthProbe(operation, condition, BoundaryOutcome.NOT_ENFORCED, f"HTTP {status}")
        return AuthProbe(
            operation, condition, BoundaryOutcome.INCONCLUSIVE,
            f"HTTP {status} (unerwartet, keine klare Auth-Antwort)",
        )

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout_s: float | None = None,
    ) -> dict:
        """Generischer JSON-RPC-Aufruf über den HTTP-Transport (z.B. tools/list,
        tools/call). Liefert das geparste `result`-Objekt zurück.

        Additiv und allgemein -- jeder künftige dynamische Check kann darüber
        Operationen am Server ausführen. Wirft bei Transportfehlern eine
        DynamicTransportError (der aufrufende Check macht daraus INCONCLUSIVE);
        ändert das bestehende probe(...) nicht."""
        if not self.is_http:
            raise DynamicTransportError("non-HTTP target (z.B. stdio): kein HTTP-JSON-RPC")

        timeout = timeout_s if timeout_s is not None else self.timeout_s
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        request = urllib.request.Request(  # noqa: S310 - scheme validated above
            self.target, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read() or b""  # 4xx/5xx koennen dennoch eine JSON-RPC-Antwort tragen
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise DynamicTransportError(f"{type(exc).__name__} ({reason})") from exc

        return self._parse_jsonrpc_result(raw)

    @staticmethod
    def _parse_jsonrpc_result(raw: bytes) -> dict:
        """Extrahiert das `result`-Objekt aus einer JSON- oder SSE-Antwort.

        HTTP-MCP-Server antworten teils als text/event-stream (Zeilen mit
        'data: {...}'). Wir parsen beide Formen best-effort; nicht-parsebare
        Antworten liefern {} (der Check wertet das als 'nichts gefunden')."""
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return {}
        payload: dict | None = None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    try:
                        payload = json.loads(line[len("data:"):].strip())
                        break
                    except json.JSONDecodeError:
                        continue
        if not isinstance(payload, dict):
            return {}
        result = payload.get("result")
        return result if isinstance(result, dict) else {}


class DynamicRunner:
    def __init__(self, checks=None, timeout_s: float = 5.0) -> None:
        if checks is None:
            from mcpfrisk.checks.registry import get_all_dynamic_checks

            checks = get_all_dynamic_checks()
        self.checks = checks
        self.timeout_s = timeout_s

    def run(self, target: str, skip_checks: set[str] | None = None) -> DynamicScanResult:
        skip_checks = skip_checks or set()
        session = DynamicSession(target=target, timeout_s=self.timeout_s)
        result = DynamicScanResult(target=target)

        for check in self.checks:
            if check.check_id in skip_checks:
                result.checks_inconclusive.append(check.check_id)
                continue

            boundary = check.run_against_server(session)
            boundary.check_id = check.check_id
            result.boundary_results.append(boundary)

            if boundary.outcome == BoundaryOutcome.INCONCLUSIVE:
                result.checks_inconclusive.append(check.check_id)
                continue

            result.checks_run.append(check.check_id)
            finding = check.to_finding(boundary)
            if finding is not None:
                result.findings.append(finding)

        return result
