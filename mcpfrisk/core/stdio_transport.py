"""StdioTransport: spricht einen MCP-Server über den stdio-Transport an.

McpFrisk startet den Server als Subprozess und kommuniziert per
newline-delimited JSON-RPC über dessen stdin/stdout (stderr = Logs/Diagnose,
nicht Protokoll) -- genau wie ein echter MCP-Client. Damit erreichen die
dynamischen Checks (SSRF_CHECK u.a.) die reale Mehrheit der MCP-Server, die
nicht über HTTP, sondern über stdio läuft.

Protokoll-Ära-Negotiation (Research-Pass 2026-06, modelcontextprotocol.io
/specification/draft/basic/transports/stdio, SEP-2575): zuerst `server/discover`
(modern/stateless, Metadaten in `_meta`); kommt ein Fehler oder keine Antwort,
Fallback auf den Legacy-`initialize`-+`notifications/initialized`-Handshake.
McpFrisk implementiert bewusst nur so viel MCP-Client, wie `tools/list` und
`tools/call` für die Checks brauchen -- stdlib-only, kein `mcp`-SDK.

Sicherheitshinweis: stdio bedeutet, den angegebenen Befehl als Prozess zu
STARTEN (Code-Ausführung). Nur gegen Server richten, denen man vertraut bzw.
die man gerade testet.
"""
from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import threading
import time

from mcpfrisk.core.dynamic_runner import DynamicTransportError, extract_jsonrpc_result
from mcpfrisk.core.models import AuthProbe, BoundaryOutcome, CredentialCondition

_CLIENT_INFO = {"name": "mcpfrisk", "version": "0.1.0"}
_MODERN_PROTOCOL = "2026-07-28"
_LEGACY_PROTOCOL = "2025-11-25"
_GRACE_SECONDS = 2.0


def _client_meta() -> dict:
    """Die per-Request-Metadaten der modernen (stateless) MCP-Ära."""
    return {
        "io.modelcontextprotocol/protocolVersion": _MODERN_PROTOCOL,
        "io.modelcontextprotocol/clientInfo": _CLIENT_INFO,
    }


class StdioServerHandle:
    """Kapselt den Server-Subprozess: Spawn (lazy), Reader-Thread, zeilenweises
    Schreiben/Lesen mit id-Korrelation und ein zeitbegrenztes request()."""

    def __init__(self, argv: list[str], timeout_s: float) -> None:
        self.argv = argv
        self.timeout_s = timeout_s
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._lines: queue.Queue = queue.Queue()
        self._next_id = 0

    def start(self) -> None:
        if self._proc is not None:
            return
        if not self.argv:
            raise DynamicTransportError("leeres stdio-Kommando")
        try:
            self._proc = subprocess.Popen(  # noqa: S603 - command is operator-provided by design
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, ValueError) as exc:
            raise DynamicTransportError(
                f"konnte stdio-Server nicht starten ({self.argv[0]!r}): {exc}"
            ) from exc
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            for raw in proc.stdout:  # newline-delimited
                self._lines.put(raw)
        except (OSError, ValueError):
            pass
        finally:
            self._lines.put(None)  # EOF-Sentinel

    def _write(self, message: dict) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise DynamicTransportError("stdio-Server nicht gestartet")
        line = json.dumps(message).encode("utf-8") + b"\n"
        try:
            proc.stdin.write(line)
            proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise DynamicTransportError(f"stdin-Schreiben fehlgeschlagen: {exc}") from exc

    def notify(self, method: str, params: dict | None = None) -> None:
        """Sendet eine Notification (ohne id, keine Antwort erwartet)."""
        self.start()
        self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def request(self, method: str, params: dict | None = None, timeout_s: float | None = None) -> dict:
        """Sendet eine Anfrage und wartet zeitbegrenzt auf die Antwort mit
        passender id. Nicht-JSON-Zeilen und fremde ids/Notifications werden
        ignoriert. Wirft DynamicTransportError bei Timeout/EOF/Transportfehler."""
        self.start()
        timeout = timeout_s if timeout_s is not None else self.timeout_s
        self._next_id += 1
        rid = self._next_id
        self._write({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DynamicTransportError(f"Timeout ({timeout}s) auf Antwort zu {method}")
            try:
                raw = self._lines.get(timeout=remaining)
            except queue.Empty:
                raise DynamicTransportError(f"Timeout ({timeout}s) auf Antwort zu {method}")
            if raw is None:
                raise DynamicTransportError(
                    "stdio-Server hat stdout geschlossen (Prozess beendet?)"
                )
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue  # Log-/Bannerzeile auf stdout -> ignorieren
            if isinstance(payload, dict) and payload.get("id") == rid:
                return payload
            # fremde id / Notification -> weiterlesen

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        for stream in (proc.stdin, proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
        if self._reader is not None:
            self._reader.join(timeout=_GRACE_SECONDS)
            self._reader = None


class StdioTransport:
    """stdio-Adapter des Transport-Ports."""

    def __init__(self, command: str | list[str], timeout_s: float = 5.0) -> None:
        if isinstance(command, str):
            argv = shlex.split(command, posix=(os.name != "nt"))
            self.target = command
        else:
            argv = list(command)
            self.target = " ".join(command)
        self.timeout_s = timeout_s
        self._handle = StdioServerHandle(argv, timeout_s)
        self._era: str | None = None  # "modern" | "legacy"
        self._negotiated = False

    def probe(self, operation: str, condition: CredentialCondition) -> AuthProbe:
        """stdio hat keinen Transport-Level-Auth-Boundary (keine HTTP-Header/Token).
        Korrekt INCONCLUSIVE -- weder Pass noch Finding (kein Spawn nötig)."""
        return AuthProbe(
            operation, condition, BoundaryOutcome.INCONCLUSIVE,
            "stdio: kein Transport-Auth-Boundary (kein HTTP-Header/Token) zum Prüfen",
        )

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout_s: float | None = None,
    ) -> dict:
        self._ensure_negotiated(timeout_s)
        request_params = dict(params or {})
        if self._era == "modern":
            request_params["_meta"] = _client_meta()
        payload = self._handle.request(method, request_params, timeout_s=timeout_s)
        return extract_jsonrpc_result(payload)

    def _ensure_negotiated(self, timeout_s: float | None) -> None:
        if self._negotiated:
            return
        self._negotiated = True  # nur einmal versuchen, auch bei Fehlschlag

        # 1) Modern probieren: server/discover mit Metadaten in _meta.
        try:
            resp = self._handle.request(
                "server/discover", {"_meta": _client_meta()}, timeout_s=timeout_s
            )
        except DynamicTransportError:
            resp = None

        if isinstance(resp, dict) and "error" not in resp:
            self._era = "modern"
            return

        # 2) Fallback: Legacy-Handshake (initialize + notifications/initialized).
        self._era = "legacy"
        try:
            self._handle.request(
                "initialize",
                {
                    "protocolVersion": _LEGACY_PROTOCOL,
                    "capabilities": {},
                    "clientInfo": _CLIENT_INFO,
                },
                timeout_s=timeout_s,
            )
            self._handle.notify("notifications/initialized")
        except DynamicTransportError:
            # Handshake gescheitert -> folgende call()s laufen in den Timeout und
            # werden vom Check als INCONCLUSIVE gewertet (Prinzip III).
            pass

    def close(self) -> None:
        self._handle.close()
