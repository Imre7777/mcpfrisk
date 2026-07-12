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

from mcpfrisk.core.dynamic_runner import (
    DynamicTransportError,
    IdentityConfig,
    extract_jsonrpc_result,
)
from mcpfrisk.core.models import AuthProbe, BoundaryOutcome, CredentialCondition

_CLIENT_INFO = {"name": "mcpfrisk", "version": "0.1.0"}
_MODERN_PROTOCOL = "2026-07-28"
_LEGACY_PROTOCOL = "2025-11-25"
_GRACE_SECONDS = 2.0
# Obergrenze für eine einzelne stdout-Zeile, bevor sie vollständig gepuffert
# wird -- ohne das puffert eine extrem lange (oder nie mit Newline
# abgeschlossene) Zeile unbegrenzt Speicher. Überschreitung wird wie EOF
# behandelt (Kanal gilt als tot -> DynamicTransportError).
_MAX_LINE_BYTES = 10 * 1024 * 1024


def _client_meta() -> dict:
    """Die per-Request-Metadaten der modernen (stateless) MCP-Ära."""
    return {
        "io.modelcontextprotocol/protocolVersion": _MODERN_PROTOCOL,
        "io.modelcontextprotocol/clientInfo": _CLIENT_INFO,
    }


class StdioServerHandle:
    """Kapselt den Server-Subprozess: Spawn (lazy), Reader-Thread, zeilenweises
    Schreiben/Lesen mit id-Korrelation und ein zeitbegrenztes request()."""

    def __init__(
        self,
        argv: list[str],
        timeout_s: float,
        env: dict[str, str] | None = None,
    ) -> None:
        self.argv = argv
        self.timeout_s = timeout_s
        # env-Overlay (z.B. identitäts-spezifisches Credential): auf os.environ
        # gelegt, damit der Subprozess seine Umgebung wie üblich erbt.
        self.env = {**os.environ, **env} if env else None
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._lines: queue.Queue = queue.Queue()
        self._next_id = 0
        # Vom Reader-Thread gesetztes EOF-Signal für die AKTUELLE Prozess-
        # Generation (eine frische Liste pro start(), s.u.). `proc.poll()`
        # allein reicht nicht: direkt nach einem Crash liefert poll() auf
        # Windows/CPython noch kurz None, bevor der Exit-Code eingesammelt
        # ist (empirisch verifizierter Race) -- das EOF-Signal des Readers
        # ist dagegen synchron mit der stdout-Schließung.
        self._eof_seen: list[bool] = [False]

    def start(self) -> None:
        # Bereits gestartet (lebendig ODER tot) -> kein automatischer
        # Neustart hier; das ist bewusst so (Neustart nur explizit über
        # restart(), s.u.). Ein automatischer Respawn in start() würde z.B.
        # SCHEMA_FUZZINGs/RATE_LIMITINGs Crash-Beweis per Liveness-Recheck
        # unterlaufen: ein neuer Prozess antwortet wieder normal, obwohl der
        # geprobte Prozess wirklich abgestürzt ist.
        if self._proc is not None:
            return
        if not self.argv:
            raise DynamicTransportError("leeres stdio-Kommando")
        self._spawn()

    def restart(self) -> None:
        """Erzwingt einen FRISCHEN Prozess, auch wenn der aktuelle Handle
        noch gesetzt ist. Nur für die Era-Negotiation gedacht (siehe
        `_StdioChannel.ensure_negotiated`): stirbt der Prozess schon bei der
        modern-Probe (`server/discover`), bekommt der legacy-Fallback
        (`initialize`) sonst nie eine echte Chance -- der tote Handle würde
        wiederverwendet (Bug: toter Handle wiederverwendet). Bewusst NICHT
        das Verhalten von `start()` selbst, weil ein bereits aktiv genutzter
        Kanal (nach erfolgreicher Verhandlung) NIE automatisch respawnen
        darf, sonst wäre ein echter Prozess-Crash während des eigentlichen
        Checks nicht mehr vom Liveness-Recheck unterscheidbar."""
        old_proc = self._proc
        if self._reader is not None:
            self._reader.join(timeout=_GRACE_SECONDS)
        self._reader = None
        self._lines = queue.Queue()  # frische Queue: kein stales EOF-Sentinel
        self._next_id = 0
        self._proc = None
        if old_proc is not None:
            # Alten (vermutlich toten) Prozess sauber beenden statt als
            # Waise laufen zu lassen (Bug beim ersten restart()-Entwurf:
            # der Handle wurde abgeworfen, ohne den Prozess zu terminieren).
            self._terminate(old_proc)
        self.start()

    def _spawn(self) -> None:
        try:
            self._proc = subprocess.Popen(  # noqa: S603 - command is operator-provided by design
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self.env,
            )
        except (OSError, ValueError) as exc:
            raise DynamicTransportError(
                f"konnte stdio-Server nicht starten ({self.argv[0]!r}): {exc}"
            ) from exc
        self._eof_seen = [False]  # frisches Signal für diese Prozess-Generation
        self._reader = threading.Thread(
            target=self._read_loop, args=(self._proc, self._lines, self._eof_seen), daemon=True
        )
        self._reader.start()

    def _read_loop(
        self, proc: subprocess.Popen, out_queue: queue.Queue, eof_seen: list[bool]
    ) -> None:
        # proc/out_queue/eof_seen werden als feste Argumente übergeben (nicht
        # dynamisch über self.gelesen), damit ein alter Reader-Thread nach
        # einem Neustart (frischer Prozess, frische Queue) garantiert NIE die
        # neue Generation beeinflusst -- sonst könnte sein EOF-Sentinel die
        # Antwort-Korrelation des neuen Kanals verfälschen, oder sein Signal
        # fälschlich die Liveness des neuen Prozesses zurücksetzen.
        if proc.stdout is None:
            eof_seen[0] = True
            return
        try:
            while True:
                raw = proc.stdout.readline(_MAX_LINE_BYTES + 1)
                if not raw:
                    break  # EOF
                if len(raw) > _MAX_LINE_BYTES:
                    # Zeile überschreitet die Obergrenze (z.B. kein Newline
                    # innerhalb des Limits) -- Kanal als beendet behandeln,
                    # statt weiter unbegrenzt zu puffern.
                    break
                out_queue.put(raw)
        except (OSError, ValueError):
            pass
        finally:
            eof_seen[0] = True  # synchrones Liveness-Signal, kein poll()-Race
            out_queue.put(None)  # EOF-Sentinel

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
        if proc is not None:
            self._terminate(proc)
        if self._reader is not None:
            self._reader.join(timeout=_GRACE_SECONDS)
            self._reader = None

    @staticmethod
    def _terminate(proc: subprocess.Popen) -> None:
        """Beendet einen Prozess zuverlässig (Streams schließen, terminate,
        bei Bedarf kill) -- geteilt zwischen close() und restart(), damit ein
        beim Neustart abgeworfener alter Prozess nicht als Waise weiterläuft."""
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


class _StdioChannel:
    """Ein Subprozess-Kanal für genau eine Identität (bzw. der Default-Kanal
    ohne Identität). Kapselt den Handle und die per-Kanal ausgehandelte Ära --
    verschiedene Identitäten sind verschiedene Prozesse und handeln unabhängig aus."""

    def __init__(self, handle: StdioServerHandle) -> None:
        self.handle = handle
        self.era: str | None = None  # "modern" | "legacy"
        self.negotiated = False

    def ensure_negotiated(self, timeout_s: float | None) -> None:
        if self.negotiated:
            return
        self.negotiated = True  # nur einmal versuchen, auch bei Fehlschlag

        # 1) Modern probieren: server/discover mit Metadaten in _meta.
        try:
            resp = self.handle.request(
                "server/discover", {"_meta": _client_meta()}, timeout_s=timeout_s
            )
        except DynamicTransportError:
            resp = None
            if self.handle._eof_seen[0]:
                # Die modern-Probe hat den Prozess NACHWEISLICH getötet (EOF,
                # nicht nur ein Timeout) -- für den legacy-Fallback einen
                # frischen Prozess starten, sonst bekommt initialize nie eine
                # echte Chance (Bug: toter Handle wiederverwendet). Ein reiner
                # Timeout (Prozess evtl. noch am Leben) löst KEINEN Neustart
                # aus -- der legacy-Fallback probiert dann denselben Handle.
                self.handle.restart()

        if isinstance(resp, dict) and "error" not in resp:
            self.era = "modern"
            return

        # 2) Fallback: Legacy-Handshake (initialize + notifications/initialized).
        self.era = "legacy"
        try:
            init_resp = self.handle.request(
                "initialize",
                {
                    "protocolVersion": _LEGACY_PROTOCOL,
                    "capabilities": {},
                    "clientInfo": _CLIENT_INFO,
                },
                timeout_s=timeout_s,
            )
        except DynamicTransportError:
            # Handshake gescheitert -> folgende call()s laufen in den Timeout und
            # werden vom Check als INCONCLUSIVE gewertet (Prinzip III).
            return
        if isinstance(init_resp, dict) and "error" in init_resp:
            # Server hat den Handshake explizit abgelehnt (z.B. protocolVersion
            # nicht unterstützt) -- NICHT als erfolgreich verhandelt behandeln
            # und KEIN notifications/initialized senden (Bug: wurde bisher nie
            # geprüft, die Session galt fälschlich als verhandelt).
            return
        self.handle.notify("notifications/initialized")


class StdioTransport:
    """stdio-Adapter des Transport-Ports.

    Identitäts-bewusst: da stdio keine HTTP-Header kennt, ist eine Identität ein
    **Env-Overlay** -- pro Identität wird ein eigener Subprozess gestartet
    (Credential in einer konfigurierbaren Env-Variable, Default `MCP_AUTH_TOKEN`).
    Das ist der real-world-Weg env-basierter Credentials und hält die
    Identitäten sauber getrennt. Ohne Identität (`identity=None`) bleibt es ein
    einzelner Default-Prozess -- exakt das bisherige Verhalten."""

    def __init__(
        self,
        command: str | list[str],
        timeout_s: float = 5.0,
        identity_config: IdentityConfig | None = None,
    ) -> None:
        if isinstance(command, str):
            self._argv = shlex.split(command, posix=(os.name != "nt"))
            self.target = command
        else:
            self._argv = list(command)
            self.target = " ".join(command)
        self.timeout_s = timeout_s
        self._identity_config = identity_config or IdentityConfig()
        self._channels: dict[str | None, _StdioChannel] = {}

    def _channel(self, identity: str | None) -> _StdioChannel:
        if identity in self._channels:
            return self._channels[identity]
        env: dict[str, str] | None = None
        if identity is not None:
            cred = self._identity_config.identities.get(identity)
            if cred:
                env = {self._identity_config.identity_env: cred}
        channel = _StdioChannel(StdioServerHandle(self._argv, self.timeout_s, env=env))
        self._channels[identity] = channel
        return channel

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
        identity: str | None = None,
    ) -> dict:
        return extract_jsonrpc_result(self.call_response(method, params, timeout_s, identity))

    def call_response(
        self,
        method: str,
        params: dict | None = None,
        timeout_s: float | None = None,
        identity: str | None = None,
    ) -> dict:
        """Wie `call()`, liefert aber die VOLLE JSON-RPC-Payload (inkl. `error`,
        `id`, `jsonrpc`) statt nur `result`. Der Handle liefert ohnehin das
        vollständige Payload -- `call()` wrappt es nur mit extract_jsonrpc_result
        (Rückwärtskompatibilität). Für PROTOCOL_COMPLIANCE (Feature 017)."""
        channel = self._channel(identity)
        channel.ensure_negotiated(timeout_s)
        request_params = dict(params or {})
        if channel.era == "modern":
            request_params["_meta"] = _client_meta()
        return channel.handle.request(method, request_params, timeout_s=timeout_s)

    def close(self) -> None:
        for channel in self._channels.values():
            channel.handle.close()
        self._channels.clear()
