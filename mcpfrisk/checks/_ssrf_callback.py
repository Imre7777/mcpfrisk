"""Einmaliger lokaler Callback-Listener für den SSRF_CHECK (Tier 2).

Der zuverlässige, fehlalarmarme SSRF-Nachweis ist out-of-band: McpFrisk startet
einen kurzlebigen HTTP-Listener auf 127.0.0.1:0, gibt einem URL-akzeptierenden
Tool eine eindeutige Callback-URL und wertet einen eingehenden Treffer mit
passendem Token als *Beweis*, dass der Server tatsächlich einen ausgehenden
Request in McpFrisks Auftrag ausgeführt hat (nicht bloß eine Heuristik).

Bewusst stdlib-only (http.server) -- keine neue Abhängigkeit (Constitution IV).
Es wird nur an Loopback gebunden; der Body ist ein fixer, harmloser String.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_CALLBACK_PREFIX = "/cb/"
_REDIRECT_PREFIX = "/redirect/"
_BENIGN_BODY = b"mcpfrisk-callback-ok"


@dataclass
class CallbackHit:
    """Ein einzelner eingehender Request, den der Listener aufgezeichnet hat."""

    token: str
    path: str
    method: str
    at: float


class CallbackListener:
    """Context-Manager um einen Loopback-Listener mit Token-basierten Proben.

    Nutzung::

        with CallbackListener() as listener:
            token, url = listener.new_probe_url()
            ...  # url an das Tool geben
            hit = listener.received(token, timeout_s=2.0)
    """

    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._hits: dict[str, CallbackHit] = {}
        self._events: dict[str, threading.Event] = {}

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "CallbackListener":
        handler = _make_handler(self)
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def base_url(self) -> str:
        if self._server is None:  # pragma: no cover - misuse outside context
            raise RuntimeError("CallbackListener nicht gestartet (nutze 'with').")
        host, port = self._server.server_address[0], self._server.server_address[1]
        return f"http://{host}:{port}"

    # -- probes ------------------------------------------------------------
    def new_probe_url(self) -> tuple[str, str]:
        """Erzeugt ein frisches Token und die zugehörige Callback-URL."""
        token = uuid.uuid4().hex
        with self._lock:
            self._events[token] = threading.Event()
        return token, f"{self.base_url}{_CALLBACK_PREFIX}{token}"

    def redirect_url(self, token: str) -> str:
        """URL auf dem Listener, die per 302 auf die Callback-URL des Tokens
        umleitet -- für den Redirect-Bypass-Test (US3)."""
        return f"{self.base_url}{_REDIRECT_PREFIX}{token}"

    def received(self, token: str, timeout_s: float) -> CallbackHit | None:
        """Wartet bis zu `timeout_s` auf einen Treffer mit diesem Token
        (begrenzte Wartezeit -- FR-010). Gibt den Hit zurück oder None."""
        with self._lock:
            event = self._events.get(token)
        if event is None:  # pragma: no cover - misuse
            return None
        if event.wait(timeout_s):
            with self._lock:
                return self._hits.get(token)
        return None

    # -- internal ----------------------------------------------------------
    def _record(self, token: str, path: str, method: str) -> None:
        with self._lock:
            self._hits[token] = CallbackHit(token=token, path=path, method=method, at=time.monotonic())
            event = self._events.get(token)
        if event is not None:
            event.set()


def _make_handler(listener: CallbackListener) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            path = self.path
            if path.startswith(_REDIRECT_PREFIX):
                token = path[len(_REDIRECT_PREFIX):].split("?", 1)[0]
                self.send_response(302)
                self.send_header("Location", f"{_CALLBACK_PREFIX}{token}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path.startswith(_CALLBACK_PREFIX):
                token = path[len(_CALLBACK_PREFIX):].split("?", 1)[0]
                listener._record(token, path, self.command)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(_BENIGN_BODY)))
                self.end_headers()
                try:
                    self.wfile.write(_BENIGN_BODY)
                except OSError:  # pragma: no cover - client gave up
                    pass
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        # Manche Fetch-Tools nutzen GET, manche HEAD/POST -- alle als Treffer werten.
        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            self._handle()

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            self._handle()

        def do_HEAD(self) -> None:  # noqa: N802
            self._handle()

        def log_message(self, *args: object) -> None:  # silence test output
            pass

    return _Handler
