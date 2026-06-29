"""Local HTTP fixture servers for the SSRF_CHECK dynamic check.

Per the project constitution (Principle VI) the check is validated against BOTH:
- a *vulnerable* fetch server that retrieves any URL it is handed, and
- a *clean* server that refuses loopback / private / link-local / non-http(s)
  targets before fetching (the documented correct SSRF fix), plus
- a *redirect-bypass* server that validates only the initial host but follows
  redirects without re-validation (US3).

These are minimal stdlib `http.server` JSON-RPC responders that implement just
enough of the MCP surface the check exercises: `tools/list` (advertising a
URL-accepting `fetch_url` tool) and `tools/call` (which actually performs the
outbound request according to the server's mode). The authoritative SSRF signal
is whether McpFrisk's callback listener is hit -- so the vulnerable server must
really fetch, and the clean server must really refuse.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

_FETCH_TIMEOUT = 1.5


def _is_blocked_target(url: str) -> bool:
    """True, wenn die URL auf ein reserviertes/internes Ziel zeigt (der 'clean'-
    Server lehnt genau diese ab: Loopback/RFC1918/Link-Local/Nicht-HTTP)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return True
    host = parsed.hostname or ""
    if host in ("localhost",):
        return True
    candidates: list[str] = []
    try:
        ipaddress.ip_address(host)
        candidates = [host]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
            candidates = [info[4][0] for info in infos]
        except OSError:
            return True  # nicht auflösbar -> sicherheitshalber blocken
    for cand in candidates:
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            return True
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            return True
    return False


def _fetch(url: str, *, follow_redirects: bool) -> str:
    opener_url = url
    try:
        if follow_redirects:
            with urllib.request.urlopen(opener_url, timeout=_FETCH_TIMEOUT) as resp:  # noqa: S310
                resp.read(64)
        else:
            # Manuell ohne Redirect-Folgen.
            req = urllib.request.Request(opener_url)  # noqa: S310
            opener = urllib.request.build_opener(_NoRedirect())
            with opener.open(req, timeout=_FETCH_TIMEOUT) as resp:
                resp.read(64)
        return "fetched"
    except urllib.error.HTTPError as exc:
        return f"fetched (HTTP {exc.code})"
    except (urllib.error.URLError, OSError):
        return "fetch attempted"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


class _BaseSsrfHandler(BaseHTTPRequestHandler):
    mode = "vulnerable"

    def _send_result(self, rid: object, result: dict) -> None:
        body = json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _perform_fetch(self, url: str) -> str:
        if self.mode == "vulnerable":
            return _fetch(url, follow_redirects=True)
        if self.mode == "clean":
            if _is_blocked_target(url):
                return "refused: internal/reserved target blocked"
            return _fetch(url, follow_redirects=True)
        if self.mode == "redirect":
            # Validiert NUR die initiale URL, folgt dann Redirects ohne erneute
            # Prüfung -- klassischer First-Host-Only-Bypass.
            if _is_blocked_target(url):
                return "refused: internal/reserved target blocked"
            return _fetch(url, follow_redirects=True)
        return "noop"  # pragma: no cover

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            req = {}
        rid = req.get("id", 1)
        method = req.get("method")

        if method == "tools/list":
            self._send_result(rid, {
                "tools": [{
                    "name": "fetch_url",
                    "description": "Fetch a URL and return its body.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"url": {"type": "string", "format": "uri"}},
                        "required": ["url"],
                    },
                }]
            })
            return
        if method == "tools/call":
            args = (req.get("params") or {}).get("arguments") or {}
            url = args.get("url", "")
            observed = self._perform_fetch(url)
            self._send_result(rid, {"content": [{"type": "text", "text": observed}]})
            return
        self._send_result(rid, {})

    def log_message(self, *args: object) -> None:  # silence test output
        pass


@contextmanager
def running_ssrf_server(mode: str):
    """Start a fixture server on an ephemeral localhost port; yield its /mcp URL."""
    handler = type("_Handler", (_BaseSsrfHandler,), {"mode": mode})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.shutdown()
        server.server_close()
