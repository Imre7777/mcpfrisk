"""Local HTTP fixture servers for the AUTH_BOUNDARY dynamic check.

Per the project constitution (Principle VI) the check is validated against BOTH:
- a *vulnerable* server that answers any caller without authentication, and
- a *clean* server that refuses unauthenticated/invalid requests with HTTP 401.

These are deliberately minimal stdlib `http.server` responders: the AUTH_BOUNDARY
check only judges the HTTP authorization boundary (401/403 vs 2xx), which a
properly-secured MCP server enforces at the transport layer *before* any MCP/
JSON-RPC handling. That makes a full MCP server unnecessary to exercise the boundary.
"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _BaseAuthHandler(BaseHTTPRequestHandler):
    mode = "vulnerable"
    slow_seconds = 0.0

    def _respond(self, code: int) -> None:
        body = b'{"jsonrpc":"2.0","id":1,"result":{}}' if code < 400 else b'{"error":"unauthorized"}'
        self.send_response(code)
        if code == 401:
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="/.well-known/oauth-protected-resource"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # client gave up (e.g. timeout test) -- harmless

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)

        if self.slow_seconds:
            time.sleep(self.slow_seconds)

        auth = self.headers.get("Authorization")
        if self.mode == "vulnerable":
            # Answers everyone, authenticated or not -> boundary NOT enforced.
            self._respond(200)
        elif self.mode == "clean":
            # Only a specific valid token is accepted; everything else -> 401.
            self._respond(200 if auth == "Bearer valid-token" else 401)
        elif self.mode == "accepts_any_token":
            # Checks for presence of a token but never validates it -> the
            # invalid-credential probe still gets through.
            self._respond(200 if auth else 401)
        else:  # pragma: no cover - misuse
            self._respond(500)

    def log_message(self, *args) -> None:  # silence test output
        pass


@contextmanager
def running_auth_server(mode: str, slow_seconds: float = 0.0):
    """Start a fixture server on an ephemeral localhost port; yield its /mcp URL."""
    handler = type("_Handler", (_BaseAuthHandler,), {"mode": mode, "slow_seconds": slow_seconds})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.shutdown()
        server.server_close()
