"""Local HTTP fixture servers for the PROTOCOL_COMPLIANCE dynamic check.

Each mode controls how the server answers an **unknown top-level JSON-RPC
method** (the only thing the check ever sends). Per the constitution (Principle
VI) there is one spec-conformant (clean) mode and several non-conformant
(vulnerable) ones:

- **compliant**: proper JSON-RPC error `{"code": -32601, "message": ...}` with a
  `"jsonrpc": "2.0"` envelope -> no finding.
- **compliant_http400**: the same correct error body, but carried on HTTP 400 --
  a server is allowed to transport a JSON-RPC error with an HTTP error status;
  the check must read the body and treat it as compliant (FR-002).
- **fail_open**: HTTP 200 with a `result` and no `error` -- pretends success for
  a method it does not know (MEDIUM, MISSING_ERROR).
- **wrong_code**: an `error` with a non-standard code (-32000) (LOW).
- **malformed_error**: an `error` object without an integer `code` (LOW).
- **malformed_envelope**: a correct error, but the response omits
  `"jsonrpc": "2.0"` (LOW).

`state["mutations"]` counts `tools/call` invocations so a test can assert the
check stayed strictly read-only (it should never call a tool at all).
"""
from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_COMPLIANT_ERROR = {"code": -32601, "message": "Method not found"}


class _BaseProtocolHandler(BaseHTTPRequestHandler):
    mode = "compliant"
    state: dict = {}

    def _send_json(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            pass

    def _unknown_method(self, rid: object) -> None:
        if self.mode == "compliant":
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "error": dict(_COMPLIANT_ERROR)})
        elif self.mode == "compliant_http400":
            self._send_json(400, {"jsonrpc": "2.0", "id": rid, "error": dict(_COMPLIANT_ERROR)})
        elif self.mode == "fail_open":
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {}})
        elif self.mode == "wrong_code":
            self._send_json(200, {
                "jsonrpc": "2.0", "id": rid,
                "error": {"code": -32000, "message": "unknown method"},
            })
        elif self.mode == "malformed_error":
            # error object without an integer code
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "error": {"message": "nope"}})
        elif self.mode == "malformed_envelope":
            # correct error, but missing the "jsonrpc": "2.0" envelope field
            self._send_json(200, {"id": rid, "error": dict(_COMPLIANT_ERROR)})
        else:
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {}})

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
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": []}})
            return
        if method == "tools/call":
            # The check must never reach here; count it if it ever does.
            self.state["mutations"] = self.state.get("mutations", 0) + 1
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"ok": True}})
            return
        # any other top-level method: the unknown-method trigger.
        self._unknown_method(rid)

    def log_message(self, *args: object) -> None:  # silence access logs
        pass


@contextmanager
def running_protocol_server(mode: str):
    """Start a fixture server on an ephemeral localhost port; yield (url, state)."""
    state: dict = {"mutations": 0}
    handler = type("_Handler", (_BaseProtocolHandler,), {"mode": mode, "state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/mcp", state
    finally:
        try:
            server.shutdown()
        except OSError:
            pass
        try:
            server.server_close()
        except OSError:
            pass
