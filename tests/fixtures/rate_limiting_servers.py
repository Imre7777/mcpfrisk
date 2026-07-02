"""Local HTTP fixture servers for the RATE_LIMITING dynamic check.

Per the project constitution (Principle VI) the check is validated against a
single `get_item(id: string)` tool in four **deterministic** modes (no
reliance on real network/timing races, so the test suite stays fast and
non-flaky). All modes share one threshold: the first `_THRESHOLD - 1` calls
to `get_item` always behave normally; call number `_THRESHOLD` and beyond
trigger the mode's special behavior. This mirrors the check's own burst
(one baseline call, then a short burst) closely enough that a burst hits the
special behavior a few calls in, keeping tests fast:

- **throttled**: from the threshold on, responds with a `result` containing
  an explicit rate-limit message (HTTP 429, but the JSON-RPC envelope still
  carries `result` so McpFrisk's `call()` can see it -- the same shape as a
  real MCP server that reports rate limiting as a tool-execution error
  rather than a transport-level block).
- **degrading**: from the threshold on, sleeps a fixed, deterministic delay
  before responding (never caps, never throttles, never dies) -- simulates
  unbounded resource consumption without any countermeasure.
- **crash**: from the threshold on, stops answering entirely by shutting the
  server down from within the handler thread (same technique as
  `fuzzing_servers.py`'s `_kill_server` -- no `os._exit`, so the pytest
  process itself is never affected).
- **fast**: always answers quickly, never throttles, never degrades, never
  dies -- the clean baseline case.

`delete_item` is present in every mode; the fixture counts its invocations so
a test can assert the check stayed strictly read-only. `state["get_item_calls"]`
counts total `get_item` invocations so a test can assert the burst stays
bounded (no unbounded load against the target).
"""
from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ITEMS = {"item-1": {"id": "item-1", "name": "Widget"}}
_THRESHOLD = 5          # calls 1..THRESHOLD-1 are always normal
_DEGRADE_DELAY_S = 0.4  # deterministic, well above any sane rate-limiting threshold

_GET_ITEM_TOOL = {
    "name": "get_item",
    "description": "Get an item by its id.",
    "inputSchema": {
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
    },
}
_DELETE_ITEM_TOOL = {
    "name": "delete_item",
    "description": "Delete an item by its id.",
    "inputSchema": {
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
    },
}


class _BaseRateLimitingHandler(BaseHTTPRequestHandler):
    mode = "fast"
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

    def _kill_server(self) -> None:
        """Stops accepting connections from a handler thread (safe: the accept
        loop runs in a different thread). Simulates 'the process is gone'
        without terminating the actual pytest process."""
        def _stop() -> None:
            self.server.shutdown()
            self.server.server_close()

        threading.Thread(target=_stop, daemon=True).start()

    def _get_item(self, rid: object, args: dict) -> None:
        self.state["get_item_calls"] = self.state.get("get_item_calls", 0) + 1
        call_index = self.state["get_item_calls"]
        item_id = args.get("id")
        item = _ITEMS.get(item_id) if isinstance(item_id, str) else None
        result = {"item": item}

        if call_index < _THRESHOLD:
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": result})
            return

        if self.mode == "throttled":
            self._send_json(429, {
                "jsonrpc": "2.0", "id": rid,
                "result": {"isError": True, "content": [{
                    "type": "text",
                    "text": "429 Too Many Requests: rate limit exceeded, please retry after backoff",
                }]},
            })
            return
        if self.mode == "degrading":
            time.sleep(_DEGRADE_DELAY_S)
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": result})
            return
        if self.mode == "crash":
            self._kill_server()
            return  # no response -> this connection dies too
        # "fast" (and any unknown mode): behave normally forever
        self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": result})

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
            if self.mode == "no_tools":
                self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": [_DELETE_ITEM_TOOL]}})
                return
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": [_GET_ITEM_TOOL, _DELETE_ITEM_TOOL]}})
            return
        if method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "get_item":
                self._get_item(rid, args)
                return
            if name == "delete_item":
                self.state["mutations"] = self.state.get("mutations", 0) + 1
                self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"ok": True}})
                return
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {}})
            return
        self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {}})

    def log_message(self, *args: object) -> None:  # silence access logs
        pass

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            pass


@contextmanager
def running_rate_limiting_server(mode: str):
    """Start a fixture server on an ephemeral localhost port; yield (url, state).

    `state["mutations"]` counts destructive calls (must stay 0);
    `state["get_item_calls"]` counts total reads (proves a bounded burst)."""
    state: dict = {"mutations": 0, "get_item_calls": 0}
    handler = type("_Handler", (_BaseRateLimitingHandler,), {"mode": mode, "state": state})
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
