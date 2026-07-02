"""Local HTTP fixture servers for the SCHEMA_FUZZING dynamic check.

Per the project constitution (Principle VI) the check is validated against
several modes of a single `get_item(id: string)` tool:

- **crash**: an unvalidated, oversized/wrong-typed `id` reaches code that would
  normally corrupt process state (segfault/OOM-class bug); we simulate the
  *observable* effect -- the server stops answering entirely -- by shutting
  down the HTTP server from within the handler. This proves "process/
  connection death" (FR-003) without literally killing the pytest process
  (the fixture runs in-process via `ThreadingHTTPServer`, unlike the stdio
  fixture which is a real subprocess).
- **leak**: the handler's unhandled exception surfaces as a raw Python
  traceback inside the MCP tool-execution-error result (`isError` + `content`
  text) -- the realistic shape for a naive handler that doesn't catch its own
  exceptions (FR-004, CWE-209).
- **clean**: validates `id` and returns a structured, generic JSON-RPC
  `-32602 Invalid params` error with no internals; stays alive.
- **hang**: a bad payload makes the handler sleep well past any test timeout
  (proves a payload can *not* be mistaken for a crash: a liveness recheck via
  a fresh connection still succeeds).
- **broken_baseline**: `get_item` always fails at the transport level, even
  for a well-formed call -- the check must never blame a payload it never
  sent (FR-002).
- **no_read_tool**: only a mutating tool (`delete_item`) is advertised.

`delete_item` is present in every mode except `no_read_tool`'s tools/list
filtering; the fixture counts its invocations so a test can assert the check
never triggers it (read-only guarantee).
"""
from __future__ import annotations

import json
import threading
import time
import traceback
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ITEMS = {"item-1": {"id": "item-1", "name": "Widget"}}

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


def _is_bad_id(item_id: object) -> bool:
    return not isinstance(item_id, str) or len(item_id) > 1000


class _BaseFuzzHandler(BaseHTTPRequestHandler):
    mode = "clean"
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
        item_id = args.get("id")

        if self.mode == "clean":
            if _is_bad_id(item_id):
                self._send_json(200, {
                    "jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32602, "message": "Invalid params: id must be a non-empty string"},
                })
                return
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"item": _ITEMS.get(item_id)}})
            return

        if self.mode == "crash":
            if _is_bad_id(item_id):
                self._kill_server()
                return  # no response -> this connection dies too
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"item": _ITEMS.get(item_id)}})
            return

        if self.mode == "leak":
            if _is_bad_id(item_id):
                try:
                    raise TypeError(f"item id must be str, got {type(item_id).__name__}: {item_id!r}")
                except TypeError:
                    tb = traceback.format_exc()
                self._send_json(200, {
                    "jsonrpc": "2.0", "id": rid,
                    "result": {"isError": True, "content": [{"type": "text", "text": tb}]},
                })
                return
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"item": _ITEMS.get(item_id)}})
            return

        if self.mode == "hang":
            if _is_bad_id(item_id):
                time.sleep(5.0)  # far beyond any probe timeout used in tests
                return
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"item": _ITEMS.get(item_id)}})
            return

        if self.mode == "broken_baseline":
            # Even a well-formed call fails -- the check must never blame a
            # payload it never sent.
            raise RuntimeError("simulated: get_item is always broken")

        # default: behave like clean
        self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"item": _ITEMS.get(item_id)}})

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
            if self.mode == "no_read_tool":
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

    def handle_error(self, request: object, client_address: object) -> None:
        # broken_baseline intentionally raises inside do_POST -- don't spam
        # the test run's stderr with an expected traceback.
        pass


@contextmanager
def running_fuzzing_server(mode: str):
    """Start a fixture server on an ephemeral localhost port; yield (url, state).

    `state["mutations"]` counts destructive calls so a test can assert the
    check stayed strictly read-only."""
    state: dict = {"mutations": 0}
    handler = type("_Handler", (_BaseFuzzHandler,), {"mode": mode, "state": state})
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
