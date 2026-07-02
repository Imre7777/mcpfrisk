"""Local HTTP fixture servers for the ERROR_LEAKAGE dynamic check.

Per the project constitution (Principle VI) the check is validated against a
single `get_item(id: string)` tool plus two protocol-level triggers, in two
modes:

- **vulnerable**: all three "natural" (schema-conformant, adversarial-free)
  error triggers leak internals -- calling a nonexistent tool name, calling a
  nonexistent top-level JSON-RPC method, and looking up a well-formed but
  nonexistent item id all surface a raw Python traceback (the realistic shape
  for a naive dispatcher/ORM that doesn't catch its own exceptions).
- **clean**: all three triggers return generic, structured responses (a
  `-32602`/`-32601` JSON-RPC error, or `{"item": None}`) with no internals.

`delete_item` is present in both modes; the fixture counts its invocations so
a test can assert the check never triggers it (read-only guarantee), exactly
like `fuzzing_servers.py`.
"""
from __future__ import annotations

import json
import threading
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


def _leak_result(rid: object, marker: Exception) -> dict:
    try:
        raise marker
    except type(marker):
        tb = traceback.format_exc()
    return {"jsonrpc": "2.0", "id": rid, "result": {"isError": True, "content": [{"type": "text", "text": tb}]}}


class _BaseErrorLeakageHandler(BaseHTTPRequestHandler):
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

    def _get_item(self, rid: object, args: dict) -> None:
        item_id = args.get("id")
        item = _ITEMS.get(item_id) if isinstance(item_id, str) else None
        if item is not None:
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"item": item}})
            return
        if self.mode == "vulnerable":
            self._send_json(200, _leak_result(
                rid, RuntimeError(f"sqlite3.OperationalError: no such row: items.id={item_id!r}")
            ))
            return
        self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"item": None}})

    def _unknown_tool(self, rid: object, name: object) -> None:
        if self.mode in ("vulnerable", "no_tools"):
            self._send_json(200, _leak_result(rid, KeyError(f"No such tool registered: {name!r}")))
            return
        self._send_json(200, {
            "jsonrpc": "2.0", "id": rid,
            "error": {"code": -32602, "message": f"Unknown tool: {name}"},
        })

    def _unknown_method(self, rid: object, method: object) -> None:
        if self.mode in ("vulnerable", "no_tools"):
            self._send_json(200, _leak_result(
                rid, AttributeError(f"'Dispatcher' object has no attribute {method!r}")
            ))
            return
        self._send_json(200, {
            "jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "Method not found"},
        })

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
                self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": []}})
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
            self._unknown_tool(rid, name)
            return
        # any other top-level method: the US2 "unknown method" trigger.
        self._unknown_method(rid, method)

    def log_message(self, *args: object) -> None:  # silence access logs
        pass


@contextmanager
def running_error_leakage_server(mode: str):
    """Start a fixture server on an ephemeral localhost port; yield (url, state).

    `state["mutations"]` counts destructive calls so a test can assert the
    check stayed strictly read-only."""
    state: dict = {"mutations": 0}
    handler = type("_Handler", (_BaseErrorLeakageHandler,), {"mode": mode, "state": state})
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
