"""Local multi-tenant HTTP fixture servers for the RBAC_CROSS_TENANT check.

Per the constitution (Principle VI) the check is validated against BOTH:
- a *vulnerable* server that leaks across tenants two ways -- it resolves any
  record id regardless of the caller (IDOR / CWE-639) and trusts a client-
  supplied `tenant` argument -- and
- a *clean* server that derives the tenant from the verified caller token and
  scopes every response to it (the documented correct fix), ignoring the
  client-supplied tenant argument and enforcing per-record ownership.

Identity is carried as `Authorization: Bearer <token>`; each token maps to a
tenant. Tenant A owns a record with a long, unique content marker; the leak is
proven when caller B's response contains that marker. The server also counts
mutating (`delete_record`) calls -- the check must never trigger one (it stays
read-only), which the tests assert stays at zero.
"""
from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# token -> tenant. Two distinct test tenants (see OWASP: "create two test tenants").
_TOKENS = {
    "tok-a": "tenant-a",
    "tok-b": "tenant-b",
}

# Each tenant owns one private record with a long, unique content marker so a
# cross-tenant leak is unambiguous (the marker must not be legitimately visible
# to the other tenant).
_RECORDS = {
    "rec-a": {
        "id": "rec-a",
        "owner": "tenant-a",
        "title": "Alice private note",
        "content": "MARKER_ALICE_5f2c9a71e4b8d3c6",
    },
    "rec-b": {
        "id": "rec-b",
        "owner": "tenant-b",
        "title": "Bob private note",
        "content": "MARKER_BOB_1a2b3c4d5e6f7089",
    },
}

_TOOLS = [
    {
        "name": "list_records",
        "description": "List records visible to the caller.",
        "inputSchema": {
            "type": "object",
            "properties": {"tenant": {"type": "string"}},
        },
    },
    {
        "name": "get_record",
        "description": "Get a single record by its id.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
    {
        "name": "delete_record",
        "description": "Delete a record by its id.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
]


class _BaseRbacHandler(BaseHTTPRequestHandler):
    mode = "vulnerable"
    state: dict = {}

    def _caller_tenant(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        return _TOKENS.get(token)

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

    def _list_records(self, caller: str | None, args: dict) -> dict:
        arg_tenant = args.get("tenant")
        if self.mode == "vulnerable" and arg_tenant:
            target = arg_tenant  # BUG: trusts the client-supplied tenant argument
        else:
            target = caller  # correct: scope to the verified caller identity
        records = [r for r in _RECORDS.values() if r["owner"] == target]
        return {"records": records}

    def _get_record(self, caller: str | None, args: dict) -> dict:
        record = _RECORDS.get(args.get("id", ""))
        if record is None:
            return {"record": None}
        if self.mode == "clean" and record["owner"] != caller:
            return {"record": None, "error": "forbidden"}  # ownership enforced
        return {"record": record}  # vulnerable: no ownership check (IDOR)

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            req = {}
        rid = req.get("id", 1)
        method = req.get("method")
        caller = self._caller_tenant()

        if method == "tools/list":
            self._send_result(rid, {"tools": _TOOLS})
            return
        if method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "list_records":
                self._send_result(rid, self._list_records(caller, args))
            elif name == "get_record":
                self._send_result(rid, self._get_record(caller, args))
            elif name == "delete_record":
                self.state["mutations"] = self.state.get("mutations", 0) + 1
                self._send_result(rid, {"ok": True})
            else:
                self._send_result(rid, {})
            return
        self._send_result(rid, {})

    def log_message(self, *args: object) -> None:  # silence test output
        pass


@contextmanager
def running_rbac_server(mode: str):
    """Start a multi-tenant fixture server; yield (mcp_url, state).

    `state["mutations"]` counts destructive calls so a test can assert the check
    stayed strictly read-only."""
    state: dict = {"mutations": 0}
    handler = type("_Handler", (_BaseRbacHandler,), {"mode": mode, "state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/mcp", state
    finally:
        server.shutdown()
        server.server_close()
