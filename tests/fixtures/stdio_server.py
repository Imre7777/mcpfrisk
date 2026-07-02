"""Standalone stdio-MCP-Fixture-Server für die Tier-2-Tests.

Wird von den Tests als Subprozess gestartet (`python stdio_server.py --era ...
--mode ...`) und spricht newline-delimited JSON-RPC über stdin/stdout -- genau
der Transport, den StdioTransport implementiert. Selbst-enthalten (keine Projekt-
Imports), damit er als reines Skript läuft.

Achsen (Prinzip VI -- paired fixtures, beide Protokoll-Ären):
- --era legacy : server/discover -> Fehler (-32601); verlangt initialize-Handshake.
- --era modern : server/discover -> result; stateless, kein Handshake.
- --toolset fetch (default): SSRF-Fixture, siehe --mode unten.
- --toolset fuzz: SCHEMA_FUZZING-Fixture -- ein `get_item(id: string)`-Tool.
  --mode vulnerable : ein typ-fremder/übergroßer `id`-Wert löst eine ungefangene
                       Exception aus -> der Prozess stirbt (Crash-Beleg, FR-003).
  --mode clean       : validiert `id`, antwortet strukturiert mit -32602, lebt weiter.
- --mode vulnerable (toolset fetch) : tools/call holt JEDE URL (Callback-Listener wird getroffen).
- --mode clean      (toolset fetch) : tools/call lehnt Loopback/RFC1918/Link-Local/Nicht-HTTP ab.
- --mode silent     : antwortet nie (für den Timeout-/Lifecycle-Test).
- --banner          : schreibt vor dem Loop eine Nicht-JSON-Zeile auf stdout
                      (testet, dass der Client Log-/Bannerzeilen ignoriert).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

_FETCH_TIMEOUT = 1.5
_MODERN_PROTOCOL = "2026-07-28"
_LEGACY_PROTOCOL = "2025-11-25"
_SERVER_INFO = {"name": "stdio-fixture", "version": "0.0.1"}

_FETCH_TOOL = {
    "name": "fetch_url",
    "description": "Fetch a URL and return its body.",
    "inputSchema": {
        "type": "object",
        "properties": {"url": {"type": "string", "format": "uri"}},
        "required": ["url"],
    },
}

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


def _is_bad_id(item_id: object) -> bool:
    return not isinstance(item_id, str) or len(item_id) > 1000


def _fuzz_get_item(rid: object, args: dict, mode: str) -> None:
    item_id = args.get("id")
    if mode == "vulnerable":
        if _is_bad_id(item_id):
            # Ungefangen -- der Prozess stirbt (Crash-Beleg für den Liveness-Recheck).
            raise TypeError(f"item id must be str, got {type(item_id).__name__}: {item_id!r}")
        _result(rid, {"item": _ITEMS.get(item_id)})
        return
    # clean
    if _is_bad_id(item_id):
        _error(rid, -32602, "Invalid params: id must be a non-empty string")
        return
    _result(rid, {"item": _ITEMS.get(item_id)})


def _is_blocked_target(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return True
    host = parsed.hostname or ""
    if host == "localhost":
        return True
    candidates: list[str] = []
    try:
        ipaddress.ip_address(host)
        candidates = [host]
    except ValueError:
        try:
            candidates = [info[4][0] for info in socket.getaddrinfo(host, None)]
        except OSError:
            return True
    for cand in candidates:
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            return True
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            return True
    return False


def _fetch(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=_FETCH_TIMEOUT) as resp:  # noqa: S310
            resp.read(64)
        return "fetched"
    except urllib.error.HTTPError as exc:
        return f"fetched (HTTP {exc.code})"
    except (urllib.error.URLError, OSError):
        return "fetch attempted"


def _perform_fetch(url: str, mode: str) -> str:
    if mode == "clean" and _is_blocked_target(url):
        return "refused: internal/reserved target blocked"
    return _fetch(url)


def _send(obj: dict) -> None:
    sys.stdout.buffer.write((json.dumps(obj) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


def _result(rid: object, result: dict) -> None:
    _send({"jsonrpc": "2.0", "id": rid, "result": result})


def _error(rid: object, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})


def _handle(method: str, rid: object, req: dict, era: str, mode: str, toolset: str) -> None:
    if method == "server/discover":
        if era == "modern":
            _result(rid, {
                "protocolVersion": _MODERN_PROTOCOL,
                "supported": [_MODERN_PROTOCOL],
                "capabilities": {"tools": {}},
                "serverInfo": _SERVER_INFO,
            })
        else:
            _error(rid, -32601, "Method not found")
        return
    if method == "initialize":
        _result(rid, {
            "protocolVersion": _LEGACY_PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": _SERVER_INFO,
        })
        return
    if method == "tools/list":
        _result(rid, {"tools": [_GET_ITEM_TOOL] if toolset == "fuzz" else [_FETCH_TOOL]})
        return
    if method == "tools/call":
        params = req.get("params") or {}
        args = params.get("arguments") or {}
        if toolset == "fuzz":
            if params.get("name") == "get_item":
                _fuzz_get_item(rid, args, mode)
            else:
                _result(rid, {})
            return
        observed = _perform_fetch(args.get("url", ""), mode)
        _result(rid, {"content": [{"type": "text", "text": observed}]})
        return
    _result(rid, {})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--era", choices=["legacy", "modern"], default="legacy")
    parser.add_argument("--mode", choices=["vulnerable", "clean", "silent"], default="vulnerable")
    parser.add_argument("--toolset", choices=["fetch", "fuzz"], default="fetch")
    parser.add_argument("--banner", action="store_true")
    args = parser.parse_args()

    if args.banner:
        # Eine Nicht-JSON-Zeile auf stdout -- ein robuster Client ignoriert sie.
        sys.stdout.buffer.write(b"[stdio-fixture] starting up\n")
        sys.stdout.buffer.flush()

    for raw in sys.stdin.buffer:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(req, dict):
            continue
        rid = req.get("id")
        if rid is None:
            continue  # Notification -> keine Antwort
        if args.mode == "silent":
            continue  # nie antworten (Timeout-/Lifecycle-Test)
        _handle(req.get("method", ""), rid, req, args.era, args.mode, args.toolset)
    return 0


if __name__ == "__main__":
    sys.exit(main())
