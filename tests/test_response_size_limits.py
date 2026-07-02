"""Tests für die Response-Größen-Obergrenze bei HTTP- und stdio-Transport
(Post-Audit-Hardening, Bug 4).

Ohne Obergrenze puffert `HttpTransport.call()`/`StdioTransport`'s Reader-
Thread eine beliebig große Antwort/Zeile vollständig, bevor überhaupt geparst
wird -- ein bösartiger/kaputter Zielserver (McpFrisks Kernzielgruppe: Server,
die noch NICHT als vertrauenswürdig gelten) kann McpFrisk selbst per Memory-
Exhaustion treffen. Eine Obergrenze macht das zu einem sauberen
DynamicTransportError (-> INCONCLUSIVE) statt unbegrenztem Speicherverbrauch.
"""
from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mcpfrisk.core.dynamic_runner import DynamicTransportError, HttpTransport
from mcpfrisk.core.stdio_transport import StdioTransport

_OVERSIZED_BYTES = 11 * 1024 * 1024  # über der 10-MB-Obergrenze


class _HugeResponseHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        body = b'{"jsonrpc": "2.0", "id": 1, "result": {"pad": "' + b"A" * _OVERSIZED_BYTES + b'"}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *args: object) -> None:
        pass


@contextmanager
def _running_huge_response_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HugeResponseHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.shutdown()
        server.server_close()


def test_http_response_over_size_limit_raises_instead_of_buffering_fully():
    with _running_huge_response_server() as url:
        transport = HttpTransport(url, timeout_s=5.0)
        with pytest.raises(DynamicTransportError):
            transport.call("tools/list")


def test_stdio_line_over_size_limit_raises_instead_of_buffering_fully():
    # Ein Subprozess, der eine einzelne, extrem lange Zeile OHNE Newline
    # schreibt und danach am Leben bleibt (kein EOF) -- ohne Obergrenze würde
    # der Reader unbegrenzt auf ein Newline/EOF warten (das nie kommt) und
    # jeder der bis zu drei sequenziellen Anfrageversuche (server/discover-
    # Probe, legacy-initialize-Fallback, die eigentliche tools/list-Anfrage)
    # den vollen request()-Timeout (5s) ausschöpfen -- macht bis zu 15s.
    # Mit der Obergrenze wird der überlange Chunk sofort als Kanal-Ende
    # gewertet; die Laufzeit bleibt klar unter diesem Worst-Case, auch wenn
    # die Era-Negotiation (bewusst, siehe Bug 2) einen einmaligen Neustart
    # auslöst, sobald die modern-Probe selbst schon über die Obergrenze läuft.
    argv = [
        sys.executable, "-c",
        "import sys, time; sys.stdout.buffer.write(b'A' * (11 * 1024 * 1024)); "
        "sys.stdout.buffer.flush(); time.sleep(30)",
    ]
    transport = StdioTransport(argv, timeout_s=5.0)
    try:
        start = time.monotonic()
        with pytest.raises(DynamicTransportError):
            transport.call("tools/list")
        elapsed = time.monotonic() - start
    finally:
        transport.close()
    assert elapsed < 10.0, (
        f"dauerte {elapsed:.1f}s -- vermutlich über mehrere volle "
        "request()-Timeouts gelöst statt über die Größen-Obergrenze"
    )
