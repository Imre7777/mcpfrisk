"""Tests für den RATE_LIMITING-Check (Feature 009).

Constitution-aligned:
- Prinzip I/VI: dieser Test wird VOR der Implementierung geschrieben (rot) --
  `mcpfrisk.checks.rate_limiting` existiert zum Zeitpunkt des Schreibens noch
  nicht, der Import schlägt fehl, bis der Check gebaut ist.
- Prinzip V: ein Finding entsteht NUR bei belegtem Crash (Liveness) oder
  konkret gemessener Latenz-Degradation mit Zahlenbeleg.
- Prinzip III: nichts auswertbar (kein Tool / roter Baseline / unreachable)
  -> INCONCLUSIVE, nie ein stiller Pass.
- Read-only: der Check darf `delete_item` nie auslösen.
- Burst-Umfang bewusst begrenzt (kein andauernder Last-Test) -- geprüft über
  den Aufruf-Zähler des Fixtures im "fast"-Modus (voller Burst ohne Abbruch).
- SC-002: läuft nachweislich über HTTP UND stdio.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from mcpfrisk.checks.rate_limiting import RateLimitingCheck
from mcpfrisk.core.dynamic_runner import DynamicRunner, DynamicSession
from mcpfrisk.core.models import BoundaryOutcome
from mcpfrisk.core.stdio_transport import StdioTransport

from tests.fixtures.rate_limiting_servers import running_rate_limiting_server

_FIXTURE = Path(__file__).parent / "fixtures" / "stdio_server.py"


def _run(target: str, timeout_s: float = 5.0):
    check = RateLimitingCheck()
    session = DynamicSession(target, timeout_s=timeout_s)
    try:
        result = check.run_against_server(session)
    finally:
        session.close()
    return result, check.to_finding(result)


def _stdio_session(era: str, mode: str, *, timeout_s: float = 5.0) -> DynamicSession:
    argv = [sys.executable, str(_FIXTURE), "--era", era, "--mode", mode, "--toolset", "burst"]
    return DynamicSession("stdio-fixture", timeout_s=timeout_s, transport=StdioTransport(argv, timeout_s))


def _run_session(session: DynamicSession):
    check = RateLimitingCheck()
    try:
        result = check.run_against_server(session)
    finally:
        session.close()
    return result, check.to_finding(result)


class TestRateLimitingHttp:
    # -- US1: crash under burst (true positive) -------------------------
    def test_crash_is_flagged(self):
        with running_rate_limiting_server("crash") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.check_id == "RATE_LIMITING"
        assert finding.severity.value == "high"
        assert "CWE-400" in (finding.cwe_ref or "")
        assert mutations == 0

    # -- US2: measured latency degradation, no throttle ------------------
    def test_degrading_is_flagged(self):
        with running_rate_limiting_server("degrading") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.severity.value == "medium"
        assert "CWE-400" in (finding.cwe_ref or "")
        assert mutations == 0

    # -- explicit throttle signal: pass regardless of the rest ------------
    def test_throttled_server_is_not_flagged(self):
        with running_rate_limiting_server("throttled") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome != BoundaryOutcome.NOT_ENFORCED
        assert finding is None
        assert mutations == 0

    # -- fast/clean server: no false positive, burst stays bounded -------
    def test_fast_server_is_not_flagged_and_burst_is_bounded(self):
        with running_rate_limiting_server("fast") as (url, state):
            result, finding = _run(url)
            calls = state["get_item_calls"]
            mutations = state["mutations"]
        assert result.outcome != BoundaryOutcome.NOT_ENFORCED
        assert finding is None
        assert mutations == 0
        # 1 baseline call + a small, fixed burst -- never unbounded.
        assert 2 <= calls <= 25

    # -- degradation: no read tool -----------------------------------------
    def test_no_read_tool_is_inconclusive(self):
        with running_rate_limiting_server("no_tools") as (url, _state):
            result, finding = _run(url)
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None

    def test_unreachable_server_is_inconclusive(self):
        result, finding = _run("http://127.0.0.1:1/mcp", timeout_s=1.0)
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None

    # -- runner integration ------------------------------------------------
    def test_runner_integration_reports_finding(self):
        with running_rate_limiting_server("crash") as (url, _state):
            result = DynamicRunner(checks=[RateLimitingCheck()], timeout_s=5.0).run(url)
        findings = [f for f in result.findings if f.check_id == "RATE_LIMITING"]
        assert len(findings) == 1
        assert "RATE_LIMITING" in result.checks_run

    # -- evidence hygiene / no OWASP-MCP mapping forced -------------------
    def test_degradation_evidence_is_bounded_length_and_has_no_owasp_ref(self):
        with running_rate_limiting_server("degrading") as (url, _state):
            _result, finding = _run(url)
        assert finding is not None
        assert len(finding.snippet or "") < 2000
        assert len(finding.description) < 3000
        assert finding.owasp_mcp_ref is None

    def test_evaluation_is_time_bounded(self):
        # even the slow "degrading" fixture must produce a verdict quickly --
        # the check stops at the first clear degradation signal (fail-fast).
        with running_rate_limiting_server("degrading") as (url, _state):
            start = time.monotonic()
            _run(url)
            elapsed = time.monotonic() - start
        assert elapsed < 10.0


class TestRateLimitingStdio:
    def test_crash_over_stdio_modern_is_flagged(self):
        result, finding = _run_session(_stdio_session("modern", "crash"))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.severity.value == "high"

    def test_crash_over_stdio_legacy_is_flagged(self):
        result, finding = _run_session(_stdio_session("legacy", "crash"))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None

    def test_fast_over_stdio_is_not_flagged(self):
        result, finding = _run_session(_stdio_session("modern", "fast"))
        assert result.outcome != BoundaryOutcome.NOT_ENFORCED
        assert finding is None
