"""Tests für den SCHEMA_FUZZING-Check (Feature 007).

Constitution-aligned:
- Prinzip I/VI: dieser Test wird VOR der Implementierung geschrieben (rot) --
  `mcpfrisk.checks.schema_fuzzing` existiert zum Zeitpunkt des Schreibens noch
  nicht, der Import schlägt fehl, bis der Check gebaut ist.
- Prinzip V: ein Finding entsteht NUR bei belegtem Crash (Liveness-Recheck)
  oder konkret geleaktem Interna-Ausschnitt -- niemals bei bloßer Ablehnung.
- Prinzip III: kein fuzzbares Tool / roter Baseline / Hang -> INCONCLUSIVE,
  niemals ein stiller Pass, niemals ein eigenständiges Finding bei einem Hang.
- Read-only: der Check darf `delete_item` nie auslösen.
- SC-002: läuft nachweislich über HTTP UND stdio.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from mcpfrisk.checks.schema_fuzzing import SchemaFuzzingCheck
from mcpfrisk.core.dynamic_runner import DynamicRunner, DynamicSession
from mcpfrisk.core.models import BoundaryOutcome
from mcpfrisk.core.stdio_transport import StdioTransport

from tests.fixtures.fuzzing_servers import running_fuzzing_server

_FIXTURE = Path(__file__).parent / "fixtures" / "stdio_server.py"


def _run(target: str, timeout_s: float = 3.0):
    check = SchemaFuzzingCheck()
    session = DynamicSession(target, timeout_s=timeout_s)
    try:
        result = check.run_against_server(session)
    finally:
        session.close()
    return result, check.to_finding(result)


def _stdio_session(era: str, mode: str, *, timeout_s: float = 5.0) -> DynamicSession:
    argv = [sys.executable, str(_FIXTURE), "--era", era, "--mode", mode, "--toolset", "fuzz"]
    return DynamicSession("stdio-fixture", timeout_s=timeout_s, transport=StdioTransport(argv, timeout_s))


def _run_session(session: DynamicSession):
    check = SchemaFuzzingCheck()
    try:
        result = check.run_against_server(session)
    finally:
        session.close()
    return result, check.to_finding(result)


class TestSchemaFuzzingHttp:
    # -- US1: crash detection (true positive) ---------------------------
    def test_crash_is_flagged(self):
        with running_fuzzing_server("crash") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.check_id == "SCHEMA_FUZZING"
        assert finding.severity.value == "high"
        assert mutations == 0

    # -- US2: stacktrace/internals leak (true positive) ------------------
    def test_leak_is_flagged(self):
        with running_fuzzing_server("leak") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.check_id == "SCHEMA_FUZZING"
        assert finding.severity.value == "medium"
        assert finding.cwe_ref == "CWE-209"
        assert mutations == 0

    # -- clean server: no false positive ---------------------------------
    def test_clean_server_is_not_flagged(self):
        with running_fuzzing_server("clean") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome != BoundaryOutcome.NOT_ENFORCED
        assert finding is None
        assert mutations == 0

    # -- US3: safe degradation, never a silent pass -----------------------
    def test_no_read_tool_is_inconclusive(self):
        with running_fuzzing_server("no_read_tool") as (url, _state):
            result, finding = _run(url)
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None

    def test_broken_baseline_is_inconclusive(self):
        with running_fuzzing_server("broken_baseline") as (url, _state):
            result, finding = _run(url)
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None

    def test_hang_is_inconclusive_not_a_finding(self):
        with running_fuzzing_server("hang") as (url, _state):
            start = time.monotonic()
            result, finding = _run(url, timeout_s=3.0)
            elapsed = time.monotonic() - start
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None
        assert elapsed < 15.0  # bounded, no real hang

    def test_unreachable_server_is_inconclusive(self):
        result, finding = _run("http://127.0.0.1:1/mcp", timeout_s=1.0)
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None

    # -- runner integration ------------------------------------------------
    def test_runner_integration_reports_finding(self):
        with running_fuzzing_server("crash") as (url, _state):
            result = DynamicRunner(checks=[SchemaFuzzingCheck()], timeout_s=3.0).run(url)
        findings = [f for f in result.findings if f.check_id == "SCHEMA_FUZZING"]
        assert len(findings) == 1
        assert "SCHEMA_FUZZING" in result.checks_run

    # -- evidence hygiene ----------------------------------------------
    def test_leak_evidence_is_bounded_length(self):
        with running_fuzzing_server("leak") as (url, _state):
            _result, finding = _run(url)
        assert finding is not None
        assert len(finding.snippet or "") < 2000
        assert len(finding.description) < 3000


class TestSchemaFuzzingStdio:
    def test_crash_over_stdio_modern_is_flagged(self):
        result, finding = _run_session(_stdio_session("modern", "vulnerable"))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.severity.value == "high"

    def test_crash_over_stdio_legacy_is_flagged(self):
        result, finding = _run_session(_stdio_session("legacy", "vulnerable"))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None

    def test_clean_over_stdio_is_not_flagged(self):
        result, finding = _run_session(_stdio_session("modern", "clean"))
        assert result.outcome != BoundaryOutcome.NOT_ENFORCED
        assert finding is None
