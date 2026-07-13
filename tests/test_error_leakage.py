"""Tests für den ERROR_LEAKAGE-Check (Feature 008).

Constitution-aligned:
- Prinzip I/VI: dieser Test wird VOR der Implementierung geschrieben (rot) --
  `mcpfrisk.checks.error_leakage` existiert zum Zeitpunkt des Schreibens noch
  nicht, der Import schlägt fehl, bis der Check gebaut ist.
- Prinzip V: ein Finding entsteht NUR bei konkret geleaktem Interna-Ausschnitt.
- Prinzip III: nichts auswertbar (Server unreachable) -> INCONCLUSIVE, nie ein
  stiller Pass.
- Read-only: der Check darf `delete_item` nie auslösen.
- Abgrenzung zu SCHEMA_FUZZING: kein ID-Tool -> US3 entfällt, US1/US2 laufen
  trotzdem weiter (SC-003).
- SC-002: läuft nachweislich über HTTP UND stdio.
"""
from __future__ import annotations

import sys
from pathlib import Path

from mcpfrisk.checks.error_leakage import ErrorLeakageCheck
from mcpfrisk.core.dynamic_runner import DynamicRunner, DynamicSession
from mcpfrisk.core.models import BoundaryOutcome, ErrorProbeClass
from mcpfrisk.core.stdio_transport import StdioTransport
from tests.fixtures.error_leakage_servers import running_error_leakage_server

_FIXTURE = Path(__file__).parent / "fixtures" / "stdio_server.py"


def _run(target: str, timeout_s: float = 3.0):
    check = ErrorLeakageCheck()
    session = DynamicSession(target, timeout_s=timeout_s)
    try:
        result = check.run_against_server(session)
    finally:
        session.close()
    return result, check.to_finding(result)


def _stdio_session(era: str, mode: str, *, timeout_s: float = 5.0) -> DynamicSession:
    argv = [sys.executable, str(_FIXTURE), "--era", era, "--mode", mode, "--toolset", "errors"]
    return DynamicSession("stdio-fixture", timeout_s=timeout_s, transport=StdioTransport(argv, timeout_s))


def _run_session(session: DynamicSession):
    check = ErrorLeakageCheck()
    try:
        result = check.run_against_server(session)
    finally:
        session.close()
    return result, check.to_finding(result)


class TestErrorLeakageHttp:
    # -- true positive: all three triggers leak -------------------------
    def test_vulnerable_is_flagged(self):
        with running_error_leakage_server("vulnerable") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.check_id == "ERROR_LEAKAGE"
        assert finding.severity.value == "medium"
        assert finding.cwe_ref == "CWE-209"
        assert mutations == 0
        classes = {p.probe_class for p in result.probes if p.outcome == BoundaryOutcome.NOT_ENFORCED}
        assert ErrorProbeClass.UNKNOWN_TOOL in classes
        assert ErrorProbeClass.UNKNOWN_METHOD in classes
        assert ErrorProbeClass.NONEXISTENT_RESOURCE in classes

    # -- clean server: no false positive ---------------------------------
    def test_clean_server_is_not_flagged(self):
        with running_error_leakage_server("clean") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome != BoundaryOutcome.NOT_ENFORCED
        assert finding is None
        assert mutations == 0

    # -- SC-003: missing ID tool doesn't break US1/US2 --------------------
    def test_no_id_tool_us3_is_skipped_but_us1_us2_still_run(self):
        with running_error_leakage_server("no_tools") as (url, _state):
            result, finding = _run(url)
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED  # US1/US2 still leak
        assert finding is not None
        classes = {p.probe_class for p in result.probes}
        assert ErrorProbeClass.NONEXISTENT_RESOURCE not in classes
        assert ErrorProbeClass.UNKNOWN_TOOL in classes
        assert ErrorProbeClass.UNKNOWN_METHOD in classes

    # -- degradation, never a silent pass ---------------------------------
    def test_unreachable_server_is_inconclusive(self):
        result, finding = _run("http://127.0.0.1:1/mcp", timeout_s=1.0)
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None

    # -- runner integration ------------------------------------------------
    def test_runner_integration_reports_finding(self):
        with running_error_leakage_server("vulnerable") as (url, _state):
            result = DynamicRunner(checks=[ErrorLeakageCheck()], timeout_s=3.0).run(url)
        findings = [f for f in result.findings if f.check_id == "ERROR_LEAKAGE"]
        assert len(findings) == 1
        assert "ERROR_LEAKAGE" in result.checks_run

    # -- evidence hygiene ----------------------------------------------
    def test_leak_evidence_is_bounded_length(self):
        with running_error_leakage_server("vulnerable") as (url, _state):
            _result, finding = _run(url)
        assert finding is not None
        assert len(finding.snippet or "") < 2000
        assert len(finding.description) < 3000


class TestErrorLeakageStdio:
    def test_vulnerable_over_stdio_modern_is_flagged(self):
        result, finding = _run_session(_stdio_session("modern", "vulnerable"))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.severity.value == "medium"

    def test_vulnerable_over_stdio_legacy_is_flagged(self):
        result, finding = _run_session(_stdio_session("legacy", "vulnerable"))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None

    def test_clean_over_stdio_is_not_flagged(self):
        result, finding = _run_session(_stdio_session("modern", "clean"))
        assert result.outcome != BoundaryOutcome.NOT_ENFORCED
        assert finding is None
