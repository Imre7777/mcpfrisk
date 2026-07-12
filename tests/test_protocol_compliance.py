"""Tests für den PROTOCOL_COMPLIANCE-Check (Feature 017).

Constitution-aligned:
- Prinzip I/VI: VOR der Implementierung geschrieben (rot) -- weder der Check noch
  die Port-Methode `call_response` existieren beim Schreiben.
- Prinzip V: ein Finding entsteht NUR bei konkreter JSON-RPC-2.0-Abweichung, mit
  Antwort-Ausschnitt als Beleg.
- Prinzip III: nicht erreichbar -> INCONCLUSIVE, nie ein stiller Pass.
- Read-only: der Check ruft kein Tool -> `state["mutations"] == 0`.
- SC-003: läuft nachweislich über HTTP UND stdio.
"""
from __future__ import annotations

import sys
from pathlib import Path

from mcpfrisk.checks.protocol_compliance import ProtocolComplianceCheck
from mcpfrisk.core.dynamic_runner import DynamicRunner, DynamicSession
from mcpfrisk.core.models import BoundaryOutcome, ProtocolProbeClass
from mcpfrisk.core.stdio_transport import StdioTransport

from tests.fixtures.protocol_servers import running_protocol_server

_FIXTURE = Path(__file__).parent / "fixtures" / "stdio_server.py"


def _run(target: str, timeout_s: float = 3.0):
    check = ProtocolComplianceCheck()
    session = DynamicSession(target, timeout_s=timeout_s)
    try:
        result = check.run_against_server(session)
    finally:
        session.close()
    return result, check.to_finding(result)


def _stdio_session(era: str, mode: str, *, timeout_s: float = 5.0) -> DynamicSession:
    argv = [sys.executable, str(_FIXTURE), "--era", era, "--mode", mode, "--toolset", "protocol"]
    return DynamicSession("stdio-fixture", timeout_s=timeout_s, transport=StdioTransport(argv, timeout_s))


def _run_session(session: DynamicSession):
    check = ProtocolComplianceCheck()
    try:
        result = check.run_against_server(session)
    finally:
        session.close()
    return result, check.to_finding(result)


# --------------------------------------------------------------------------
# Port-Erweiterung: call_response liefert das volle Payload inkl. error
# --------------------------------------------------------------------------


class TestCallResponsePort:
    def test_call_response_exposes_error_object(self):
        with running_protocol_server("compliant") as (url, _state):
            session = DynamicSession(url, timeout_s=3.0)
            try:
                payload = session.call_response("mcpfrisk/probe_x", {})
            finally:
                session.close()
        assert payload.get("error", {}).get("code") == -32601

    def test_call_still_returns_only_result(self):
        # Regression: call() unverändert -- extrahiert weiterhin nur result.
        with running_protocol_server("fail_open") as (url, _state):
            session = DynamicSession(url, timeout_s=3.0)
            try:
                result = session.call("mcpfrisk/probe_x", {})
            finally:
                session.close()
        assert result == {}


# --------------------------------------------------------------------------
# US1 — fail-open vs. compliant (HTTP)
# --------------------------------------------------------------------------


class TestHttp:
    def test_fail_open_is_flagged_medium(self):
        with running_protocol_server("fail_open") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.check_id == "PROTOCOL_COMPLIANCE"
        assert finding.severity.value == "medium"
        assert finding.cwe_ref == "CWE-703"
        assert finding.owasp_mcp_ref is None
        assert mutations == 0
        probe = result.failing_probe()
        assert probe.probe_class == ProtocolProbeClass.MISSING_ERROR

    def test_compliant_is_not_flagged(self):
        with running_protocol_server("compliant") as (url, _state):
            result, finding = _run(url)
        assert result.outcome == BoundaryOutcome.ENFORCED
        assert finding is None

    def test_compliant_over_http400_is_not_flagged(self):
        # Ein JSON-RPC-Fehler darf auf HTTP 400 transportiert werden -> ENFORCED.
        with running_protocol_server("compliant_http400") as (url, _state):
            result, finding = _run(url)
        assert result.outcome == BoundaryOutcome.ENFORCED
        assert finding is None

    def test_wrong_code_is_low(self):
        with running_protocol_server("wrong_code") as (url, _state):
            result, finding = _run(url)
        assert finding is not None
        assert finding.severity.value == "low"
        assert result.failing_probe().probe_class == ProtocolProbeClass.WRONG_ERROR_CODE

    def test_malformed_error_is_low(self):
        with running_protocol_server("malformed_error") as (url, _state):
            result, finding = _run(url)
        assert finding is not None
        assert finding.severity.value == "low"
        assert result.failing_probe().probe_class == ProtocolProbeClass.MALFORMED_ERROR

    def test_malformed_envelope_is_low(self):
        with running_protocol_server("malformed_envelope") as (url, _state):
            result, finding = _run(url)
        assert finding is not None
        assert finding.severity.value == "low"
        assert result.failing_probe().probe_class == ProtocolProbeClass.MALFORMED_ENVELOPE

    def test_unreachable_is_inconclusive(self):
        result, finding = _run("http://127.0.0.1:1/mcp", timeout_s=1.0)
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None

    def test_runner_integration_reports_finding(self):
        with running_protocol_server("fail_open") as (url, _state):
            result = DynamicRunner(checks=[ProtocolComplianceCheck()], timeout_s=3.0).run(url)
        findings = [f for f in result.findings if f.check_id == "PROTOCOL_COMPLIANCE"]
        assert len(findings) == 1
        assert "PROTOCOL_COMPLIANCE" in result.checks_run

    def test_evidence_is_bounded_length(self):
        with running_protocol_server("fail_open") as (url, _state):
            _result, finding = _run(url)
        assert finding is not None
        assert len(finding.snippet or "") < 2000
        assert len(finding.description) < 3000


# --------------------------------------------------------------------------
# US3 — stdio parity
# --------------------------------------------------------------------------


class TestStdio:
    def test_fail_open_over_stdio_modern_is_flagged(self):
        result, finding = _run_session(_stdio_session("modern", "fail_open"))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.severity.value == "medium"

    def test_fail_open_over_stdio_legacy_is_flagged(self):
        result, finding = _run_session(_stdio_session("legacy", "fail_open"))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None

    def test_compliant_over_stdio_is_not_flagged(self):
        result, finding = _run_session(_stdio_session("modern", "compliant"))
        assert result.outcome == BoundaryOutcome.ENFORCED
        assert finding is None
