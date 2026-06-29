"""Tests for the AUTH_BOUNDARY dynamic check (Tier 2).

Constitution-aligned:
- Principle VI: paired vulnerable + clean fixture servers, both asserted.
- Principle III: a crash/timeout/unreachable target is INCONCLUSIVE, never a
  silent "secure" pass.
"""
from __future__ import annotations

from mcpfrisk.core.dynamic_runner import DynamicRunner
from mcpfrisk.core.models import BoundaryOutcome

from tests.fixtures.auth_servers import running_auth_server


def _run(target: str, timeout_s: float = 2.0):
    return DynamicRunner(timeout_s=timeout_s).run(target)


class TestAuthBoundary:
    def test_vulnerable_server_is_flagged(self):
        with running_auth_server("vulnerable") as url:
            result = _run(url)
        findings = [f for f in result.findings if f.check_id == "AUTH_BOUNDARY"]
        assert len(findings) == 1
        assert findings[0].severity.value == "high"

    def test_clean_server_is_not_flagged(self):
        with running_auth_server("clean") as url:
            result = _run(url)
        assert [f for f in result.findings if f.check_id == "AUTH_BOUNDARY"] == []
        assert "AUTH_BOUNDARY" in result.checks_run
        assert result.boundary_results[0].outcome == BoundaryOutcome.ENFORCED

    def test_invalid_credentials_are_flagged(self):
        # Server accepts ANY non-empty token (presence check, no validation).
        with running_auth_server("accepts_any_token") as url:
            result = _run(url)
        findings = [f for f in result.findings if f.check_id == "AUTH_BOUNDARY"]
        assert len(findings) == 1

    def test_unreachable_server_is_inconclusive(self):
        # Port 1 is not listening -> connection refused.
        result = _run("http://127.0.0.1:1/mcp", timeout_s=1.0)
        assert result.findings == []
        assert "AUTH_BOUNDARY" in result.checks_inconclusive
        assert result.boundary_results[0].outcome == BoundaryOutcome.INCONCLUSIVE

    def test_timeout_is_inconclusive(self):
        with running_auth_server("vulnerable", slow_seconds=1.5) as url:
            result = _run(url, timeout_s=0.3)
        assert result.findings == []
        assert result.boundary_results[0].outcome == BoundaryOutcome.INCONCLUSIVE

    def test_stdio_target_is_not_applicable(self):
        # stdio transport has no transport-level auth boundary to probe.
        result = _run("stdio:///usr/bin/my-mcp-server")
        assert result.findings == []
        assert "AUTH_BOUNDARY" in result.checks_inconclusive
