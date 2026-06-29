"""Tests for the SSRF_CHECK dynamic check (Tier 2).

Constitution-aligned:
- Principle VI: paired vulnerable + clean fixture servers (clean lands in US2).
- Principle III: the authoritative signal is an out-of-band callback hit, never
  the tool's return value; an undeliverable/unreachable target is INCONCLUSIVE.

US1 (this file, MVP): a server whose tool fetches a McpFrisk-controlled callback
URL is flagged, proven by a recorded callback hit.
"""
from __future__ import annotations

from mcpfrisk.checks.ssrf_check import SsrfCheck
from mcpfrisk.core.dynamic_runner import DynamicRunner

from tests.fixtures.ssrf_servers import running_ssrf_server


def _run_ssrf(target: str, timeout_s: float = 3.0):
    # Nur den SSRF-Check laufen lassen, um den Test von AUTH_BOUNDARY zu entkoppeln.
    return DynamicRunner(checks=[SsrfCheck()], timeout_s=timeout_s).run(target)


class TestSsrfCheck:
    def test_vulnerable_server_is_flagged(self):
        with running_ssrf_server("vulnerable") as url:
            result = _run_ssrf(url)
        findings = [f for f in result.findings if f.check_id == "SSRF_CHECK"]
        assert len(findings) == 1
        assert findings[0].severity.value == "high"
