"""Tests for the SSRF_CHECK dynamic check (Tier 2).

Constitution-aligned:
- Principle VI: paired vulnerable + clean fixture servers (clean lands in US2).
- Principle III: the authoritative signal is an out-of-band callback hit, never
  the tool's return value; an undeliverable/unreachable target is INCONCLUSIVE.

US1 (this file, MVP): a server whose tool fetches a McpFrisk-controlled callback
URL is flagged, proven by a recorded callback hit.
"""
from __future__ import annotations

import time

from mcpfrisk.checks._ssrf_callback import CallbackListener
from mcpfrisk.checks.ssrf_check import SsrfCheck
from mcpfrisk.core.dynamic_runner import DynamicRunner, DynamicSession
from mcpfrisk.core.models import BoundaryOutcome
from tests.fixtures.ssrf_servers import running_ssrf_server


def _run_ssrf(target: str, timeout_s: float = 3.0):
    # Nur den SSRF-Check laufen lassen, um den Test von AUTH_BOUNDARY zu entkoppeln.
    return DynamicRunner(checks=[SsrfCheck()], timeout_s=timeout_s).run(target)


class TestSsrfCheck:
    # -- US1: detection (true positive) --------------------------------
    def test_vulnerable_server_is_flagged(self):
        with running_ssrf_server("vulnerable") as url:
            result = _run_ssrf(url)
        findings = [f for f in result.findings if f.check_id == "SSRF_CHECK"]
        assert len(findings) == 1
        assert findings[0].severity.value == "high"

    # -- US2: clean server passes cleanly (no false positive) ----------
    def test_clean_server_is_not_flagged(self):
        with running_ssrf_server("clean") as url:
            result = _run_ssrf(url)
        assert [f for f in result.findings if f.check_id == "SSRF_CHECK"] == []
        assert "SSRF_CHECK" in result.checks_run
        assert result.boundary_results[0].outcome == BoundaryOutcome.ENFORCED

    # -- US3: redirect-based bypass is still caught --------------------
    def test_redirect_bypass_is_flagged(self):
        # Der Server blockt das direkte Callback-Ziel, folgt aber Redirects
        # ungeprüft -> die REDIRECT-Probe muss greifen, die CALLBACK-Probe nicht.
        with running_ssrf_server("redirect") as url:
            result = _run_ssrf(url)
        findings = [f for f in result.findings if f.check_id == "SSRF_CHECK"]
        assert len(findings) == 1
        probes = result.boundary_results[0].probes
        classes = {p.probe_class.value for p in probes if p.outcome == BoundaryOutcome.NOT_ENFORCED}
        assert "redirect" in classes
        assert "callback" not in classes  # direktes Ziel war geblockt

    # -- Polish: inconclusive, never a silent pass ---------------------
    def test_no_url_tool_is_inconclusive(self):
        with running_ssrf_server("no_url_tool") as url:
            result = _run_ssrf(url)
        assert result.findings == []
        assert "SSRF_CHECK" in result.checks_inconclusive
        assert result.boundary_results[0].outcome == BoundaryOutcome.INCONCLUSIVE

    def test_unreachable_server_is_inconclusive(self):
        result = _run_ssrf("http://127.0.0.1:1/mcp", timeout_s=1.0)
        assert result.findings == []
        assert "SSRF_CHECK" in result.checks_inconclusive
        assert result.boundary_results[0].outcome == BoundaryOutcome.INCONCLUSIVE

    def test_evaluation_is_time_bounded(self):
        # Server, der die Calls beantwortet aber nie fetcht (clean) -> der Lauf
        # muss klar innerhalb einer kleinen Schranke fertig sein (kein Hängen).
        with running_ssrf_server("clean") as url:
            start = time.monotonic()
            _run_ssrf(url, timeout_s=1.0)
            elapsed = time.monotonic() - start
        assert elapsed < 8.0

    # -- Safety: only loopback + the metadata IP are ever targeted -----
    def test_probes_target_only_local_and_metadata(self, monkeypatch):
        sent_urls: list[str] = []
        original = DynamicSession.call

        def _spy(self, method, params=None, timeout_s=None):
            if method == "tools/call":
                args = (params or {}).get("arguments") or {}
                sent_urls.extend(v for v in args.values() if isinstance(v, str))
            return original(self, method, params, timeout_s)

        monkeypatch.setattr(DynamicSession, "call", _spy)
        with running_ssrf_server("vulnerable") as url:
            _run_ssrf(url)

        from urllib.parse import urlparse
        allowed_hosts = {"127.0.0.1", "localhost", "169.254.169.254"}
        for u in sent_urls:
            host = urlparse(u).hostname
            assert host in allowed_hosts, f"unexpected probe target host: {host} ({u})"

    # -- Evidence redaction --------------------------------------------
    def test_finding_evidence_does_not_leak_full_token(self):
        with running_ssrf_server("vulnerable") as url:
            result = _run_ssrf(url)
        finding = next(f for f in result.findings if f.check_id == "SSRF_CHECK")
        # Nur ein kurzes Token-Suffix (…8 Zeichen) darf erscheinen, nie ein
        # 32-stelliges hex-Token in voller Länge.
        import re
        assert not re.search(r"[0-9a-f]{32}", (finding.snippet or "") + finding.description)


def test_callback_listener_records_hit():
    import urllib.request
    with CallbackListener() as listener:
        token, url = listener.new_probe_url()
        urllib.request.urlopen(url, timeout=2).read()
        hit = listener.received(token, timeout_s=2.0)
    assert hit is not None
    assert hit.token == token
