"""Tests für den stdio-Transport (Feature 005).

Constitution-aligned:
- Prinzip VI: paired vulnerable + clean Fixture-Server, je in Legacy- UND
  Modern-Protokoll-Ära.
- Prinzip III: nicht startbarer/silent Server -> INCONCLUSIVE, nie stilles "sicher".
- Lifecycle: ein gestarteter Subprozess wird zuverlässig beendet (kein Waise).
"""
from __future__ import annotations

import sys
from pathlib import Path

from mcpfrisk.checks.ssrf_check import SsrfCheck
from mcpfrisk.core.dynamic_runner import DynamicRunner, DynamicSession
from mcpfrisk.core.models import BoundaryOutcome, CredentialCondition
from mcpfrisk.core.stdio_transport import StdioTransport

_FIXTURE = Path(__file__).parent / "fixtures" / "stdio_server.py"


def _stdio_session(era: str, mode: str, *, banner: bool = False, timeout_s: float = 5.0) -> DynamicSession:
    argv = [sys.executable, str(_FIXTURE), "--era", era, "--mode", mode]
    if banner:
        argv.append("--banner")
    return DynamicSession("stdio-fixture", timeout_s=timeout_s, transport=StdioTransport(argv, timeout_s))


def _run_ssrf(session: DynamicSession):
    check = SsrfCheck()
    try:
        result = check.run_against_server(session)
    finally:
        session.close()
    return result, check.to_finding(result)


# ---------------------------------------------------------------------------
# US1 / US2 — SSRF über stdio, beide Protokoll-Ären
# ---------------------------------------------------------------------------
class TestSsrfOverStdio:
    def test_vulnerable_modern_is_flagged(self):
        result, finding = _run_ssrf(_stdio_session("modern", "vulnerable"))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.check_id == "SSRF_CHECK"

    def test_vulnerable_legacy_is_flagged(self):
        result, finding = _run_ssrf(_stdio_session("legacy", "vulnerable"))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None

    def test_clean_modern_is_not_flagged(self):
        result, finding = _run_ssrf(_stdio_session("modern", "clean"))
        assert result.outcome != BoundaryOutcome.NOT_ENFORCED
        assert finding is None

    def test_clean_legacy_is_not_flagged(self):
        result, finding = _run_ssrf(_stdio_session("legacy", "clean"))
        assert result.outcome != BoundaryOutcome.NOT_ENFORCED
        assert finding is None

    def test_stdout_banner_is_ignored(self):
        # Eine Nicht-JSON-Bannerzeile auf stdout darf den Client nicht stören.
        result, finding = _run_ssrf(_stdio_session("modern", "vulnerable", banner=True))
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None


# ---------------------------------------------------------------------------
# Prinzip III — Fehler/Timeout sind INCONCLUSIVE
# ---------------------------------------------------------------------------
class TestStdioInconclusive:
    def test_unstartable_command_is_inconclusive(self):
        session = DynamicSession(
            "stdio-fixture", timeout_s=2.0,
            transport=StdioTransport(["__mcpfrisk_no_such_cmd__"], 2.0),
        )
        result, finding = _run_ssrf(session)
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None

    def test_silent_server_times_out_and_process_is_terminated(self):
        session = _stdio_session("modern", "silent", timeout_s=0.5)
        transport = session._transport
        result, finding = _run_ssrf(session)
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None
        # Lifecycle: nach close() läuft kein Subprozess mehr (Kanäle geleert).
        assert transport._channels == {}


# ---------------------------------------------------------------------------
# AUTH_BOUNDARY auf stdio: kein Transport-Auth-Boundary -> INCONCLUSIVE
# ---------------------------------------------------------------------------
class TestAuthBoundaryOverStdio:
    def test_probe_is_inconclusive_without_spawning(self):
        transport = StdioTransport([sys.executable, str(_FIXTURE)], 2.0)
        probe = transport.probe("tools/list", CredentialCondition.NONE)
        assert probe.outcome == BoundaryOutcome.INCONCLUSIVE
        # probe() darf den Server nicht starten (Auth-Boundary ist HTTP-Sache) --
        # es wird kein Kanal/Subprozess angelegt.
        assert transport._channels == {}
        transport.close()

    def test_runner_stdio_target_auth_boundary_inconclusive(self):
        result = DynamicRunner(timeout_s=2.0).run("stdio:__mcpfrisk_no_such_cmd__")
        assert result.findings == []
        assert "AUTH_BOUNDARY" in result.checks_inconclusive


# ---------------------------------------------------------------------------
# Post-Audit-Hardening: Era-Negotiation-Robustheit (Bugs 2 + 3)
# ---------------------------------------------------------------------------
class TestEraNegotiationRobustness:
    def test_legacy_fallback_spawns_fresh_process_after_modern_probe_crash(self):
        """Regressionstest (Bug 2): stirbt der Prozess bei der modern-Probe
        (server/discover) -- z.B. weil ein naiver Server auf eine unbekannte
        Methode nicht mit einem JSON-RPC-Fehler antwortet, sondern crasht --
        MUSS der legacy-Fallback (initialize) einen FRISCHEN Prozess starten.
        Vorher wurde der tote Handle wiederverwendet, wodurch die gesamte
        Session dauerhaft INCONCLUSIVE blieb, ohne dass initialize je eine
        echte Chance bekam."""
        session = _stdio_session("crash-on-discover", "vulnerable", timeout_s=3.0)
        try:
            result = session.call("tools/list")
        finally:
            session.close()
        assert "tools" in result

    def test_rejected_initialize_does_not_send_initialized_notification(self, monkeypatch):
        """Regressionstest (Bug 3): lehnt der Server initialize explizit ab
        (JSON-RPC-Fehler), darf notifications/initialized NICHT trotzdem
        gesendet werden -- vorher wurde die initialize-Antwort nie auf
        'error' geprüft, die Session galt fälschlich als verhandelt."""
        from mcpfrisk.core.stdio_transport import StdioServerHandle

        notified: list[str] = []
        original_notify = StdioServerHandle.notify

        def spy_notify(self, method, params=None):
            notified.append(method)
            return original_notify(self, method, params)

        monkeypatch.setattr(StdioServerHandle, "notify", spy_notify)

        session = _stdio_session("reject-initialize", "vulnerable", timeout_s=2.0)
        try:
            try:
                session.call("tools/list", timeout_s=1.0)
            except Exception:
                pass  # erwartet: der Server ist nie sauber initialisiert
        finally:
            session.close()
        assert "notifications/initialized" not in notified
