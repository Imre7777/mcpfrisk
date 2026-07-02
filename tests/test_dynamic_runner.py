"""Tests für die Robustheit von DynamicRunner selbst (Post-Audit-Hardening).

Constitution Prinzip III/V: ein Check darf NIE werfen; tut er es trotzdem
(z.B. weil ein bösartiger/kaputter Zielserver eine unerwartete Exception tief
im Check auslöst -- etwa RecursionError bei extrem verschachteltem JSON),
MUSS der Runner das für genau diesen Check in INCONCLUSIVE übersetzen und mit
den übrigen Checks weiterlaufen -- niemals den gesamten Scan abstürzen lassen.
"""
from __future__ import annotations

from mcpfrisk.core.base_check import BaseDynamicCheck
from mcpfrisk.core.dynamic_runner import DynamicRunner, DynamicSession
from mcpfrisk.core.models import (
    AuthProbe,
    BoundaryOutcome,
    BoundaryResult,
    CredentialCondition,
    Severity,
)


class _ExplodingCheck(BaseDynamicCheck):
    check_id = "EXPLODING_CHECK"
    name = "Deliberately Broken Check"
    severity = Severity.HIGH

    def run_against_server(self, session: DynamicSession) -> BoundaryResult:
        # Simuliert z.B. einen RecursionError bei extrem verschachteltem JSON
        # in einer Server-Antwort -- ein Fehler, den der Check NICHT selbst
        # abfängt (Prinzip: der Runner ist das Sicherheitsnetz, nicht jeder
        # einzelne Check muss jede denkbare Exception selbst behandeln).
        raise RecursionError("simulated: deeply nested response blew the stack")


class _WellBehavedCheck(BaseDynamicCheck):
    check_id = "WELL_BEHAVED_CHECK"
    name = "Well-Behaved Check"
    severity = Severity.HIGH

    def run_against_server(self, session: DynamicSession) -> BoundaryResult:
        return BoundaryResult(
            target=session.target,
            check_id=self.check_id,
            probes=[AuthProbe("noop", CredentialCondition.NONE, BoundaryOutcome.ENFORCED, "ok")],
        )


def test_a_check_that_raises_degrades_to_inconclusive_not_a_crash():
    runner = DynamicRunner(checks=[_ExplodingCheck(), _WellBehavedCheck()], timeout_s=1.0)
    # Ziel muss nicht erreichbar sein -- keiner der beiden Checks nutzt die
    # Session tatsächlich; es geht nur darum, dass runner.run() selbst nicht
    # an der geworfenen Exception zerbricht.
    result = runner.run("http://127.0.0.1:1/mcp")

    assert "EXPLODING_CHECK" in result.checks_inconclusive
    assert "WELL_BEHAVED_CHECK" in result.checks_run
    assert result.findings == []

    exploding = next(b for b in result.boundary_results if b.check_id == "EXPLODING_CHECK")
    assert exploding.outcome == BoundaryOutcome.INCONCLUSIVE
    assert "RecursionError" in exploding.probes[0].observed
