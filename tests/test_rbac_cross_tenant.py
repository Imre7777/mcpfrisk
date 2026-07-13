"""Tests für den RBAC_CROSS_TENANT-Check (Feature 006).

Constitution-aligned:
- Prinzip VI: paired vulnerable + clean multi-tenant Fixture, beide asserted.
- Prinzip V: Finding nur bei nachgewiesenem A-privaten Marker in B's Antwort.
- Prinzip III: < 2 Identitäten / kein belegbarer Fingerprint -> INCONCLUSIVE.
- Read-only: der Check darf keine mutierende Operation auslösen.
"""
from __future__ import annotations

from mcpfrisk.checks.rbac_cross_tenant import RbacCrossTenantCheck
from mcpfrisk.core.dynamic_runner import DynamicRunner, DynamicSession, IdentityConfig
from mcpfrisk.core.models import BoundaryOutcome, RbacProbeClass
from tests.fixtures.rbac_servers import running_rbac_server

_TWO = {"A": "tok-a", "B": "tok-b"}


def _session(url: str, identities: dict[str, str] = _TWO) -> DynamicSession:
    return DynamicSession(url, timeout_s=3.0, identity_config=IdentityConfig(identities=dict(identities)))


def _run(url: str, identities: dict[str, str] = _TWO):
    check = RbacCrossTenantCheck()
    session = _session(url, identities)
    try:
        result = check.run_against_server(session)
    finally:
        session.close()
    return result, check.to_finding(result)


class TestRbacCrossTenant:
    def test_vulnerable_server_leaks_both_ways(self):
        with running_rbac_server("vulnerable") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome == BoundaryOutcome.NOT_ENFORCED
        assert finding is not None
        assert finding.check_id == "RBAC_CROSS_TENANT"
        assert finding.owasp_mcp_ref == "MCP07"
        classes = {p.probe_class for p in result.probes if p.outcome == BoundaryOutcome.NOT_ENFORCED}
        assert RbacProbeClass.IDOR_REPLAY in classes   # US1
        assert RbacProbeClass.TENANT_ARG in classes    # US2
        assert mutations == 0  # read-only garantiert

    def test_clean_server_is_not_flagged(self):
        with running_rbac_server("clean") as (url, state):
            result, finding = _run(url)
            mutations = state["mutations"]
        assert result.outcome != BoundaryOutcome.NOT_ENFORCED
        assert finding is None
        assert mutations == 0

    def test_single_identity_is_inconclusive(self):
        with running_rbac_server("vulnerable") as (url, _state):
            result, finding = _run(url, identities={"A": "tok-a"})
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None

    def test_no_identities_is_inconclusive(self):
        with running_rbac_server("vulnerable") as (url, _state):
            result, finding = _run(url, identities={})
        assert result.outcome == BoundaryOutcome.INCONCLUSIVE
        assert finding is None

    def test_runner_integration_reports_rbac_finding(self):
        cfg = IdentityConfig(identities=dict(_TWO))
        with running_rbac_server("vulnerable") as (url, _state):
            result = DynamicRunner(timeout_s=3.0, identity_config=cfg).run(url)
        rbac = [f for f in result.findings if f.check_id == "RBAC_CROSS_TENANT"]
        assert len(rbac) == 1
        assert "RBAC_CROSS_TENANT" in result.checks_run
