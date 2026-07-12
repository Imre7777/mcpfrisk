"""Tests für den DEPENDENCY_SCAN-Check (Feature 019).

Constitution-aligned:
- Prinzip I: VOR der Implementierung geschrieben (rot) -- der Check existiert noch
  nicht beim Schreiben.
- Prinzip IV: getestet OHNE installiertes osv-scanner (Fake-Runner injiziert).
- Prinzip V: Finding kommt aus dem Report (Paket+Version+CVE/OSV-ID+Fix).
- Prinzip III: Tool fehlt → skipped; Tool-Fehler/malformt → INFO, nie Crash, nie
  stiller Pass.
"""
from __future__ import annotations

import json
from pathlib import Path

from mcpfrisk.checks.dependency_scan import DependencyScanCheck, cvss_to_severity
from mcpfrisk.core.models import Severity


class FakeRunner:
    """Injizierter Tool-Runner: liefert Canned-Output, kein echtes osv-scanner."""

    def __init__(self, stdout: str = "", ok: bool = True, available: bool = True) -> None:
        self._stdout = stdout
        self._ok = ok
        self._available = available
        self.calls = 0

    def available(self) -> bool:
        return self._available

    def scan(self, target: Path) -> tuple[str, bool]:
        self.calls += 1
        return self._stdout, self._ok


def _report(*packages: dict) -> str:
    return json.dumps({"results": [{"source": {"path": "/x/requirements.txt",
                                                "type": "lockfile"},
                                     "packages": list(packages)}]})


def _vuln_package(name: str, version: str, vuln_id: str, cve: str, score: str, fixed: str) -> dict:
    return {
        "package": {"name": name, "version": version, "ecosystem": "PyPI"},
        "vulnerabilities": [{
            "id": vuln_id,
            "aliases": [cve],
            "summary": f"{name} before {fixed} has a known vulnerability.",
            "references": [{"type": "ADVISORY", "url": f"https://osv.dev/vulnerability/{vuln_id}"}],
            "affected": [{"ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": fixed}]}]}],
        }],
        "groups": [{"ids": [vuln_id, cve], "max_severity": score}],
    }


def _write_manifest(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")


# --------------------------------------------------------------------------
# Severity-Ableitung
# --------------------------------------------------------------------------


class TestCvssMapping:
    def test_critical(self):
        assert cvss_to_severity(9.8) == Severity.CRITICAL

    def test_high(self):
        assert cvss_to_severity(7.5) == Severity.HIGH

    def test_medium(self):
        assert cvss_to_severity(5.0) == Severity.MEDIUM

    def test_low(self):
        assert cvss_to_severity(2.0) == Severity.LOW

    def test_unknown_defaults_medium(self):
        assert cvss_to_severity(None) == Severity.MEDIUM


# --------------------------------------------------------------------------
# US1 — Vuln gemeldet / clean
# --------------------------------------------------------------------------


class TestTranslate:
    def test_vulnerable_dependency_is_flagged(self, tmp_path):
        _write_manifest(tmp_path)
        report = _report(_vuln_package("requests", "2.19.0", "GHSA-x", "CVE-2018-18074", "9.8", "2.20.0"))
        check = DependencyScanCheck(runner=FakeRunner(stdout=report))
        findings = check.run(tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "DEPENDENCY_SCAN"
        assert f.severity == Severity.CRITICAL
        assert f.owasp_mcp_ref == "MCP04"
        blob = f.title + f.description + (f.snippet or "") + (f.remediation or "")
        assert "requests" in blob
        assert "2.19.0" in blob
        assert "CVE-2018-18074" in blob
        assert "2.20.0" in blob  # fix version

    def test_no_vulnerabilities_is_clean(self, tmp_path):
        _write_manifest(tmp_path)
        check = DependencyScanCheck(runner=FakeRunner(stdout='{"results": []}'))
        assert check.run(tmp_path) == []

    def test_multiple_packages_each_flagged(self, tmp_path):
        _write_manifest(tmp_path)
        report = _report(
            _vuln_package("requests", "2.19.0", "GHSA-a", "CVE-1", "9.8", "2.20.0"),
            _vuln_package("flask", "0.12.0", "GHSA-b", "CVE-2", "7.5", "0.12.3"),
        )
        findings = DependencyScanCheck(runner=FakeRunner(stdout=report)).run(tmp_path)
        assert len(findings) == 2
        assert {f.severity for f in findings} == {Severity.CRITICAL, Severity.HIGH}

    def test_same_vuln_across_lockfiles_is_deduped(self, tmp_path):
        _write_manifest(tmp_path)
        pkg = _vuln_package("requests", "2.19.0", "GHSA-a", "CVE-1", "9.8", "2.20.0")
        data = {"results": [
            {"source": {"path": "/a/requirements.txt"}, "packages": [pkg]},
            {"source": {"path": "/b/requirements.txt"}, "packages": [pkg]},
        ]}
        findings = DependencyScanCheck(runner=FakeRunner(stdout=json.dumps(data))).run(tmp_path)
        assert len(findings) == 1


# --------------------------------------------------------------------------
# US3 — Degradation
# --------------------------------------------------------------------------


class TestDegradation:
    def test_tool_unavailable_does_not_apply(self, tmp_path):
        _write_manifest(tmp_path)
        check = DependencyScanCheck(runner=FakeRunner(available=False))
        assert check.applies_to(tmp_path) is False

    def test_no_manifest_does_not_apply(self, tmp_path):
        (tmp_path / "server.py").write_text("print(1)\n", encoding="utf-8")
        check = DependencyScanCheck(runner=FakeRunner(available=True))
        assert check.applies_to(tmp_path) is False

    def test_manifest_and_tool_present_applies(self, tmp_path):
        _write_manifest(tmp_path)
        check = DependencyScanCheck(runner=FakeRunner(available=True))
        assert check.applies_to(tmp_path) is True

    def test_tool_error_yields_info_not_crash(self, tmp_path):
        _write_manifest(tmp_path)
        check = DependencyScanCheck(runner=FakeRunner(stdout="", ok=False))
        findings = check.run(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        # kein Vuln-Finding, kein stiller Clean
        assert findings[0].check_id == "DEPENDENCY_SCAN"

    def test_malformed_json_yields_info(self, tmp_path):
        _write_manifest(tmp_path)
        check = DependencyScanCheck(runner=FakeRunner(stdout="not json {", ok=True))
        findings = check.run(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_run_never_raises(self, tmp_path):
        _write_manifest(tmp_path)
        # Ein Runner, der wirft, darf run() nicht crashen lassen.
        class BoomRunner:
            def available(self):
                return True
            def scan(self, target):
                raise RuntimeError("boom")
        findings = DependencyScanCheck(runner=BoomRunner()).run(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
