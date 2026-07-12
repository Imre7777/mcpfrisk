"""Tests für den PACKAGE_PROVENANCE-Check (Feature 021).

Constitution-aligned:
- Prinzip I: VOR der Implementierung geschrieben (rot).
- Prinzip IV: getestet OHNE installiertes npm (Fake-Runner injiziert).
- Prinzip V: Finding kommt aus dem Tool-Report (Paket+Version+Status).
- Prinzip III: npm/Lockfile fehlt → skipped; Tool-Fehler/malformt → INFO;
  fehlende Provenance-Attestation → NIE ein Finding.
"""
from __future__ import annotations

import json
from pathlib import Path

from mcpfrisk.checks.package_provenance import PackageProvenanceCheck
from mcpfrisk.core.models import Severity


class FakeRunner:
    def __init__(self, stdout: str = "", ok: bool = True, available: bool = True) -> None:
        self._stdout = stdout
        self._ok = ok
        self._available = available

    def available(self) -> bool:
        return self._available

    def scan(self, target: Path) -> tuple[str, bool]:
        return self._stdout, self._ok


def _report(invalid=None, missing=None) -> str:
    return json.dumps({"invalid": invalid or [], "missing": missing or []})


def _lockfile(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}', encoding="utf-8")


class TestInvalidSignature:
    def test_invalid_is_high(self, tmp_path):
        _lockfile(tmp_path)
        report = _report(invalid=[{"name": "foo", "version": "1.0.0", "code": "EINTEGRITYSIGNATURE"}])
        check = PackageProvenanceCheck(runner=FakeRunner(stdout=report))
        findings = check.run(tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "PACKAGE_PROVENANCE"
        assert f.severity == Severity.HIGH
        assert f.cwe_ref == "CWE-347"
        assert f.owasp_mcp_ref == "MCP04"
        blob = f.title + f.description + (f.snippet or "")
        assert "foo" in blob and "1.0.0" in blob

    def test_clean_report_is_empty(self, tmp_path):
        _lockfile(tmp_path)
        check = PackageProvenanceCheck(runner=FakeRunner(stdout=_report()))
        assert check.run(tmp_path) == []


class TestMissingSignature:
    def test_missing_is_low(self, tmp_path):
        _lockfile(tmp_path)
        report = _report(missing=[{"name": "bar", "version": "2.0.0"}])
        findings = PackageProvenanceCheck(runner=FakeRunner(stdout=report)).run(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_invalid_and_missing_combined(self, tmp_path):
        _lockfile(tmp_path)
        report = _report(
            invalid=[{"name": "foo", "version": "1.0.0"}],
            missing=[{"name": "bar", "version": "2.0.0"}],
        )
        findings = PackageProvenanceCheck(runner=FakeRunner(stdout=report)).run(tmp_path)
        assert len(findings) == 2
        assert {f.severity for f in findings} == {Severity.HIGH, Severity.LOW}

    def test_duplicate_entries_are_deduped(self, tmp_path):
        _lockfile(tmp_path)
        report = _report(invalid=[
            {"name": "foo", "version": "1.0.0"},
            {"name": "foo", "version": "1.0.0"},
        ])
        findings = PackageProvenanceCheck(runner=FakeRunner(stdout=report)).run(tmp_path)
        assert len(findings) == 1


class TestDegradation:
    def test_npm_unavailable_does_not_apply(self, tmp_path):
        _lockfile(tmp_path)
        check = PackageProvenanceCheck(runner=FakeRunner(available=False))
        assert check.applies_to(tmp_path) is False

    def test_no_lockfile_does_not_apply(self, tmp_path):
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        check = PackageProvenanceCheck(runner=FakeRunner(available=True))
        assert check.applies_to(tmp_path) is False

    def test_lockfile_and_npm_apply(self, tmp_path):
        _lockfile(tmp_path)
        check = PackageProvenanceCheck(runner=FakeRunner(available=True))
        assert check.applies_to(tmp_path) is True

    def test_tool_error_yields_info(self, tmp_path):
        _lockfile(tmp_path)
        findings = PackageProvenanceCheck(runner=FakeRunner(stdout="", ok=False)).run(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_malformed_json_yields_info(self, tmp_path):
        _lockfile(tmp_path)
        findings = PackageProvenanceCheck(runner=FakeRunner(stdout="not json {")).run(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_run_never_raises(self, tmp_path):
        _lockfile(tmp_path)

        class BoomRunner:
            def available(self):
                return True
            def scan(self, target):
                raise RuntimeError("boom")

        findings = PackageProvenanceCheck(runner=BoomRunner()).run(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
