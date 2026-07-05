"""Tests für den SARIF-Output (Feature 010, GitHub Code Scanning).

Constitution-aligned: reine Serialisierung, keine neue Erkennungslogik. Muss
für "Findings vorhanden" UND "keine Findings" sauber funktionieren, und darf
bei fehlender Datei/Zeile (Tier-2-Findings) nicht crashen -- auch wenn SARIF
laut Design nur für `scan` (Tier 1) angeboten wird, bleibt der Writer selbst
defensiv.
"""
from __future__ import annotations

import json
from pathlib import Path

from mcpfrisk.core.models import Finding, ScanResult, Severity
from mcpfrisk.core.sarif import write_sarif_report


def _finding(**overrides) -> Finding:
    defaults = dict(
        check_id="CMD_INJECTION",
        severity=Severity.CRITICAL,
        title="Potenzielle Command Injection via subprocess.run()",
        description="Ein interpolierter Befehl wurde gefunden.",
        file_path=Path("/repo/server.py"),
        line_number=42,
        snippet="subprocess.run(cmd, shell=True)",
        owasp_mcp_ref="MCP05",
        cwe_ref="CWE-78",
        remediation="Nutze eine Argument-Liste statt String-Interpolation.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _write_and_load(tmp_path: Path, findings: list[Finding], target_path: Path | None = None) -> dict:
    result = ScanResult(target_path=target_path or Path("/repo"), findings=findings)
    out = tmp_path / "results.sarif"
    write_sarif_report(result, out)
    return json.loads(out.read_text(encoding="utf-8"))


class TestSarifStructure:
    def test_has_expected_top_level_schema(self, tmp_path):
        data = _write_and_load(tmp_path, [_finding()])
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "mcpfrisk"

    def test_empty_findings_produces_valid_empty_results(self, tmp_path):
        data = _write_and_load(tmp_path, [])
        assert data["runs"][0]["results"] == []

    def test_one_result_per_finding(self, tmp_path):
        findings = [_finding(), _finding(check_id="PATH_TRAVERSAL", line_number=10)]
        data = _write_and_load(tmp_path, findings)
        assert len(data["runs"][0]["results"]) == 2

    def test_rule_id_matches_check_id(self, tmp_path):
        data = _write_and_load(tmp_path, [_finding(check_id="HARDCODED_SECRETS")])
        result = data["runs"][0]["results"][0]
        assert result["ruleId"] == "HARDCODED_SECRETS"

    def test_physical_location_uses_relative_path_and_line(self, tmp_path):
        data = _write_and_load(
            tmp_path, [_finding(file_path=Path("/repo/src/server.py"), line_number=42)],
            target_path=Path("/repo"),
        )
        loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/server.py"
        assert loc["region"]["startLine"] == 42

    def test_finding_without_location_does_not_crash(self, tmp_path):
        data = _write_and_load(tmp_path, [_finding(file_path=None, line_number=None)])
        result = data["runs"][0]["results"][0]
        assert not result.get("locations")

    def test_message_contains_description(self, tmp_path):
        data = _write_and_load(tmp_path, [_finding(description="genau dieser Text")])
        assert "genau dieser Text" in data["runs"][0]["results"][0]["message"]["text"]


class TestSeverityMapping:
    def test_critical_and_high_map_to_error(self, tmp_path):
        for sev in (Severity.CRITICAL, Severity.HIGH):
            data = _write_and_load(tmp_path, [_finding(severity=sev)])
            assert data["runs"][0]["results"][0]["level"] == "error"

    def test_medium_maps_to_warning(self, tmp_path):
        data = _write_and_load(tmp_path, [_finding(severity=Severity.MEDIUM)])
        assert data["runs"][0]["results"][0]["level"] == "warning"

    def test_low_and_info_map_to_note(self, tmp_path):
        for sev in (Severity.LOW, Severity.INFO):
            data = _write_and_load(tmp_path, [_finding(severity=sev)])
            assert data["runs"][0]["results"][0]["level"] == "note"


class TestSarifRules:
    def test_rules_are_deduplicated_by_check_id(self, tmp_path):
        findings = [_finding(line_number=1), _finding(line_number=2)]  # same check_id
        data = _write_and_load(tmp_path, findings)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len([r for r in rules if r["id"] == "CMD_INJECTION"]) == 1
