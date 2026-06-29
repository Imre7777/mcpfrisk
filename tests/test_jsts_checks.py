"""US1 (Detection Parity): die statischen Checks finden in JS/TS dieselben
Schwachstellenklassen wie in Python -- über den gemeinsamen SourceModel-Port.

Jeder Check: ein True-Positive- UND ein False-Positive-Fixture (Constitution
Prinzip VI: keine Detektionslogik ohne gepaarten clean/vuln-Test).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcpfrisk.checks.command_injection import CommandInjectionCheck
from mcpfrisk.checks.path_traversal import PathTraversalCheck
from mcpfrisk.checks.tool_poisoning import ToolDescriptionPoisoningCheck
from mcpfrisk.core.sourcetree import jsts_available

FX = Path(__file__).parent / "fixtures" / "jsts"

pytestmark = pytest.mark.skipif(
    not jsts_available(), reason="jsts-Extra (tree-sitter) nicht installiert"
)


def _run(check, tmp_path: Path, fixture_name: str):
    dest = tmp_path / fixture_name
    dest.write_text((FX / fixture_name).read_text(encoding="utf-8"), encoding="utf-8")
    return [f for f in check.run(tmp_path) if f.check_id == check.check_id]


class TestJsTsCommandInjection:
    def test_detects_exec_template_injection(self, tmp_path):
        findings = _run(CommandInjectionCheck(), tmp_path, "cmd_injection_vuln.ts")
        assert len(findings) >= 1

    def test_execfile_array_is_clean(self, tmp_path):
        findings = _run(CommandInjectionCheck(), tmp_path, "cmd_injection_clean.ts")
        assert findings == []


class TestJsTsPathTraversal:
    def test_detects_unsandboxed_readfile(self, tmp_path):
        findings = _run(PathTraversalCheck(), tmp_path, "path_traversal_vuln.ts")
        assert len(findings) >= 1

    def test_validated_path_is_clean(self, tmp_path):
        findings = _run(PathTraversalCheck(), tmp_path, "path_traversal_clean.ts")
        assert findings == []


class TestJsTsToolPoisoning:
    def test_detects_important_tag_in_server_tool(self, tmp_path):
        findings = _run(ToolDescriptionPoisoningCheck(), tmp_path, "tool_poisoning_vuln.ts")
        assert len(findings) >= 1

    def test_clean_description_is_clean(self, tmp_path):
        findings = _run(ToolDescriptionPoisoningCheck(), tmp_path, "tool_poisoning_clean.ts")
        assert findings == []
