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

    def test_sh_dash_c_spawn_pattern_is_detected(self, tmp_path):
        """Regressionstest: spawn("sh", ["-c", tainted]) wurde komplett übersehen
        -- _assess() prüfte nur args[0] (die Konstante "sh"), nie das Array in
        args[1], wo das eigentlich gefährliche Element steht."""
        (tmp_path / "vuln.ts").write_text(
            "import { spawn } from 'child_process';\n"
            "export function run(cmd: string) {\n"
            "  spawn('sh', ['-c', cmd]);\n"
            "}\n",
            encoding="utf-8",
        )
        findings = [f for f in CommandInjectionCheck().run(tmp_path) if f.check_id == "CMD_INJECTION"]
        assert len(findings) == 1
        assert findings[0].severity.value == "critical"

    def test_import_alias_does_not_bypass_detection(self, tmp_path):
        """Regressionstest: 'import { exec as run } from "child_process"; run(...)'
        wurde nicht erkannt, weil der Callee-Name nur der lokale Alias 'run' ist,
        der nicht in JS_DANGEROUS_SEGMENTS steht."""
        (tmp_path / "vuln.ts").write_text(
            "import { exec as run } from 'child_process';\n"
            "export function go(cmd: string) {\n"
            "  run(`echo ${cmd}`);\n"
            "}\n",
            encoding="utf-8",
        )
        findings = [f for f in CommandInjectionCheck().run(tmp_path) if f.check_id == "CMD_INJECTION"]
        assert len(findings) >= 1

    def test_computed_member_access_does_not_bypass_detection(self, tmp_path):
        """Regressionstest: cp["exec"](...) (computed/bracket member access)
        wurde nicht erkannt -- _member_name kannte nur identifier und
        member_expression, nicht subscript_expression."""
        (tmp_path / "vuln.ts").write_text(
            "import * as cp from 'child_process';\n"
            "export function go(cmd: string) {\n"
            "  cp['exec'](`echo ${cmd}`);\n"
            "}\n",
            encoding="utf-8",
        )
        findings = [f for f in CommandInjectionCheck().run(tmp_path) if f.check_id == "CMD_INJECTION"]
        assert len(findings) >= 1


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
