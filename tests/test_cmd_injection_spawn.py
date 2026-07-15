"""Feature 023: spawn-Array-Präzision (JS/TS CMD_INJECTION).

Node-Semantik: exec()/execSync() öffnen IMMER eine Shell (erstes Argument =
Shell-Kommandostring). spawn()/spawnSync() starten ein Programm direkt (execvp),
Argumente als separate argv-Elemente -- KEINE Shell, außer `{shell: true}`.

Vorher meldete _assess() spawn(cmd, [args]) fälschlich als HIGH Command Injection
(behandelte spawn wie exec). Das ist ein False Positive auf der von Node
empfohlenen, sicheren Standardform. Diese Tests fixieren die korrekte Trennung.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcpfrisk.checks.command_injection import CommandInjectionCheck
from mcpfrisk.core.sourcetree import jsts_available

pytestmark = pytest.mark.skipif(
    not jsts_available(), reason="jsts-Extra (tree-sitter) nicht installiert"
)


def _scan(tmp_path: Path, code: str) -> list:
    (tmp_path / "srv.ts").write_text(code, encoding="utf-8")
    check = CommandInjectionCheck()
    return [f for f in check.run(tmp_path) if f.check_id == "CMD_INJECTION"]


# --------------------------------------------------------------------------
# US1 -- spawn ohne shell:true ist sauber (der eigentliche Fix)
# --------------------------------------------------------------------------
class TestSpawnWithoutShellIsClean:
    def test_spawn_variable_program_with_array_args_is_clean(self, tmp_path):
        code = (
            "import { spawn } from 'child_process';\n"
            "export function run(cmd: string, arg: string) {\n"
            "  spawn(cmd, [arg]);\n"   # sichere Standardform: keine Shell
            "}\n"
        )
        assert _scan(tmp_path, code) == []

    def test_spawn_template_program_no_shell_is_clean(self, tmp_path):
        code = (
            "import { spawn } from 'child_process';\n"
            "export function run(bin: string, arg: string) {\n"
            "  spawn(`${bin}`, [arg]);\n"
            "}\n"
        )
        assert _scan(tmp_path, code) == []

    def test_spawnSync_variable_is_clean(self, tmp_path):
        code = (
            "import { spawnSync } from 'child_process';\n"
            "export function run(cmd: string, a: string) {\n"
            "  spawnSync(cmd, [a]);\n"
            "}\n"
        )
        assert _scan(tmp_path, code) == []

    def test_spawn_with_explicit_shell_false_is_clean(self, tmp_path):
        code = (
            "import { spawn } from 'child_process';\n"
            "export function run(cmd: string, a: string) {\n"
            "  spawn(cmd, [a], { shell: false });\n"
            "}\n"
        )
        assert _scan(tmp_path, code) == []


# --------------------------------------------------------------------------
# US2 -- spawn MIT shell:true bleibt gefährlich (dann wie exec)
# --------------------------------------------------------------------------
class TestSpawnWithShellTrueIsDangerous:
    def test_spawn_shell_true_variable_is_flagged(self, tmp_path):
        code = (
            "import { spawn } from 'child_process';\n"
            "export function run(cmd: string) {\n"
            "  spawn(cmd, [], { shell: true });\n"
            "}\n"
        )
        assert len(_scan(tmp_path, code)) >= 1

    def test_spawn_shell_true_template_is_flagged(self, tmp_path):
        code = (
            "import { spawn } from 'child_process';\n"
            "export function run(dir: string) {\n"
            "  spawn(`ls ${dir}`, [], { shell: true });\n"
            "}\n"
        )
        assert len(_scan(tmp_path, code)) >= 1


# --------------------------------------------------------------------------
# US3 -- exec/execSync unverändert gefährlich (immer Shell)
# --------------------------------------------------------------------------
class TestExecFamilyUnchanged:
    def test_exec_template_still_flagged(self, tmp_path):
        code = (
            "import { exec } from 'child_process';\n"
            "export function run(cmd: string) {\n"
            "  exec(`echo ${cmd}`);\n"
            "}\n"
        )
        assert len(_scan(tmp_path, code)) >= 1

    def test_execSync_variable_still_flagged(self, tmp_path):
        code = (
            "import { execSync } from 'child_process';\n"
            "export function run(cmd: string) {\n"
            "  execSync(cmd);\n"
            "}\n"
        )
        assert len(_scan(tmp_path, code)) >= 1


# --------------------------------------------------------------------------
# US4 -- sh -c <tainted> bleibt CRITICAL (echte Shell-Invokation)
# --------------------------------------------------------------------------
class TestShDashCStillCritical:
    def test_spawn_sh_dash_c_tainted_is_critical(self, tmp_path):
        code = (
            "import { spawn } from 'child_process';\n"
            "export function run(cmd: string) {\n"
            "  spawn('sh', ['-c', cmd]);\n"
            "}\n"
        )
        findings = _scan(tmp_path, code)
        assert len(findings) >= 1
        assert findings[0].severity.value == "critical"
