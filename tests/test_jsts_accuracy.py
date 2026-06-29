"""US3 (Semantic Accuracy): die AST-basierte JS/TS-Analyse ist mehrzeilen-fest
und immun gegen Treffer in Kommentaren/Strings -- die zentrale Verbesserung
gegenüber der früheren Zeilen-Regex.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcpfrisk.checks.command_injection import CommandInjectionCheck
from mcpfrisk.core.sourcetree import jsts_available

pytestmark = pytest.mark.skipif(
    not jsts_available(), reason="jsts-Extra (tree-sitter) nicht installiert"
)


def _cmd_findings(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8")
    return [f for f in CommandInjectionCheck().run(tmp_path) if f.check_id == "CMD_INJECTION"]


def test_multiline_exec_call_is_detected(tmp_path):
    """Ein über mehrere Zeilen verteilter exec()-Aufruf wird erkannt --
    eine Zeilen-Regex sähe nur Fragmente."""
    src = (
        'import { exec } from "child_process";\n'
        "export function f(x: string) {\n"
        "  exec(\n"
        "    `echo ${x}`\n"
        "  );\n"
        "}\n"
    )
    assert len(_cmd_findings(tmp_path, "multiline.ts", src)) >= 1


def test_dangerous_pattern_in_comment_is_not_flagged(tmp_path):
    """execSync(...) in einem Kommentar ist kein ausgeführter Code."""
    src = (
        "export function f(x: string) {\n"
        "  // legacy: execSync(`rm -rf ${x}`) wurde entfernt\n"
        "  return x;\n"
        "}\n"
    )
    assert _cmd_findings(tmp_path, "comment.ts", src) == []


def test_dangerous_pattern_in_string_is_not_flagged(tmp_path):
    """Der Text 'execSync(' in einem String-Literal ist kein Aufruf."""
    src = 'const help = "call execSync( ... ) only with argument arrays";\n'
    assert _cmd_findings(tmp_path, "string.ts", src) == []
