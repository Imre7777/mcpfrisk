"""Polish-Phase: Robustheit der JS/TS-Analyse.

- Fehlerhafte TS-Dateien dürfen den Scan nicht zum Absturz bringen.
- Gemischte Python-/TS-Bäume werden in einem Lauf beide abgedeckt.
- Fehlt das jsts-Extra, werden JS/TS-Dateien sauber übersprungen (NIE als
  'clean' gewertet); CMD_INJECTION fällt auf seine Regex zurück.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcpfrisk.checks.command_injection import CommandInjectionCheck
from mcpfrisk.core.runner import run_static_scan
from mcpfrisk.core.sourcetree import jsts_available

FX = Path(__file__).parent / "fixtures"
JSTS = FX / "jsts"

requires_jsts = pytest.mark.skipif(
    not jsts_available(), reason="jsts-Extra (tree-sitter) nicht installiert"
)


@requires_jsts
def test_malformed_ts_does_not_crash_scan(tmp_path):
    (tmp_path / "broken.ts").write_text(
        "export function f( { const x = exec(`echo ${\n", encoding="utf-8"
    )
    (tmp_path / "ok.ts").write_text(
        (JSTS / "cmd_injection_clean.ts").read_text(encoding="utf-8"), encoding="utf-8"
    )
    result = run_static_scan(tmp_path)  # darf nicht werfen
    assert "CMD_INJECTION" in result.checks_run


@requires_jsts
def test_mixed_python_and_ts_tree(tmp_path):
    (tmp_path / "server.py").write_text(
        (FX / "vulnerable_server.py").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "tool.ts").write_text(
        (JSTS / "path_traversal_vuln.ts").read_text(encoding="utf-8"), encoding="utf-8"
    )
    result = run_static_scan(tmp_path)
    flagged_suffixes = {
        f.file_path.suffix for f in result.findings if f.file_path is not None
    }
    assert ".py" in flagged_suffixes
    assert ".ts" in flagged_suffixes


def test_parser_absent_skips_jsts_but_cmd_falls_back(tmp_path, monkeypatch):
    from mcpfrisk.core.sourcetree import treesitter

    monkeypatch.setattr(treesitter, "available", lambda: False)
    assert jsts_available() is False

    (tmp_path / "vuln.ts").write_text(
        (JSTS / "cmd_injection_vuln.ts").read_text(encoding="utf-8"), encoding="utf-8"
    )
    # CMD_INJECTION: Regex-Fallback findet exec(`...${...}`) auch ohne Parser.
    cmd = [f for f in CommandInjectionCheck().run(tmp_path) if f.check_id == "CMD_INJECTION"]
    assert len(cmd) >= 1

    # Der Gesamt-Scan läuft durch, ohne zu crashen.
    result = run_static_scan(tmp_path)
    assert "PATH_TRAVERSAL" in result.checks_run


def test_scan_prints_jsts_hint_once_when_extra_missing(tmp_path, monkeypatch, capsys):
    """T033: liegt JS/TS-Code vor, fehlt aber das jsts-Extra, soll der Scan
    EINMAL auf `pip install mcpfrisk[jsts]` hinweisen (statt still nur Teil-
    abdeckung zu liefern)."""
    import argparse

    from mcpfrisk.cli import _run_scan
    from mcpfrisk.core.sourcetree import treesitter

    monkeypatch.setattr(treesitter, "available", lambda: False)
    (tmp_path / "vuln.ts").write_text(
        (JSTS / "cmd_injection_vuln.ts").read_text(encoding="utf-8"), encoding="utf-8"
    )
    args = argparse.Namespace(path=tmp_path, json=None, fail_on="high", skip=[])
    _run_scan(args)
    err = capsys.readouterr().err
    assert "jsts" in err.lower()
    assert err.lower().count("pip install mcpfrisk[jsts]".lower()) == 1
