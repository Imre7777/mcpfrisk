"""Tests für Cross-Function-Taint in PATH_TRAVERSAL (Feature 012).

Constitution-aligned:
- Prinzip VI: paired vulnerable + clean Fixtures, Python UND JS/TS.
- Prinzip V: Finding verortet den konkreten Sink im Helper (Datei:Zeile).
- Prinzip III: validierender Helper → kein FP; Dedup gegen Doppelmeldung;
  zwei Ebenen tief bleibt (dokumentierte v1-Grenze) befundfrei statt falsch.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcpfrisk.checks.path_traversal import PathTraversalCheck
from mcpfrisk.core.sourcetree import jsts_available

FIXTURES = Path(__file__).parent / "fixtures"
JSTS = FIXTURES / "jsts"

requires_jsts = pytest.mark.skipif(
    not jsts_available(), reason="jsts-Extra (tree-sitter) nicht installiert"
)


def _run(tmp_path: Path, src: Path):
    (tmp_path / src.name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return [f for f in PathTraversalCheck().run(tmp_path) if f.check_id == "PATH_TRAVERSAL"]


def _write(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8")
    return [f for f in PathTraversalCheck().run(tmp_path) if f.check_id == "PATH_TRAVERSAL"]


class TestCrossFunctionPython:
    def test_positional_and_keyword_flow_are_flagged(self, tmp_path):
        findings = _run(tmp_path, FIXTURES / "crossfn_vuln.py")
        # Zwei getrennte Flüsse (read_file→_load positional, fetch_doc→_fetch
        # keyword) -> zwei Sinks in den Helfern.
        assert len(findings) == 2
        assert all(f.severity.value == "high" for f in findings)
        assert all(f.cwe_ref == "CWE-22" for f in findings)
        # Der Sink wird im Helper verortet (open() in _load / _fetch).
        lines = {f.line_number for f in findings}
        assert lines  # konkrete Sink-Zeilen vorhanden

    def test_validating_helper_is_clean(self, tmp_path):
        findings = _run(tmp_path, FIXTURES / "crossfn_clean.py")
        assert findings == []

    def test_untainted_constant_sink_is_not_flagged(self, tmp_path):
        # Nur der konstante Sink (_load_constant) + der validierende Helfer;
        # crossfn_clean.py insgesamt befundfrei -> deckt "kein Taint" mit ab.
        findings = _run(tmp_path, FIXTURES / "crossfn_clean.py")
        assert findings == []

    def test_no_double_report_when_helper_param_is_path_like(self, tmp_path):
        # Helper-Param IST pfad-artig ('path') -> der intra-Pass meldet den Sink
        # bereits; der cross-Pass darf ihn NICHT zusätzlich melden.
        findings = _write(
            tmp_path, "dedup.py",
            "def read_file(filename):\n"
            "    return _load(filename)\n"
            "def _load(path):\n"
            "    with open(path) as f:\n"
            "        return f.read()\n",
        )
        assert len(findings) == 1  # genau ein Finding, nicht zwei

    def test_two_levels_deep_is_out_of_scope(self, tmp_path):
        # F -> G -> H -> sink: zwei Funktionsgrenzen. v1 verfolgt nur eine ->
        # bewusst befundfrei (dokumentierte Grenze), kein Crash.
        findings = _write(
            tmp_path, "twolevel.py",
            "def read_file(filename):\n"
            "    return _mid(filename)\n"
            "def _mid(a):\n"
            "    return _deep(a)\n"
            "def _deep(b):\n"
            "    with open(b) as f:\n"
            "        return f.read()\n",
        )
        assert findings == []

    def test_keyword_bound_to_other_param_does_not_taint_sink(self, tmp_path):
        # Der pfad-artige Wert wird als Keyword an einen Parameter gebunden,
        # der NICHT geöffnet wird; der geöffnete Parameter ist konstant.
        findings = _write(
            tmp_path, "kwmiss.py",
            "def read_file(filename):\n"
            "    return _load(note=filename, src='/etc/hosts')\n"
            "def _load(note, src):\n"
            "    with open(src) as f:\n"
            "        return f.read()\n",
        )
        assert findings == []


@requires_jsts
class TestCrossFunctionJsTs:
    def test_positional_flow_is_flagged(self, tmp_path):
        findings = _run(tmp_path, JSTS / "crossfn_vuln.ts")
        assert len(findings) == 1
        assert findings[0].severity.value == "high"

    def test_validating_helper_is_clean(self, tmp_path):
        findings = _run(tmp_path, JSTS / "crossfn_clean.ts")
        assert findings == []
