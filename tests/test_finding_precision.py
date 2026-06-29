"""Tests für Feature 004 — Befund-Präzision.

Diese Tests sichern drei Präzisions-Verbesserungen ab, die aus der
Real-Repo-Validierung stammen, OHNE Prinzip III zu verletzen (kein Finding
wird unterdrückt, keine Pfade werden ausgeschlossen):

- US1: konstante Argument-Liste + redundantes shell=True -> MEDIUM statt CRITICAL
- US2: mehrzeilige Aufrufe liefern ein vollständiges, kompaktes Snippet
- US3: PATH_TRAVERSAL hängt einen Triage-Hinweis an, wenn das Modul eine
  separate Validierungsfunktion besitzt (Finding feuert trotzdem)

Jede US hat verwundbar + sauber/Gegenprobe (Prinzip VI).
"""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.checks.command_injection import CommandInjectionCheck
from mcpfrisk.checks.path_traversal import PathTraversalCheck
from mcpfrisk.core.models import Severity
from mcpfrisk.core.runner import run_static_scan

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CLEAN_SERVER = FIXTURES_DIR / "clean_server.py"


def _scan_single_file(tmp_path: Path, source_file: Path):
    target_dir = tmp_path / "isolated"
    target_dir.mkdir()
    (target_dir / source_file.name).write_text(source_file.read_text())
    return run_static_scan(target_dir)


# ---------------------------------------------------------------------------
# US1 — Severity-Kalibrierung
# ---------------------------------------------------------------------------
class TestCommandInjectionSeverityCalibration:
    def test_array_with_redundant_shell_true_is_medium(self, tmp_path):
        """[cmd, '--version'] + shell=True ist KEIN interpolierter Befehl ->
        Best-Practice-Verstoß (MEDIUM), nicht CRITICAL. Wird weiterhin gemeldet."""
        sample = tmp_path / "redundant_shell.py"
        sample.write_text(
            "import subprocess\n"
            "def check(cmd):\n"
            "    return subprocess.run([cmd, '--version'], shell=True)\n"
        )
        findings = CommandInjectionCheck().run(tmp_path)
        assert len(findings) == 1, "Befund darf nicht unterdrückt werden (Prinzip III)."
        assert findings[0].severity == Severity.MEDIUM

    def test_interpolated_command_with_shell_true_stays_critical(self, tmp_path):
        """Echter RCE-Pfad (f-string + shell=True) bleibt CRITICAL — keine Regression."""
        sample = tmp_path / "interp_shell.py"
        sample.write_text(
            "import subprocess\n"
            "def run(arg):\n"
            "    return subprocess.run(f'git clone {arg}', shell=True)\n"
        )
        findings = CommandInjectionCheck().run(tmp_path)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_list_without_shell_true_is_clean(self, tmp_path):
        sample = tmp_path / "safe.py"
        sample.write_text(
            "import subprocess\n"
            "def run_ls():\n"
            "    return subprocess.run(['ls', '-la'], capture_output=True)\n"
        )
        assert CommandInjectionCheck().run(tmp_path) == []


# ---------------------------------------------------------------------------
# US2 — Mehrzeilen-Snippets
# ---------------------------------------------------------------------------
class TestMultilineSnippet:
    def test_multiline_call_snippet_is_complete_and_single_line(self, tmp_path):
        sample = tmp_path / "multiline.py"
        sample.write_text(
            "import subprocess\n"
            "def run(arg):\n"
            "    return subprocess.run(\n"
            "        f'git clone {arg}',\n"
            "        shell=True,\n"
            "    )\n"
        )
        findings = CommandInjectionCheck().run(tmp_path)
        assert len(findings) >= 1
        snippet = findings[0].snippet or ""
        assert "\n" not in snippet, "Snippet soll zu einer Zeile kollabiert sein."
        assert "subprocess.run" in snippet
        assert "git clone" in snippet, "Das relevante Argument muss sichtbar sein."

    def test_long_call_snippet_is_capped(self, tmp_path):
        sample = tmp_path / "long_call.py"
        long_arg = "x" * 400
        sample.write_text(
            "import subprocess\n"
            "def run():\n"
            f"    return subprocess.run(f'echo {{0}} {long_arg}'.format(1), shell=True)\n"
        )
        findings = CommandInjectionCheck().run(tmp_path)
        assert len(findings) >= 1
        snippet = findings[0].snippet or ""
        assert len(snippet) <= 200
        assert snippet.endswith("…")


# ---------------------------------------------------------------------------
# US3 — Triage-Kontext bei separater Validierungsfunktion
# ---------------------------------------------------------------------------
class TestPathTraversalTriageContext:
    def test_module_with_separate_validator_adds_hint(self, tmp_path):
        """filesystem-Muster: Validierung in eigener Funktion, Öffner in anderer.
        Das Finding feuert weiterhin (HIGH) und nennt die Validierungsfunktion."""
        sample = tmp_path / "with_validator.py"
        sample.write_text(
            "import os\n"
            "def validate_path(p):\n"
            "    real = os.path.realpath(p)\n"
            "    if not real.startswith('/data'):\n"
            "        raise ValueError('denied')\n"
            "    return real\n"
            "\n"
            "def read_file(filename):\n"
            "    with open(filename) as f:\n"
            "        return f.read()\n"
        )
        findings = PathTraversalCheck().run(tmp_path)
        assert len(findings) >= 1, "Finding darf nicht unterdrückt werden."
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert "validate_path" in f.description
        assert "verifizieren" in f.description.lower()

    def test_module_without_validator_has_no_hint(self, tmp_path):
        sample = tmp_path / "no_validator.py"
        sample.write_text(
            "def read_file(filename):\n"
            "    with open(filename) as f:\n"
            "        return f.read()\n"
        )
        findings = PathTraversalCheck().run(tmp_path)
        assert len(findings) >= 1
        assert "verifizieren" not in findings[0].description.lower()

    def test_clean_server_still_has_no_finding(self, tmp_path):
        result = _scan_single_file(tmp_path, CLEAN_SERVER)
        pt = [f for f in result.findings if f.check_id == "PATH_TRAVERSAL"]
        assert pt == []
