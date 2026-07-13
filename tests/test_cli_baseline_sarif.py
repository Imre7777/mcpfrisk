"""CLI-Integrationstests für Baseline-Diffing (scan + probe) und SARIF-Output
(scan) -- Feature 010.

Constitution-aligned: eine Baseline-Datei darf gefundene Alt-Befunde nie
kommentarlos verschwinden lassen (Prinzip III) -- sie bleiben im Report
sichtbar, blockieren aber den Build nicht mehr.
"""
from __future__ import annotations

import json

from mcpfrisk import cli
from mcpfrisk.core.baseline import load_baseline
from tests.fixtures.ssrf_servers import running_ssrf_server

_VULNERABLE_SNIPPET = (
    "import subprocess\n"
    "def run_tool(user_input):\n"
    "    return subprocess.run(f'echo {user_input}', shell=True)\n"
)


def _write_vulnerable(tmp_path):
    (tmp_path / "server.py").write_text(_VULNERABLE_SNIPPET, encoding="utf-8")


class TestScanBaseline:
    def test_write_baseline_then_rescan_is_not_blocking(self, tmp_path):
        _write_vulnerable(tmp_path)
        baseline_path = tmp_path / "baseline.json"

        # Erster Lauf: Baseline aus dem aktuellen (verwundbaren) Stand schreiben.
        write_exit = cli.main(["scan", str(tmp_path), "--write-baseline", str(baseline_path)])
        assert baseline_path.exists()
        assert load_baseline(baseline_path)  # mind. ein Fingerprint wurde geschrieben
        # Der Schreib-Lauf selbst wertet noch nicht gegen die (gerade erst
        # erzeugte) Baseline -- der Fund blockiert hier wie gewohnt.
        assert write_exit == 1

        # Zweiter Lauf: derselbe Code, jetzt gegen die Baseline geprüft ->
        # der bekannte Fund darf NICHT mehr blockieren.
        rescan_exit = cli.main(["scan", str(tmp_path), "--baseline", str(baseline_path)])
        assert rescan_exit == 0

    def test_new_vulnerability_still_blocks_despite_baseline(self, tmp_path):
        _write_vulnerable(tmp_path)
        baseline_path = tmp_path / "baseline.json"
        cli.main(["scan", str(tmp_path), "--write-baseline", str(baseline_path)])

        # Eine ZUSÄTZLICHE, neue Schwachstelle in einer zweiten Datei ergänzen.
        (tmp_path / "other.py").write_text(
            "import os\ndef read(filename):\n    return open(os.path.join('/data', filename)).read()\n",
            encoding="utf-8",
        )
        exit_code = cli.main(["scan", str(tmp_path), "--baseline", str(baseline_path)])
        assert exit_code == 1  # das neue Finding blockiert weiterhin

    def test_missing_baseline_file_is_not_an_error(self, tmp_path):
        _write_vulnerable(tmp_path)
        missing = tmp_path / "does_not_exist.json"
        # Fehlende Baseline == leere Baseline -- alles gilt als neu, kein Crash.
        exit_code = cli.main(["scan", str(tmp_path), "--baseline", str(missing)])
        assert exit_code == 1

    def test_known_finding_stays_visible_in_report(self, tmp_path, capsys):
        _write_vulnerable(tmp_path)
        baseline_path = tmp_path / "baseline.json"
        cli.main(["scan", str(tmp_path), "--write-baseline", str(baseline_path)])
        capsys.readouterr()  # ersten Report verwerfen

        cli.main(["scan", str(tmp_path), "--baseline", str(baseline_path)])
        out = capsys.readouterr().out
        # Der Befund verschwindet nicht kommentarlos -- er wird weiterhin
        # gezeigt (nur nicht mehr blockierend gewertet).
        assert "Command Injection" in out


class TestScanSarif:
    def test_sarif_file_is_written_with_expected_content(self, tmp_path):
        _write_vulnerable(tmp_path)
        sarif_path = tmp_path / "results.sarif"
        cli.main(["scan", str(tmp_path), "--sarif", str(sarif_path), "--fail-on", "critical"])
        assert sarif_path.exists()
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"
        rule_ids = {r["ruleId"] for r in data["runs"][0]["results"]}
        assert "CMD_INJECTION" in rule_ids


class TestProbeBaseline:
    def test_probe_baseline_suppresses_known_finding_from_blocking(self, tmp_path):
        baseline_path = tmp_path / "baseline.json"
        with running_ssrf_server("vulnerable") as url:
            write_exit = cli.main(["probe", "--server", url, "--write-baseline", str(baseline_path)])
            assert write_exit == 1
            assert load_baseline(baseline_path)

            rescan_exit = cli.main(["probe", "--server", url, "--baseline", str(baseline_path)])
        assert rescan_exit == 0
