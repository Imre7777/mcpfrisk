"""Regression tests for CLI output safety.

Bug (fixed): on a legacy non-UTF-8 console (e.g. Windows cp1252), printing the
report's status glyphs (e.g. the "no findings" / severity icons) raised
UnicodeEncodeError and crashed the whole run. The CLI now reconfigures stdout/stderr
to UTF-8 with replacement so output degrades gracefully instead of aborting.

Per the project's "fixed bugs become regression tests" practice, this locks the
behavior in so the crash cannot silently return.
"""
from __future__ import annotations

import io
import sys

from mcpfrisk import cli


def test_scan_does_not_crash_on_cp1252_console(tmp_path, monkeypatch):
    # A clean directory => report hits the "no findings" glyph path that used to crash.
    (tmp_path / "server.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    # Simulate a legacy Windows console: stdout/stderr that can only encode cp1252.
    cp1252_stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    cp1252_stderr = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", cp1252_stdout)
    monkeypatch.setattr(sys, "stderr", cp1252_stderr)

    # Must not raise UnicodeEncodeError.
    exit_code = cli.main(["scan", str(tmp_path)])

    assert exit_code == 0  # clean dir => passing build


def test_make_output_utf8_safe_is_idempotent_and_safe():
    # Calling the hardening helper must never raise, even repeatedly.
    cli._make_output_utf8_safe()
    cli._make_output_utf8_safe()


def test_dynamic_report_success_message_names_the_actual_check(capsys):
    """Regressionstest: die 'keine Findings'-Erfolgsmeldung im dynamischen
    Report war hartcodiert auf 'Keine AUTH_BOUNDARY-Findings', obwohl bis zu
    6 verschiedene Tier-2-Checks laufen können (SSRF_CHECK, RBAC_CROSS_TENANT,
    SCHEMA_FUZZING, ERROR_LEAKAGE, RATE_LIMITING). Die Meldung muss den
    tatsächlich gelaufenen Check nennen, nicht immer AUTH_BOUNDARY."""
    from mcpfrisk.core.models import DynamicScanResult
    from mcpfrisk.core.report import print_dynamic_report

    result = DynamicScanResult(target="http://localhost:8000/mcp", checks_run=["SSRF_CHECK"])
    print_dynamic_report(result)
    out = capsys.readouterr().out
    assert "SSRF_CHECK" in out
    assert "AUTH_BOUNDARY" not in out


def test_version_flag_prints_and_exits_zero(capsys):
    """--version funktioniert trotz required subparser (argparse-Quirk) und nennt
    die installierte Version -- wichtig für belastbare Bug-Reports."""
    import pytest

    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("mcpfrisk ")


def test_nonexistent_path_exits_nonzero(tmp_path, capsys):
    """Ein nicht existierender Scan-Pfad MUSS mit != 0 enden (CI-Gate darf einen
    Tippfehler im Pfad nicht als Pass durchwinken)."""
    missing = tmp_path / "does-not-exist"
    assert cli.main(["scan", str(missing)]) == 2
