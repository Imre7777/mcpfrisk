"""Tests für Baseline-/Diff-Scanning (Feature 010).

Constitution-aligned:
- Prinzip III: eine fehlende/korrupte Baseline-Datei ist NIE ein Fehler --
  wird als leere Baseline behandelt (alle Findings gelten als neu).
- Der Fingerprint ist stabil über Maschinen/CI-Runner hinweg (relativer statt
  absoluter Pfad) und ändert sich NICHT durch kosmetische Snippet-Änderungen.
"""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.core.baseline import (
    fingerprint,
    load_baseline,
    split_new_vs_known,
    write_baseline,
)
from mcpfrisk.core.models import Finding, Severity


def _finding(**overrides) -> Finding:
    defaults = dict(
        check_id="CMD_INJECTION",
        severity=Severity.HIGH,
        title="Potenzielle Command Injection via subprocess.run()",
        description="...",
        file_path=Path("/repo/server.py"),
        line_number=42,
        snippet="subprocess.run(cmd, shell=True)",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestFingerprint:
    def test_stable_across_calls(self):
        f = _finding()
        assert fingerprint(f) == fingerprint(f)

    def test_changes_when_check_id_differs(self):
        a = _finding(check_id="CMD_INJECTION")
        b = _finding(check_id="PATH_TRAVERSAL")
        assert fingerprint(a) != fingerprint(b)

    def test_changes_when_line_differs(self):
        a = _finding(line_number=42)
        b = _finding(line_number=43)
        assert fingerprint(a) != fingerprint(b)

    def test_changes_when_title_differs(self):
        a = _finding(title="A")
        b = _finding(title="B")
        assert fingerprint(a) != fingerprint(b)

    def test_unaffected_by_snippet_text(self):
        # Kosmetische Formatierungsänderungen im Snippet dürfen den
        # Fingerprint nicht kippen -- sonst würde jede Whitespace-Änderung
        # eine "neue" Baseline-Abweichung erzeugen.
        a = _finding(snippet="subprocess.run(cmd, shell=True)")
        b = _finding(snippet="subprocess.run(  cmd,   shell = True )")
        assert fingerprint(a) == fingerprint(b)

    def test_uses_relative_path_not_absolute(self):
        # Zwei verschiedene Scan-Ziel-Präfixe, gleiche relative Struktur ->
        # gleicher Fingerprint (portabel über Maschinen/CI-Runner hinweg).
        a = _finding(file_path=Path("/home/alice/repo/server.py"))
        b = _finding(file_path=Path("/builds/ci-runner-7/repo/server.py"))
        fp_a = fingerprint(a, target_path=Path("/home/alice/repo"))
        fp_b = fingerprint(b, target_path=Path("/builds/ci-runner-7/repo"))
        assert fp_a == fp_b

    def test_no_target_path_falls_back_to_raw_path(self):
        # Ohne target_path (z.B. Tier-2-Findings ohne Datei-Kontext) darf es
        # nicht crashen.
        f = _finding()
        assert fingerprint(f, target_path=None)

    def test_no_file_path_does_not_crash(self):
        # Tier-2-Findings haben oft keinen file_path.
        f = _finding(file_path=None, line_number=None)
        assert fingerprint(f)


class TestLoadBaseline:
    def test_missing_file_returns_empty_set(self, tmp_path):
        assert load_baseline(tmp_path / "does_not_exist.json") == set()

    def test_corrupt_json_returns_empty_set(self, tmp_path):
        p = tmp_path / "corrupt.json"
        p.write_text("{not valid json", encoding="utf-8")
        assert load_baseline(p) == set()

    def test_write_then_load_round_trip(self, tmp_path):
        findings = [_finding(), _finding(check_id="PATH_TRAVERSAL")]
        p = tmp_path / "baseline.json"
        write_baseline(p, findings)
        loaded = load_baseline(p)
        assert loaded == {fingerprint(f) for f in findings}


class TestSplitNewVsKnown:
    def test_known_finding_is_split_out(self):
        known_finding = _finding()
        new_finding = _finding(check_id="PATH_TRAVERSAL")
        baseline = {fingerprint(known_finding)}

        new, known = split_new_vs_known([known_finding, new_finding], baseline)

        assert new == [new_finding]
        assert known == [known_finding]

    def test_empty_baseline_means_everything_is_new(self):
        findings = [_finding(), _finding(check_id="PATH_TRAVERSAL")]
        new, known = split_new_vs_known(findings, set())
        assert new == findings
        assert known == []
