"""Tests für den TYPOSQUAT-Check (Feature 018).

Constitution-aligned:
- Prinzip I: VOR der Implementierung geschrieben (rot) -- weder der Check noch
  `_name_similarity` existieren beim Schreiben.
- Prinzip VI: paired vulnerable + clean Fixtures, npm UND PyPI.
- Prinzip V: Finding nennt Kandidat + ähnliches bekanntes Paket.
- Prinzip III: kuratierte Allowlist; unverwandte Pakete / malformte Manifeste →
  kein Finding; exakter Treffer → kein Finding.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcpfrisk.checks._name_similarity import damerau_le_1, levenshtein_le_1
from mcpfrisk.checks.typosquat import TyposquatCheck
from mcpfrisk.core.models import Severity


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# --------------------------------------------------------------------------
# Helfer: damerau_le_1
# --------------------------------------------------------------------------


class TestDamerau:
    def test_equal_is_true(self):
        assert damerau_le_1("fastmcp", "fastmcp")

    def test_single_substitution(self):
        assert damerau_le_1("fastmcp", "fastmcq")

    def test_single_insertion(self):
        assert damerau_le_1("fastmcp", "fastmcps")

    def test_single_deletion(self):
        assert damerau_le_1("fastmcp", "fastmc")

    def test_adjacent_transposition(self):
        assert damerau_le_1("fastmcp", "fatsmcp")

    def test_distance_two_is_false(self):
        assert not damerau_le_1("fastmcp", "faxtmcq")

    def test_far_apart_is_false(self):
        assert not damerau_le_1("fastmcp", "requests")


class TestLevenshtein:
    """Der geteilte Nicht-Check-Helfer, genutzt von TOOL_NAME_COLLISION (Review 2026-07)."""

    def test_equal(self):
        assert levenshtein_le_1("send_mail", "send_mail")

    def test_one_substitution(self):
        assert levenshtein_le_1("send_mail", "send_mall")

    def test_one_insertion(self):
        assert levenshtein_le_1("get_item", "get_items")

    def test_transposition_is_not_levenshtein_1(self):
        # Vertauschung = Damerau-1, aber Levenshtein-2 -> hier False.
        assert not levenshtein_le_1("fastmcp", "fatsmcp")

    def test_distance_two_is_false(self):
        assert not levenshtein_le_1("get_item", "get_orders")


# --------------------------------------------------------------------------
# US1 — npm
# --------------------------------------------------------------------------


class TestNpm:
    def test_scope_typo_is_flagged_medium(self, tmp_path):
        _write(
            tmp_path,
            "package.json",
            '{"dependencies": {"@modelcontextprotcol/server-github": "^1.0.0", '
            '"express": "^4.0.0"}}',
        )
        findings = TyposquatCheck().run(tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "TYPOSQUAT"
        assert f.severity == Severity.MEDIUM
        assert f.cwe_ref == "CWE-829"
        blob = f.description + (f.snippet or "")
        assert "@modelcontextprotcol/server-github" in blob
        assert "@modelcontextprotocol/server-github" in blob

    def test_exact_known_package_is_clean(self, tmp_path):
        _write(
            tmp_path,
            "package.json",
            '{"dependencies": {"@modelcontextprotocol/server-github": "^1.0.0"}}',
        )
        assert TyposquatCheck().run(tmp_path) == []

    def test_unrelated_packages_are_clean(self, tmp_path):
        _write(
            tmp_path,
            "package.json",
            '{"dependencies": {"express": "^4", "zod": "^3", "left-pad": "^1"}}',
        )
        assert TyposquatCheck().run(tmp_path) == []

    def test_malformed_json_is_skipped(self, tmp_path):
        _write(tmp_path, "package.json", '{"dependencies": {')
        assert TyposquatCheck().run(tmp_path) == []


# --------------------------------------------------------------------------
# US2 — PyPI (requirements.txt) + Damerau transposition
# --------------------------------------------------------------------------


class TestPyPI:
    def test_transposition_is_flagged(self, tmp_path):
        _write(tmp_path, "requirements.txt", "fatsmcp==1.0.0\nrequests>=2.0\n")
        findings = TyposquatCheck().run(tmp_path)
        assert len(findings) == 1
        blob = findings[0].description + (findings[0].snippet or "")
        assert "fatsmcp" in blob
        assert "fastmcp" in blob

    def test_correct_packages_are_clean(self, tmp_path):
        _write(tmp_path, "requirements.txt", "fastmcp==1.0.0\nmcp\nrequests\n")
        assert TyposquatCheck().run(tmp_path) == []

    def test_comment_and_flag_lines_ignored(self, tmp_path):
        _write(
            tmp_path,
            "requirements.txt",
            "# a comment\n-r other.txt\n--index-url https://x\nrequests\n",
        )
        assert TyposquatCheck().run(tmp_path) == []


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib erst ab 3.11")
class TestPyproject:
    def test_pyproject_dependency_typo_is_flagged(self, tmp_path):
        _write(
            tmp_path,
            "pyproject.toml",
            '[project]\nname = "x"\ndependencies = ["fatsmcp>=1.0", "requests"]\n',
        )
        findings = TyposquatCheck().run(tmp_path)
        assert len(findings) == 1
        assert "fastmcp" in (findings[0].description + (findings[0].snippet or ""))

    def test_pyproject_correct_is_clean(self, tmp_path):
        _write(
            tmp_path,
            "pyproject.toml",
            '[project]\nname = "x"\ndependencies = ["fastmcp>=1.0"]\n',
        )
        assert TyposquatCheck().run(tmp_path) == []

    def test_malformed_toml_is_skipped(self, tmp_path):
        _write(tmp_path, "pyproject.toml", "[project\nname = ")
        assert TyposquatCheck().run(tmp_path) == []


# --------------------------------------------------------------------------
# US3 — Degradation
# --------------------------------------------------------------------------


class TestDegradation:
    def test_no_manifest_does_not_apply(self, tmp_path):
        _write(tmp_path, "server.py", "print('hi')\n")
        check = TyposquatCheck()
        assert check.applies_to(tmp_path) is False
        assert check.run(tmp_path) == []

    def test_manifest_present_applies(self, tmp_path):
        _write(tmp_path, "requirements.txt", "requests\n")
        assert TyposquatCheck().applies_to(tmp_path) is True
