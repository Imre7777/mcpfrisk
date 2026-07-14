"""Feature 022: Scan-Exclusions (`.mcpfriskignore` + `--exclude`).

Zentrales `is_excluded()`-Prädikat, gitignore-artige Ignore-Datei und ein
CLI-`--exclude`, das via contextvars bis zu den Checks durchreicht. Bewusste
Recall-Entscheidung (Prinzip III): der Default excludet weiterhin NUR echte
Build-/Dependency-Verzeichnisse; Test-/Example-Ausschluss ist opt-in.
"""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.core.fs import (
    DEFAULT_EXCLUDED_DIRS,
    exclude_context,
    is_excluded,
    iter_source_files,
    load_ignore_patterns,
)


# --------------------------------------------------------------------------
# is_excluded — Default-Verzeichnisse (unverändertes Verhalten)
# --------------------------------------------------------------------------
class TestDefaultExclusions:
    def test_node_modules_is_excluded_by_default(self, tmp_path):
        p = tmp_path / "node_modules" / "left-pad" / "index.js"
        assert is_excluded(p, tmp_path) is True

    def test_venv_and_dist_excluded_by_default(self, tmp_path):
        assert is_excluded(tmp_path / ".venv" / "x.py", tmp_path) is True
        assert is_excluded(tmp_path / "dist" / "b.js", tmp_path) is True

    def test_plain_source_not_excluded_by_default(self, tmp_path):
        # KEIN pauschaler tests-Ausschluss: Test-Code wird per Default gescannt.
        assert is_excluded(tmp_path / "tests" / "test_server.py", tmp_path) is False
        assert is_excluded(tmp_path / "server.py", tmp_path) is False

    def test_default_set_unchanged(self):
        # Regressions-Anker: Default-Set bleibt Build/Vendor-only.
        assert "tests" not in DEFAULT_EXCLUDED_DIRS
        assert "node_modules" in DEFAULT_EXCLUDED_DIRS


# --------------------------------------------------------------------------
# is_excluded — explizite Muster (extra=...)
# --------------------------------------------------------------------------
class TestExplicitPatterns:
    def test_directory_pattern_with_trailing_slash(self, tmp_path):
        p = tmp_path / "tests" / "test_a.py"
        assert is_excluded(p, tmp_path, extra=("tests/",)) is True
        # Ohne Muster bleibt es drin.
        assert is_excluded(p, tmp_path) is False

    def test_glob_extension_pattern(self, tmp_path):
        p = tmp_path / "public" / "bundle.min.js"
        assert is_excluded(p, tmp_path, extra=("*.min.js",)) is True
        assert is_excluded(tmp_path / "public" / "app.js", tmp_path, extra=("*.min.js",)) is False

    def test_nested_double_star_pattern(self, tmp_path):
        p = tmp_path / "pkg" / "sub" / "fixtures" / "data.py"
        assert is_excluded(p, tmp_path, extra=("**/fixtures",)) is True

    def test_path_prefix_pattern(self, tmp_path):
        p = tmp_path / "examples" / "srv" / "main.py"
        assert is_excluded(p, tmp_path, extra=("examples/",)) is True
        assert is_excluded(tmp_path / "src" / "main.py", tmp_path, extra=("examples/",)) is False

    def test_bare_name_matches_any_component(self, tmp_path):
        p = tmp_path / "a" / "b" / "vendored" / "x.py"
        assert is_excluded(p, tmp_path, extra=("vendored",)) is True

    def test_single_file_target_defaults_still_apply(self, tmp_path):
        # Einzeldatei-Ziel: root == file. Darf nicht crashen; Default greift.
        f = tmp_path / "server.py"
        f.write_text("x = 1\n", encoding="utf-8")
        assert is_excluded(f, f) is False


# --------------------------------------------------------------------------
# load_ignore_patterns — Datei-Parsing
# --------------------------------------------------------------------------
class TestLoadIgnorePatterns:
    def test_missing_file_returns_empty(self, tmp_path):
        assert load_ignore_patterns(tmp_path) == ()

    def test_comments_and_blank_lines_stripped(self, tmp_path):
        (tmp_path / ".mcpfriskignore").write_text(
            "# ein Kommentar\n\n  tests/  \nexamples/\n\n#noch einer\n*.min.js\n",
            encoding="utf-8",
        )
        pats = load_ignore_patterns(tmp_path)
        assert pats == ("tests/", "examples/", "*.min.js")

    def test_ignore_file_applied_by_is_excluded(self, tmp_path):
        (tmp_path / ".mcpfriskignore").write_text("tests/\n", encoding="utf-8")
        p = tmp_path / "tests" / "test_a.py"
        assert is_excluded(p, tmp_path) is True


# --------------------------------------------------------------------------
# exclude_context — CLI-Muster via contextvars
# --------------------------------------------------------------------------
class TestExcludeContext:
    def test_context_patterns_apply_and_reset(self, tmp_path):
        p = tmp_path / "examples" / "x.py"
        assert is_excluded(p, tmp_path) is False
        with exclude_context(("examples/",)):
            assert is_excluded(p, tmp_path) is True
        # nach dem Kontext wieder zurückgesetzt
        assert is_excluded(p, tmp_path) is False

    def test_empty_context_is_noop(self, tmp_path):
        with exclude_context(()):
            assert is_excluded(tmp_path / "src" / "a.py", tmp_path) is False


# --------------------------------------------------------------------------
# iter_source_files — Integration
# --------------------------------------------------------------------------
class TestIterSourceFilesIntegration:
    def _tree(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "server.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "examples").mkdir()
        (tmp_path / "examples" / "demo.py").write_text("y = 2\n", encoding="utf-8")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "dep.js").write_text("z = 3\n", encoding="utf-8")

    def test_default_scans_examples_but_not_node_modules(self, tmp_path):
        self._tree(tmp_path)
        files = {p.name for p in iter_source_files(tmp_path)}
        assert "server.py" in files
        assert "demo.py" in files          # examples per Default gescannt
        assert "dep.js" not in files       # node_modules per Default aus

    def test_ignore_file_excludes_examples(self, tmp_path):
        self._tree(tmp_path)
        (tmp_path / ".mcpfriskignore").write_text("examples/\n", encoding="utf-8")
        files = {p.name for p in iter_source_files(tmp_path)}
        assert "server.py" in files
        assert "demo.py" not in files

    def test_context_exclude_excludes_examples(self, tmp_path):
        self._tree(tmp_path)
        with exclude_context(("examples/",)):
            files = {p.name for p in iter_source_files(tmp_path)}
        assert "demo.py" not in files


# --------------------------------------------------------------------------
# End-to-End über run_static_scan (--exclude reicht bis zu den Checks durch)
# --------------------------------------------------------------------------
class TestRunStaticScanExclude:
    def test_exclude_suppresses_findings_in_excluded_dir(self, tmp_path):
        from mcpfrisk.core.runner import run_static_scan

        # Ein hartcodiertes Secret in examples/ -> würde normalerweise gemeldet.
        (tmp_path / "examples").mkdir()
        (tmp_path / "examples" / "leak.py").write_text(
            "API_KEY = 'sk-proj-abc123def456ghi789jklmnopqrstuvwxyz0123456789'\n",
            encoding="utf-8",
        )

        baseline = run_static_scan(tmp_path)
        assert any(f.check_id == "HARDCODED_SECRETS" for f in baseline.findings)

        excluded = run_static_scan(tmp_path, exclude={"examples/"})
        assert not any(f.check_id == "HARDCODED_SECRETS" for f in excluded.findings)

    def test_default_scan_unchanged_without_exclude(self, tmp_path):
        from mcpfrisk.core.runner import run_static_scan

        (tmp_path / "srv.py").write_text(
            "API_KEY = 'sk-proj-abc123def456ghi789jklmnopqrstuvwxyz0123456789'\n",
            encoding="utf-8",
        )
        result = run_static_scan(tmp_path)
        assert any(f.check_id == "HARDCODED_SECRETS" for f in result.findings)
