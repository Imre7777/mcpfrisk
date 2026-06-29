"""Datei-Discovery-Helfer für statische Checks.

`Path.rglob(pattern)` liefert auf einem *Datei*pfad nichts zurück (rglob
iteriert nur Verzeichnisinhalte). Dadurch wurde beim Scan eines einzelnen
Files -- z.B. `mcpfrisk scan server.py` -- fast jeder Check still
übersprungen (`applies_to` war False) bzw. fand nichts. Dieser Helfer
behandelt Datei- und Verzeichnis-Ziele einheitlich, damit die Checks in
beiden Fällen identisch greifen.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path


def rglob_or_file(target_path: Path, pattern: str) -> Iterator[Path]:
    """Liefert alle zu `pattern` passenden Dateien unter `target_path`.

    - Verzeichnis: rekursiver Glob (wie `target_path.rglob(pattern)`).
    - Einzelne Datei: die Datei selbst, sofern ihr Name auf `pattern` passt
      (genau hier lieferte `rglob` zuvor nichts -- der gefixte Bug).
    """
    if target_path.is_file():
        if target_path.match(pattern):
            yield target_path
        return
    yield from target_path.rglob(pattern)


# Quellcode-Dateitypen, die die AST-fähigen Checks (CMD/PATH/TOOL) betrachten.
SOURCE_GLOBS = (
    "*.py",
    "*.js", "*.mjs", "*.cjs", "*.jsx",
    "*.ts", "*.mts", "*.cts", "*.tsx",
)

# Nur echte Build-/Dependency-Verzeichnisse ausschließen (Lesson Learned:
# keine pauschalen "tests"-Excludes, die echte Findings verschluckt haben).
DEFAULT_EXCLUDED_DIRS = frozenset(
    {"node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".git"}
)


def iter_source_files(
    target_path: Path,
    patterns: tuple[str, ...] = SOURCE_GLOBS,
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
) -> list[Path]:
    """Eindeutige, deterministisch sortierte Quelldateien unter `target_path`.

    Dedupliziert über mehrere Glob-Pattern hinweg und schließt Build-/
    Dependency-Verzeichnisse aus. Sortierte Rückgabe -> stabile Finding-
    Reihenfolge (gleicher Input => gleiche Ausgabe)."""
    seen: set[Path] = set()
    for pattern in patterns:
        for path in rglob_or_file(target_path, pattern):
            if path in seen:
                continue
            if any(part in excluded_dirs for part in path.parts):
                continue
            seen.add(path)
    return sorted(seen)
