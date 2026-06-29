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
