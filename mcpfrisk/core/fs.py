"""Datei-Discovery-Helfer für statische Checks.

`Path.rglob(pattern)` liefert auf einem *Datei*pfad nichts zurück (rglob
iteriert nur Verzeichnisinhalte). Dadurch wurde beim Scan eines einzelnen
Files -- z.B. `mcpfrisk scan server.py` -- fast jeder Check still
übersprungen (`applies_to` war False) bzw. fand nichts. Dieser Helfer
behandelt Datei- und Verzeichnis-Ziele einheitlich, damit die Checks in
beiden Fällen identisch greifen.

Feature 022 ergänzt hier den **Scan-Exclude**: ein zentrales `is_excluded()`
kapselt die Default-Verzeichnisse, eine gitignore-artige `.mcpfriskignore`
und CLI-`--exclude`-Muster (via ContextVar, scan-lokal). Alle Discovery-
Stellen rufen dasselbe Prädikat -- so wirkt ein Nutzer-Ausschluss überall,
statt das frühere `any(part in DEFAULT_EXCLUDED_DIRS ...)`-Idiom sechsfach
zu duplizieren.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from fnmatch import fnmatch
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
# Test-/Example-Ausschluss ist opt-in über .mcpfriskignore / --exclude.
DEFAULT_EXCLUDED_DIRS = frozenset(
    {"node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".git"}
)

# CLI-`--exclude`-Muster, scan-lokal gesetzt (contextvars => thread-/async-sicher
# und automatisch zurückgesetzt). Leeres Tuple = keine zusätzlichen Muster.
_ignore_context: ContextVar[tuple[str, ...]] = ContextVar("_ignore_context", default=())

_IGNORE_FILENAME = ".mcpfriskignore"


@contextmanager
def exclude_context(patterns: tuple[str, ...]):
    """Setzt für die Dauer des Blocks zusätzliche `--exclude`-Muster.

    Wird vom Runner um einen Scan gelegt, damit `is_excluded()` die Muster in
    jedem Check sieht -- ohne die `run(target_path)`-Signatur zu ändern."""
    token = _ignore_context.set(tuple(patterns))
    try:
        yield
    finally:
        _ignore_context.reset(token)


def load_ignore_patterns(root: Path) -> tuple[str, ...]:
    """Liest `root/.mcpfriskignore` (gitignore-Subset).

    Leerzeilen und `#`-Kommentare werden ignoriert, umgebender Whitespace
    getrimmt. Fehlt die Datei (oder ist `root` eine Datei), gibt es keine
    Muster. Negation (`!`) wird in v1 nicht unterstützt -- nur additiver
    Ausschluss."""
    ignore_file = (root if root.is_dir() else root.parent) / _IGNORE_FILENAME
    if not ignore_file.is_file():
        return ()
    patterns: list[str] = []
    for raw in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return tuple(patterns)


def _matches_pattern(rel_posix: str, parts: tuple[str, ...], pattern: str) -> bool:
    """Ein gitignore-Subset-Match gegen den zu `root` relativen Pfad.

    - `pattern` endet auf `/`  -> Verzeichnis-Präfix: irgendeine Komponente == Name.
    - `pattern` enthält `/`     -> fnmatch gegen den ganzen relativen Pfad
      (deckt `**/x` und `dir/*` ab).
    - sonst                     -> Komponenten-Name-Match ODER Basename-Glob.
    """
    if pattern.endswith("/"):
        return pattern[:-1] in parts
    if "/" in pattern:
        return fnmatch(rel_posix, pattern) or fnmatch(rel_posix, pattern + "/*")
    return pattern in parts or (bool(parts) and fnmatch(parts[-1], pattern))


def is_excluded(path: Path, root: Path, *, extra: tuple[str, ...] = ()) -> bool:
    """Soll `path` vom Scan ausgeschlossen werden?

    True, wenn eine Pfad-Komponente in `DEFAULT_EXCLUDED_DIRS` liegt ODER der
    zu `root` relative Pfad auf ein Muster aus `.mcpfriskignore`, `extra` oder
    dem `--exclude`-ContextVar passt. Deterministisch und ohne I/O außer dem
    einmaligen Lesen der Ignore-Datei.
    """
    parts = path.parts
    if any(part in DEFAULT_EXCLUDED_DIRS for part in parts):
        return True

    patterns = extra + _ignore_context.get() + load_ignore_patterns(root)
    if not patterns:
        return False

    try:
        rel = path.relative_to(root)
        rel_parts = rel.parts
    except ValueError:
        rel_parts = parts
    # Einzeldatei-Ziel (path == root): relative_to ergibt ".", keine Komponenten.
    if not rel_parts or rel_parts == (".",):
        rel_parts = (path.name,)
    rel_posix = "/".join(rel_parts)
    return any(_matches_pattern(rel_posix, rel_parts, p) for p in patterns)


def iter_source_files(
    target_path: Path,
    patterns: tuple[str, ...] = SOURCE_GLOBS,
) -> list[Path]:
    """Eindeutige, deterministisch sortierte Quelldateien unter `target_path`.

    Dedupliziert über mehrere Glob-Pattern hinweg und schließt Build-/
    Dependency-Verzeichnisse sowie Nutzer-Ausschlüsse (`.mcpfriskignore` /
    `--exclude`) aus. Sortierte Rückgabe -> stabile Finding-Reihenfolge
    (gleicher Input => gleiche Ausgabe)."""
    seen: set[Path] = set()
    for pattern in patterns:
        for path in rglob_or_file(target_path, pattern):
            if path in seen:
                continue
            if is_excluded(path, target_path):
                continue
            seen.add(path)
    return sorted(seen)
