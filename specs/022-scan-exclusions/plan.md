# Implementation Plan: Scan-Exclusions

**Feature**: 022-scan-exclusions | **Constitution-Check**: bestanden.

- **I Test-First**: rote Tests zuerst (`tests/test_scan_exclusions.py`), dann grün.
- **II Plugin-Isolation**: `is_excluded`/Ignore-Parsing leben in `core/fs.py`
  (Nicht-Check-Helfer, wie `rglob_or_file`). Checks importieren nur den Helfer,
  nie einander.
- **III FP-over-FN**: Default unverändert (nur Build/Vendor). Test-Ausschluss
  strikt opt-in → kein stiller Recall-Verlust.
- **IV Zero-Deps**: nur stdlib (`fnmatch`, `pathlib`, `contextvars`).
- **V Evidence-Grounded**: n/a (keine Findings).
- **VI Paired-Fixture-Testing**: Positiv (Muster excludet) + Negativ (ohne
  Muster gescannt) je Mechanismus.

## Architektur

### `core/fs.py` (Erweiterung)
```
_ignore_context: ContextVar[tuple[str, ...]]  # CLI --exclude, scan-lokal

def load_ignore_patterns(root: Path) -> tuple[str, ...]:
    # liest root/.mcpfriskignore; strippt Kommentare (#) + Leerzeilen.
    # Fehlt die Datei → ().

def is_excluded(path: Path, root: Path, *, extra: tuple[str,...] = ()) -> bool:
    # True, wenn:
    #  - eine Pfad-Komponente in DEFAULT_EXCLUDED_DIRS liegt, ODER
    #  - der zu root relative POSIX-Pfad auf ein Muster aus
    #    (load_ignore_patterns(root) + extra + _ignore_context) passt.
    # Match-Semantik pro Muster p (gitignore-Subset):
    #  - p endet auf '/'  → Verzeichnis-Präfix: irgendeine Komponente == p[:-1]
    #  - p enthält '/'    → fnmatch(rel, p) oder fnmatch(rel, p+'/*')
    #  - sonst            → Komponenten-Name-Match ODER fnmatch(basename, p)

@contextmanager
def exclude_context(patterns): ...  # setzt/resettet _ignore_context

def iter_source_files(target, patterns=SOURCE_GLOBS): 
    # nutzt is_excluded statt inline-Set-Check.
```

### `core/runner.py`
`run_static_scan(target, skip_checks=None, exclude=())` → betritt
`exclude_context(exclude)` für die Dauer des Scans. Dynamische Checks unberührt.

### 5 Direkt-Globber
`any(part in DEFAULT_EXCLUDED_DIRS ...)` → `is_excluded(path, target_path)`.
Semantik bleibt identisch, gewinnt aber Datei-/CLI-Muster automatisch.

### `cli.py`
`scan_parser.add_argument("--exclude", action="append", default=[])`;
`_run_scan` reicht `exclude=set(args.exclude)` (→ tuple) an `run_static_scan`.

## Risiken
- **Regressionsgefahr Discovery**: die Konsolidierung darf das Default-Verhalten
  nicht ändern → FR4-Test vergleicht Fund-Anzahl vorher/nachher auf Fixtures.
- **Relativierung bei Einzeldatei-Ziel**: `is_excluded` muss robust sein, wenn
  `path == root` (Einzeldatei-Scan) → `rel = "."`; Defaults greifen weiter.
