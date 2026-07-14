# Tasks: Scan-Exclusions

Strikt TDD (rot → grün), ein Commit fürs Feature.

- **T001** `tests/test_scan_exclusions.py` (rot): `is_excluded` (Default-Dir,
  Verzeichnis-Muster `tests/`, Glob `*.min.js`, verschachteltes `**/fixtures`,
  Einzeldatei-Ziel), `load_ignore_patterns` (Kommentare/Leerzeilen/Whitespace),
  `exclude_context` (setzt/resettet), FR4 Default unverändert,
  `--exclude`/`.mcpfriskignore` End-to-End über `run_static_scan`.
- **T002** `core/fs.py`: `load_ignore_patterns`, `is_excluded`, `_ignore_context`
  ContextVar + `exclude_context`, `iter_source_files` auf `is_excluded` umstellen.
- **T003** 5 Direkt-Globber (`hardcoded_secrets`, `typosquat`, `dependency_scan`,
  `mcp_config_audit`, `package_provenance`) → `is_excluded(path, target_path)`.
- **T004** `run_static_scan(exclude=())` betritt `exclude_context`; `cli.py`
  `--exclude` (append) + `_run_scan`-Durchreichung.
- **T005** Volle Suite grün, ruff clean, README-Abschnitt + `.mcpfriskignore`-
  Beispiel, Commit + Push.

## Match-Semantik (Referenz, gitignore-Subset)
Für Muster `p` gegen den zu `root` relativen POSIX-Pfad `rel` (Komponenten `parts`):
- Komponente ∈ `DEFAULT_EXCLUDED_DIRS` → excluded (immer).
- `p` endet auf `/` → `p[:-1] in parts` (Verzeichnis-Präfix).
- `p` enthält `/` → `fnmatch(rel, p)` oder `fnmatch(rel, p + "/*")`.
- sonst → `p in parts` oder `fnmatch(basename, p)`.
`**/x` wird über die letzten beiden Regeln durch `fnmatch` mit abgedeckt.
