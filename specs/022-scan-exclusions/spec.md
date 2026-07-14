# Feature Specification: Scan-Exclusions (`.mcpfriskignore` + `--exclude`)

**Feature Branch**: `022-scan-exclusions`

**Created**: 2026-07-14

**Status**: Design entschieden — in Implementierung. Ergebnis der breiten Real-
World-Validierung (13 echte MCP-Server, 2026-07-14): die dominante verbleibende
False-Positive-Klasse ist Rauschen aus **Test-/Example-/Monorepo-Verzeichnissen**
(v.a. `TOOL_NAME_COLLISION`-Flut über unabhängige SDK-Beispielserver hinweg) und
die **Performance** auf großen Monorepos (python-sdk, 815 Dateien → Timeout).

**Input**: Ein Zielpfad, dessen Nutzer bestimmte Verzeichnisse/Dateien vom Scan
ausnehmen möchte — per committeter Datei **`.mcpfriskignore`** (im Repo-Root,
gitignore-artige Syntax) und/oder per **`--exclude PATTERN`** (CLI, wiederholbar).

## Kontext / Motivation

**Markt-Recherche (Prinzip VII, Stand 2026-07-14):** Jeder ernsthafte Scanner
trennt sauber **zwei** Mechanismen:

1. **Pfad-Ausschluss** (was gar nicht erst gescannt wird) — semgrep
   `.semgrepignore`, eslint `.eslintignore`, ruff `extend-exclude`. Syntax ist
   gitignore-artig; die Ignore-Datei hat Vorrang vor `.gitignore`. Semgrep
   excludet per Default u.a. `node_modules/`, `vendor/`, `dist/`, `build/`,
   `.venv/`, `*.min.js` **und** Test-Verzeichnisse — aber als **überschreibbaren
   Default**, nicht als hartes Ausblenden.
2. **Content-Allowlist/Baseline** (bekannter Fund ist FP) — gitleaks
   `.gitleaks.toml` (paths/regexes/**stopwords**) + Baseline-JSON.

McpFrisk hat (2) bereits: `core/baseline.py` (010) für die Baseline und den
`_PLACEHOLDER_RE`-Stopword-Filter in `HARDCODED_SECRETS` (Real-World-Fix
2026-07-14). Was fehlt, ist (1): der **Pfad-Ausschluss**.

**Bewusste Recall-Entscheidung (Prinzip III, FP-over-FN):** Anders als semgrep
schließen wir Test-/Example-Verzeichnisse **NICHT** per Default aus. Der Default
excludet weiterhin nur echte Build-/Dependency-Verzeichnisse
(`DEFAULT_EXCLUDED_DIRS`: `node_modules`, `.venv`, `venv`, `__pycache__`, `dist`,
`build`, `.git`). Das bewahrt die frühere Lesson-Learned (siehe `core/fs.py`:
pauschale `tests`-Excludes hatten echte Findings verschluckt) und maximiert den
Recall für das Audit. Test-/Example-Ausschluss ist **opt-in** über
`.mcpfriskignore`/`--exclude` — der Nutzer entscheidet bewusst und sichtbar.

**Architektur-Befund:** Das Exclude-Idiom
`any(part in DEFAULT_EXCLUDED_DIRS for part in path.parts)` ist aktuell
**6-fach dupliziert** (in `core/fs.py::iter_source_files` plus den fünf Checks,
die direkt globben: `hardcoded_secrets`, `typosquat`, `dependency_scan`,
`mcp_config_audit`, `package_provenance`). Ein User-Exclude, das nur an einer
Stelle eingebaut würde, erreichte die anderen nicht. Deshalb ist der erste
Schritt eine **Konsolidierung** auf ein zentrales Prädikat `is_excluded()`.

**OWASP/CWE-Mapping:** Kein Finding-Typ — reine Scan-Steuerung. Betrifft
Präzision (weniger FP) und Performance (weniger Dateien).

## User Scenarios

### US1 — `.mcpfriskignore` im Repo-Root (Primärmechanismus)
Ein Nutzer legt eine committete `.mcpfriskignore` an (gitignore-artig: Leerzeilen
und `#`-Kommentare werden ignoriert; Muster wie `tests/`, `examples/`,
`**/fixtures`, `*.min.js`). Beim Scan werden passende Pfade in **allen** Checks
übersprungen. Die Datei wird aus dem Scan-Root gelesen — keine `run()`-
Signaturänderung nötig.

### US2 — `--exclude PATTERN` (CLI, wiederholbar)
`mcpfrisk scan . --exclude tests/ --exclude "*.min.js"` schließt zusätzlich zu
`.mcpfriskignore` diese Muster aus. Nützlich für Ad-hoc-Scans/CI ohne committete
Datei. Muster kombinieren sich additiv mit der Datei und den Defaults.

### US3 — Default-Verhalten unverändert (Recall bewahrt)
Ohne `.mcpfriskignore` und ohne `--exclude` verhält sich der Scan **exakt wie
bisher**: nur `DEFAULT_EXCLUDED_DIRS` werden ausgeschlossen. Test-/Example-Code
wird weiterhin gescannt (kein stiller Recall-Verlust).

## Functional Requirements
- **FR1**: Ein zentrales `is_excluded(path, root)` kapselt Defaults + Datei +
  CLI-Muster; alle 6 Discovery-Stellen nutzen es (keine Duplikation mehr).
- **FR2**: `.mcpfriskignore` wird aus `root` gelesen; gitignore-Subset
  (Kommentare, Leerzeilen, Verzeichnis-Muster `dir/`, Globs `*.ext`, `**/x`).
- **FR3**: `--exclude PATTERN` (append, wiederholbar) reicht via `contextvars`
  bis zu den Checks durch — thread-/scan-lokal, ohne Signaturänderung, auto-reset.
- **FR4**: Default-Verhalten ohne Datei/Flag ist byte-identisch zu vorher.
- **FR5**: Matching ist deterministisch; gleiche Eingabe ⇒ gleiche Ausgabe.

## Nicht-Ziele
- Keine `!`-Negation in v1 (gitignore-Re-Include) — nur additiver Ausschluss.
- Kein Default-Ausschluss von Tests/Examples (bewusste Recall-Entscheidung).
- Keine Änderung an Baseline/Allowlist (existiert bereits).
