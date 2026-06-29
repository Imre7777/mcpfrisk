# Implementation Plan: Befund-Präzision (004-finding-precision)

**Spec**: [`spec.md`](./spec.md) | **Status**: Ready

## Technical Context

Rein statische (Tier 1) Verbesserung über dem bestehenden `SourceModel`-Port.
Kein neues Modul, keine neue Abhängigkeit (Prinzip IV). Drei chirurgische
Eingriffe in vorhandene Use-Cases plus eine kleine, von beiden Adaptern geteilte
Snippet-Hilfsfunktion.

- **Sprache/Runtime**: Python 3.10+ (stdlib `ast`), optionales `jsts`/tree-sitter.
- **Betroffene Dateien**:
  - `mcpfrisk/checks/command_injection.py` — Severity-Kalibrierung (US1).
  - `mcpfrisk/core/sourcetree/model.py` — `condense_snippet()`-Helfer (US2).
  - `mcpfrisk/core/sourcetree/python_ast.py` — mehrzeilen-Snippet für Calls (US2).
  - `mcpfrisk/core/sourcetree/treesitter.py` — mehrzeilen-Snippet für Calls (US2).
  - `mcpfrisk/checks/path_traversal.py` — Modul-Validator-Erkennung + Hinweis (US3).
- **Neue Fixtures/Tests**: `tests/fixtures/precision/*`, `tests/test_finding_precision.py`.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Tests werden zuerst geschrieben und rot bestätigt, dann implementiert. |
| II. Plugin Isolation | ✅ | Keine Check-übergreifende Kopplung; CMD/PATH bleiben isoliert. `condense_snippet` ist Infrastruktur (sourcetree), kein Check. |
| III. FP over FN | ✅ **kritisch** | Kein Finding wird unterdrückt. US1 stuft CRITICAL→MEDIUM (bleibt sichtbar). US3 fügt nur Kontext hinzu. Keine Pfad-Excludes. |
| IV. Zero Unnecessary Deps | ✅ | stdlib-only; `ast.end_lineno`/tree-sitter `end_point` reichen. |
| V. Evidence-Grounded | ✅ | US2 verbessert Snippets; Severity folgt der Rubrik (Array+shell=True = Best-Practice-Verstoß = MEDIUM). |
| VI. Paired Fixture Testing (NON-NEGOTIABLE) | ✅ | Jede US bekommt verwundbar **und** sauber/gegenprobe (z.B. interpolierter Befehl bleibt CRITICAL; Modul ohne Validator bekommt keinen Hinweis). |
| VII. Security-Research Currency | ✅ (n/a) | Keine neue Schwachstellenklasse; Kalibrierung bestehender Checks. Kein neuer Research-Pass nötig. |

**Gate-Ergebnis: PASS.** Keine Einträge in Complexity Tracking nötig.

## Approach per User Story

### US1 — Severity-Kalibrierung (`command_injection.py::_assess`, Python-Zweig)

Aktuell fällt `first.is_array` + `shell=True` durch in den CRITICAL-Default. Neue
Reihenfolge:

```text
if first.is_array:
    if not shell_true: return None            # sichere Standardform
    return MEDIUM ("Argument-Liste mit redundantem shell=True; kein interpolierter
                   Befehl -> Best-Practice-Verstoß, kein direkter Injection-Pfad.")
if shell_true:
    if first.is_constant_string: return MEDIUM
    return CRITICAL                            # interpolierter Befehl -> unverändert
...
```

Nur der Array-Pfad ändert sich; der interpolierte Pfad bleibt CRITICAL (FR-002).

### US2 — Mehrzeilen-Snippets (`model.py` + beide Adapter)

- Neuer reiner Helfer in `model.py`:
  `condense_snippet(text, max_len=200) -> str` = `" ".join(text.split())`, bei
  Überlänge auf `max_len-1` + `…` gekürzt.
- `python_ast.py::_call`: Snippet aus `ast.get_source_segment(node)` (voller
  Aufruf) durch `condense_snippet` jagen; Fallback auf bisherige Zeile, wenn das
  Segment leer ist.
- `treesitter.py::_call`: Snippet aus `self._text(node)` (voller Call-Knoten)
  durch `condense_snippet`.
- **Scope-Disziplin**: Nur `_call`-Snippets ändern sich. Assignment-/String-
  Snippets (und damit die Secret-Redaction in `HARDCODED_SECRETS`) bleiben
  unangetastet (FR-006).

### US3 — Modul-Validator-Hinweis (`path_traversal.py`)

- `run()` berechnet pro Modell einmalig die Liste der „Validator"-Funktionsnamen:
  Funktionen, deren *kommentar-bereinigter* Körper einen `SAFE_VALIDATION_HINTS`
  enthält.
- `_scan_function(..., validators)`: beim Erzeugen eines Findings werden Validator-
  Namen ≠ aktuelle Funktion gesammelt; sind welche da, hängt `_make_finding` einen
  Hinweis an die Beschreibung (Name + „falls Pfad vorab geprüft wird, evtl. FP —
  bitte verifizieren"). Severity bleibt HIGH.

## Test Strategy (TDD, Prinzip I & VI)

Neue Datei `tests/test_finding_precision.py` mit je verwundbar+sauber/gegenprobe:

- US1: `array+shell=True -> MEDIUM`; `f-string+shell=True -> CRITICAL`; `list ohne
  shell -> kein Finding`.
- US2: mehrzeiliger Call -> Snippet enthält Callee+Arg, einzeilig, gedeckelt;
  einzeiliger Call -> unverändert nutzbar. JS/TS-Variante via `requires_jsts`-Skip.
- US3: Modul mit separater `validatePath` -> Finding + Hinweis; Modul ohne ->
  Finding ohne Hinweis; clean_server -> kein Finding.

Fixtures unter `tests/fixtures/precision/`. Reihenfolge: Tests schreiben → rot
bestätigen → implementieren → grün → volle Suite (68+) grün → Gegenprobe via
echtem Repo-Scan (python-sdk: MEDIUM statt CRITICAL).
