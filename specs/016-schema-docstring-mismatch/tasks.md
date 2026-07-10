# Tasks: SCHEMA_DOCSTRING_MISMATCH (016-schema-docstring-mismatch)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): erst Tests (rot), dann Port-Erweiterung/Check/Registry (grün).
**Status: IMPLEMENTIERT (2026-07-10). Volle Suite 242/242, keine Regression.**

## Phase 1 — Tests zuerst (rot)

- [x] **T001** `tests/test_schema_docstring_mismatch.py` (rot): Port-Parameter
  (Python-Signatur ohne `self`/`ctx`; JS/TS-Schema-Keys), US1 (Python: sensibel
  undokumentiert → HIGH, dokumentiert → 0, nur nicht-sensibel → 0), US2 (JS/TS
  beide Aufruf-Formen), US3 (kein Schema → 0, `ok=False` übersprungen, `self`/
  `ctx` nie, leere Beschreibung + sensibel → 1), Regression.

## Phase 2 — Port-Erweiterung + Check + Registry

- [x] **T002** `mcpfrisk/core/sourcetree/model.py`: `ToolDefinition.parameters:
  list[str] = field(default_factory=list)` (additiv, Default `[]`).
- [x] **T003** `mcpfrisk/core/sourcetree/python_ast.py`: `tool_definitions()`
  füllt `parameters` aus `node.args.args + node.args.kwonlyargs`, filtert
  `self`/`cls`/`ctx`/`context`.
- [x] **T004** `mcpfrisk/core/sourcetree/treesitter.py`: `tool_definitions()`
  füllt `parameters` aus dem Schema-/`inputSchema`-Objekt (Top-Level-Keys,
  Metadaten-Keys ausgenommen).
- [x] **T005** `mcpfrisk/checks/schema_docstring_mismatch.py`: `applies_to` =
  Quelldateien vorhanden; `run` = je Tool sensible, in der Beschreibung nicht
  erwähnte Parameter → HIGH (MCP04/CWE-213) mit Tool + Parameter + Re-Doku/
  Entfernen-Hinweis. Token-tolerantes "erwähnt".
- [x] **T006** Registrierung in `checks/registry.py` (`STATIC_CHECKS`).

## Phase 3 — Polish & Verifikation

- [x] **T007** Volle Suite grün (`pytest -q`); Integrationstest
  `test_all_static_checks_actually_run` um den neuen Check ergänzt (falls er die
  Liste hart prüft); keine Regression; `tool_baseline`-Round-Trip unverändert;
  dependency-frei.
- [x] **T008** Doku: README (Check-Tabelle + Kurzbeschreibung), CONTEXT.md,
  Dogfood-Stichprobe, `.specify/feature.json`, commit + push, CI (Nutzer prüft
  manuell).

## Constitution-Leitplanke (alle Tasks)

stdlib-only (`re`); KEINE Check-zu-Check-Abhängigkeit; additive/rückwärts-
kompatible Port-Erweiterung (Default `[]`); doppeltes Signal (sensibel UND
undokumentiert), nicht-sensible/injizierte Parameter nie geflaggt; token-
tolerantes "erwähnt" (kein FP bei anderer Schreibweise); nicht-parsebare Datei
sauber übersprungen, nie Crash, nie „sicher"; Finding nennt Tool + konkreten
Parameter-Beleg; paired vuln/clean Fixtures über Python UND JS/TS; neue Datei +
ein Registry-Eintrag.
