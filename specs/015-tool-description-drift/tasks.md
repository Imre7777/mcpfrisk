# Tasks: TOOL_DESCRIPTION_DRIFT (015-tool-description-drift)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): erst Tests (rot), dann Modul/Check/CLI (grün).
**Status: IMPLEMENTIERT (2026-07-05). Volle Suite 227/227, keine Regression.**

## Phase 1 — Tests zuerst (rot)

- [x] **T001** `tests/test_tool_description_drift.py` (rot): US1 (Beschreibung
  geändert → MEDIUM, unverändert → 0, whitespace-only → 0), US2 (neues Tool →
  LOW, gepinntes → 0), US3 (keine Baseline → 0/skipped, malformte Baseline → 0,
  write→Round-Trip), JS/TS-Drift, CLI `--write-tools-baseline`, Regression.

## Phase 2 — Core-Modul + Check + CLI

- [x] **T002** `mcpfrisk/core/tool_baseline.py`: `baseline_path(target)`,
  `snapshot(target) -> dict[name,hash]` (via iter_source_files + analyze +
  tool_definitions, whitespace-normalisierter sha256[:16]), `load(path)`,
  `write(path, snapshot)`, `diff(baseline, current) -> (changed, new)`.
- [x] **T003** `mcpfrisk/checks/tool_description_drift.py`: `applies_to` =
  Baseline existiert; `run` = snapshot vs Baseline diffen → CHANGED (MEDIUM,
  MCP04/CWE-471) + NEW (LOW) Findings mit Tool-Name + aktuellem Beschreibungs-
  Ausschnitt + Re-Pin-Hinweis; malformte Baseline → [].
- [x] **T004** Registrierung in `checks/registry.py` (`STATIC_CHECKS`);
  `cli.py`: `scan --write-tools-baseline` (Pin-Aktion, schreibt Snapshot,
  exit 0, Bestätigung).

## Phase 3 — Polish & Verifikation

- [x] **T005** Volle Suite grün (`pytest -q`); Integrationstest unverändert
  (ohne Baseline ist der Check „skipped"); keine Regression; dependency-frei.
- [x] **T006** Doku: README (Check-Tabelle + Kurzbeschreibung + Pin-Workflow-
  Beispiel), CONTEXT.md, Dogfood-Stichprobe, `.specify/feature.json`,
  commit + push, CI grün.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; KEINE Check-zu-Check-Abhängigkeit; opt-in (ohne gepinnten Baseline
nichts, kein FP); Whitespace-normalisierter Hash (reine Reformatierung ist keine
Drift); malformte/fehlende Baseline sauber übersprungen, nie Crash, nie
„sicher"; Finding nennt Tool + aktuellen Beschreibungs-Beleg; paired
changed/new/clean Fixtures über Python UND JS/TS; ein Pfad-Helfer für Check +
CLI (eine Quelle der Wahrheit); neue Dateien + ein Registry-Eintrag.
