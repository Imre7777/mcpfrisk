# Tasks: Befund-Präzision (004-finding-precision)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

Reihenfolge folgt TDD (Prinzip I): pro Phase erst Tests (rot), dann
Implementierung (grün). `[P]` = parallelisierbar (andere Datei, keine Abhängigkeit).

## Phase 0 — Setup

- [x] **T001** Fixture-Verzeichnis `tests/fixtures/precision/` anlegen.
- [x] **T002** Testdatei `tests/test_finding_precision.py` mit `requires_jsts`-Skip-Helfer
  und Imports anlegen.

## Phase 1 — US1: Severity-Kalibrierung (P1)

- [x] **T003** Test (rot): `subprocess.run([cmd], shell=True)` → genau 1 CMD_INJECTION,
  Severity **MEDIUM**.
- [x] **T004** Test (rot/gegenprobe): `subprocess.run(f"git {x}", shell=True)` → **CRITICAL**;
  `subprocess.run(['ls','-la'])` → kein Finding.
- [x] **T005** Implementierung: `command_injection.py::_assess` Array+`shell=True` → MEDIUM,
  ohne den interpolierten CRITICAL-Pfad zu berühren.

## Phase 2 — US2: Mehrzeilen-Snippets (P2)

- [x] **T006** Test (rot): mehrzeiliger gefährlicher Aufruf → Snippet enthält Callee
  und interpoliertes Argument, einzeilig (kein `\n`), gedeckelt mit `…` bei Überlänge.
- [x] **T007** [P] Implementierung: `condense_snippet()` in `core/sourcetree/model.py`.
- [x] **T008** Implementierung: `python_ast.py::_call` nutzt vollen Knoten-Source + condense.
- [x] **T009** [P] Implementierung: `treesitter.py::_call` nutzt vollen Knoten-Text + condense.

## Phase 3 — US3: Triage-Kontext PATH_TRAVERSAL (P3)

- [x] **T010** Test (rot): Modul mit separater `validatePath()` + tainted-Öffner →
  Finding (HIGH) + Hinweis inkl. Funktionsname.
- [x] **T011** Test (gegenprobe): Modul ohne Validator → Finding ohne Hinweis;
  `clean_server.py` → kein Finding.
- [x] **T012** Implementierung: `path_traversal.py` Modul-Validator-Erkennung +
  Hinweis in `_make_finding`; Severity bleibt HIGH, nichts wird unterdrückt.

## Phase 4 — Polish & Verifikation

- [x] **T013** Volle Testsuite grün (`pytest -q`) — keine Regression der bestehenden Tests.
- [x] **T014** Self-Scan (`mcpfrisk scan mcpfrisk`) crasht nicht und bleibt befundfrei.
- [x] **T015** Doku: README („Bekannte Grenzen"/Checks) + `CONTEXT.md` um die
  Severity-Rubrik-Klarstellung und den PATH-Triage-Hinweis ergänzen.

## Constitution-Leitplanke (gilt für alle Tasks)

Kein Finding unterdrücken, keine Pfade ausschließen, Secret-Redaction unangetastet
lassen (Prinzip III, VI + Conservative-excludes). Jede Detektions-Änderung hat ein
verwundbares **und** ein sauberes/gegenproben-Fixture.
