# Tasks: TOOL_NAME_COLLISION (011-tool-name-collision)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): erst Fixtures + Tests (rot), dann Check (grün).
**Status: IMPLEMENTIERT (2026-07-05). Alle Phasen grün, volle Suite 185/185, keine Regression.**

## Phase 1 — Fixtures & Tests zuerst (rot)

- [x] **T001** Fixtures: `tests/fixtures/collision_vuln.py` (exaktes Duplikat +
  Near-Duplicate-Paar), `tests/fixtures/collision_clean.py` (eindeutige Namen,
  inkl. gemeinsames-Wort-aber-verschieden), plus JS/TS-Pendants unter
  `tests/fixtures/jsts/`.
- [x] **T002** `tests/test_tool_name_collision.py` (rot): US1 (exakt, Py+JS/TS),
  US2 (near-duplicate), US3 (kein Tool / eindeutig / gemeinsames Wort),
  FR-005 (keine Doppelmeldung), Regression (bestehende Fixtures kollisionsfrei).

## Phase 2 — Check

- [x] **T003** `mcpfrisk/checks/tool_name_collision.py`: `tool_definitions()`
  über alle Dateien aggregieren; exakte Duplikate → MEDIUM, near-duplicate →
  LOW; konservative Near-Duplicate-Heuristik (Normalisierung / Edit-Distanz 1 /
  Präfix); jede Paarung genau einmal; eigene stdlib-Edit-Distanz.
- [x] **T004** Registrierung in `checks/registry.py` (`STATIC_CHECKS`).

## Phase 3 — Polish & Verifikation

- [x] **T005** Volle Suite grün (`pytest -q`); keine Regression (bestehende
  Finding-Zahlen stabil); Basis-Install bleibt dependency-frei.
- [x] **T006** Doku: README (Tier-1-Check-Tabelle + Kurzbeschreibung),
  CONTEXT.md (Check-Tabelle/Roadmap), `.specify/feature.json`, commit + push,
  CI grün.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; keine Port-/Core-Änderung; Finding nur bei konkreter Kollision
mit beiden Fundstellen (Datei:Zeile) als Beleg; konservative Near-Duplicate-
Heuristik (FP-arm, Prinzip III/V); Intra-Repo-Scope transparent (kein
Cross-Server-Anspruch); paired vulnerable/clean Fixtures über Python UND JS/TS;
neue Datei + ein Registry-Eintrag (Plugin-Isolation).
