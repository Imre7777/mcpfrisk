# Tasks: Cross-Function-Taint (012-cross-function-taint)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): erst Fixtures + Tests (rot), dann Erweiterung (grün).
**Status: IMPLEMENTIERT (2026-07-05). Volle Suite 193/193, keine Regression.**

## Phase 1 — Fixtures & Tests zuerst (rot)

- [x] **T001** Fixtures: `tests/fixtures/crossfn_vuln.py` (positional + keyword
  Fluss zum Sink, Helper-Param NICHT pfad-artig), `tests/fixtures/
  crossfn_clean.py` (Helper validiert), plus `tests/fixtures/jsts/
  crossfn_vuln.ts` + `crossfn_clean.ts` (benannte Helfer, positional).
- [x] **T002** `tests/test_path_traversal_crossfn.py` (rot): US1 (positional,
  Py+JS/TS), US2 (keyword, Python), US3 (kein Taint → 0, Dedup, zwei Ebenen →
  0), Regression (bestehende PATH_TRAVERSAL-Fälle unverändert).

## Phase 2 — Cross-Function-Pass

- [x] **T003** `path_traversal.py`: `_scan_function` um `seed_tainted`-Param
  erweitern (intra unverändert); `run()` um einen zweiten Pass ergänzen:
  `name→FunctionDef`-Map, Taint an Helper-Params binden (positional +
  keyword), Helper-Sink über die geteilte Logik prüfen, Validierung
  unterdrücken, Dedup nach Sink-Fundstelle, eigener Fluss-Finding-Text.

## Phase 3 — Polish & Verifikation

- [x] **T004** Volle Suite grün (`pytest -q`); keine Regression (bestehende
  PATH_TRAVERSAL-/JS-TS-/finding-precision-Tests unverändert); Basis-Install
  bleibt dependency-frei.
- [x] **T005** Doku: README "Known limitations" (Taint jetzt eine
  Funktionsebene tief, intra-repo/intra-modul; Grenzen: kein Cross-Module,
  eine Ebene, keine Arrow-Const-Helper), CONTEXT.md (Roadmap/Lessons),
  `.specify/feature.json`, commit + push, CI grün.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; KEINE Port-/Fremd-Check-Änderung (nur `path_traversal.py`);
Finding nur bei konkretem Fluss zum Sink ohne Helper-Validierung (Datei:Zeile
als Beleg); Dedup gegen Doppelmeldung; validierender Helper → kein Finding
(FP-arm); eine Ebene tief (dokumentierte Grenze); paired vulnerable/clean
Fixtures über Python UND JS/TS.
