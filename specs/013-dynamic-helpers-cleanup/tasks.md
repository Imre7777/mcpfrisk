# Tasks: Dynamic-Helpers-Cleanup (013)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

**Status: VORBEREITET — nur Docs geschrieben. Implementierung nach dem
Kontext-Reset. Reines Refactoring (verhaltensneutral) + Doku-Korrektur.**

## Phase 0 — Vorab-Check (vor jeder Code-Änderung)

- [ ] **T001** `grep -rn "_find_leak\|_READ_HINTS\|_MUTATE_HINTS\|_LEAK_PATTERNS
  \|_is_read_tool\|_properties\|_required\|_truncate" tests/` — feststellen, ob
  ein bestehender Test ein privates Symbol direkt importiert (dann in T004
  Import nachziehen). Aktueller Baseline-Stand: volle Suite grün (193).

## Phase 1 — Contract-Test zuerst (rot)

- [ ] **T002** `tests/test_dynamic_helpers.py` (rot): `is_read_tool`
  (get→True, delete→False), `find_leak` (Traceback→Treffer, harmlos→None),
  `tool_properties`/`tool_required` gegen ein Beispiel-`inputSchema`; plus
  Nachweis, dass die vier Checks die Symbole NICHT mehr selbst definieren
  (Identität gegen das gemeinsame Modul bzw. `not hasattr`).

## Phase 2 — Gemeinsames Modul + Umstellung

- [ ] **T003** `mcpfrisk/checks/_dynamic_helpers.py` anlegen: `READ_HINTS`,
  `MUTATE_HINTS`, `is_read_tool`, `tool_properties`, `tool_required`,
  Leak-Marker-Set + `find_leak`, `truncate` — 1:1-Übernahme der bestätigt
  byte-gleichen Symbole. Kein Check-Import, kein `BaseCheck`.
- [ ] **T004** `schema_fuzzing.py`, `error_leakage.py`, `rbac_cross_tenant.py`,
  `rate_limiting.py` auf Importe aus `_dynamic_helpers` umstellen; lokale
  Duplikate entfernen; ggf. Test-Importe (aus T001) nachziehen.

## Phase 3 — Verifikation + Doku

- [ ] **T005** Volle Suite grün (`pytest -q`), OHNE geänderte Test-
  Erwartungen (reiner Refactor); Finding-Ausgaben aller vier Checks
  unverändert (Dogfood-Stichprobe).
- [ ] **T006** `MARKET-RESEARCH.md` korrigieren: §5-Tabelle (JS/TS-Abdeckung
  = alle Checks; Regelanzahl 5 statisch + 6 dynamisch; Baseline/SARIF/Action
  vorhanden; Cross-Function-Taint eine Ebene vorhanden) + §6/§7 erledigte
  Punkte markieren (offene: eigenes Benchmark, Tier 3, bleiben).
- [ ] **T007** CONTEXT.md-Architektur (kurzer Hinweis auf `_dynamic_helpers.py`
  als geteilter Nicht-Check-Helfer, Präzedenz `_ssrf_callback.py`),
  `.specify/feature.json`, commit + push, CI grün.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; gemeinsames Modul ist check-AGNOSTISCH (kein `BaseCheck`, kein
Check-Import) → Plugin-Isolation gewahrt (Präzedenz `_ssrf_callback.py`);
verhaltensneutral (bestehende Suite bleibt unverändert grün, KEINE geänderten
Erwartungen); byte-gleicher 1:1-Move (kein Merge-Risiko); KEINE funktionale
Erweiterung (reiner Umzug); MARKET-RESEARCH.md-Korrektur nur Fakten, keine
Strategie-Umschreibung.
