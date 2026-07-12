# Tasks: PACKAGE_PROVENANCE (021-package-provenance)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): erst Tests (rot) gegen Canned-Report, dann Check (grün).
**Status: IMPLEMENTIERT (2026-07-12). Volle Suite 313/313, keine Regression.**

## Phase 1 — Tests zuerst (rot)

- [x] **T001** `tests/test_package_provenance.py` (rot): US1 (invalid→HIGH,
  sauber→0), US2 (missing→LOW, kombiniert dedup), US3 (unavailable/keine Lockfile
  →applies_to False, Tool-Fehler→INFO, malformt→INFO, kein Crash). Fake-Runner.

## Phase 2 — Check + Registry

- [x] **T002** `mcpfrisk/checks/package_provenance.py`: `ToolRunner`-Port +
  `_NpmSignaturesRunner` (shutil.which npm + subprocess) + reine `_translate`
  (invalid→HIGH/CWE-347, missing→LOW; fehlende Provenance NIE) +
  `PackageProvenanceCheck(runner=None)` mit `applies_to` (npm verfügbar UND
  Lockfile) und `run` (nie werfen; Tool-Fehler→INFO).
- [x] **T003** Registrierung in `checks/registry.py` (`STATIC_CHECKS`).

## Phase 3 — Polish & Verifikation

- [x] **T004** Volle Suite grün; Integrationstest unverändert (gated); keine
  Regression; Basis-Install dependency-frei.
- [x] **T005** Doku: README (Tier-1-Tabelle + Badge 12 statisch), CONTEXT.md,
  `.specify/feature.json`, commit + push, CI (Nutzer prüft manuell).

## Constitution-Leitplanke (alle Tasks)

Basis-Install stdlib-only; npm optionale externe Laufzeit-Voraussetzung; KEINE
Check-zu-Check-Abhängigkeit; DI-Runner (offline testbar); nie werfen, nie stiller
Clean (npm/Lockfile fehlt → skipped, Tool-Fehler/malformt → INFO); fehlende
Provenance NIE geflaggt (FP-Disziplin); invalid → HIGH/CWE-347, missing → LOW;
Finding nennt Paket+Version+Status; paired vuln/clean/degradation; neue Datei +
ein Registry-Eintrag.
