# Tasks: DEPENDENCY_SCAN (019-dependency-scan)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): erst Tests (rot) gegen Canned-osv-Report, dann Check (grün).
**Status: IMPLEMENTIERT (2026-07-12). Volle Suite 290/290, keine Regression.**

## Phase 1 — Tests zuerst (rot)

- [x] **T001** `tests/test_dependency_scan.py` (rot): `_severity_from`-Tabelle;
  US1 (Canned-Report mit Vuln→Finding, ohne→0); US2 (mehrere Vulns/Pakete,
  dedup); US3 (Runner unavailable→applies_to False, Runner-Fehler→INFO,
  malformt→INFO, kein Crash). Fake-Runner injiziert.

## Phase 2 — Check + Registry

- [x] **T002** `mcpfrisk/checks/dependency_scan.py`: `ToolRunner`-Port +
  `_OsvScannerRunner` (shutil.which + subprocess, Exit 0/1 = ok) + reine
  `_translate`/`_severity_from` + `DependencyScanCheck(runner=None)` mit
  `applies_to` (Manifest vorhanden UND Runner verfügbar) und `run` (nie werfen;
  Tool-Fehler → INFO).
- [x] **T003** Registrierung in `checks/registry.py` (`STATIC_CHECKS`).

## Phase 3 — Polish & Verifikation

- [x] **T004** Volle Suite grün (`pytest -q`); Integrationstest unverändert
  (ohne Tool/Manifest „skipped"); keine Regression; Basis-Install dependency-frei.
- [x] **T005** Doku: README (Tier-1-Tabelle + Badge 10 statisch + osv-scanner-
  Installationshinweis), CONTEXT.md, `.specify/feature.json`, commit + push, CI
  (Nutzer prüft manuell).

## Constitution-Leitplanke (alle Tasks)

Basis-Install stdlib-only (`subprocess`/`shutil`/`json`); osv-scanner optionale
externe Laufzeit-Voraussetzung, kein Python-Dependency; KEINE Check-zu-Check-
Abhängigkeit; DI-Runner (offline testbar); nie werfen, nie stiller Clean (Tool
fehlt → skipped, Tool-Fehler/malformt → INFO); Exit-Code 1 = Vulns (kein Fehler);
Severity aus CVSS/Label, unbekannt → MEDIUM; Finding nennt Paket+Version+ID+Fix+
Referenzen; paired vuln/clean/degradation; neue Datei + ein Registry-Eintrag.
