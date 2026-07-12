# Tasks: FALSE_ERROR_ESCALATION (020-false-error-escalation)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): erst Tests + Fixtures (rot), dann Check (grün).
**Status: IMPLEMENTIERT (2026-07-12). Volle Suite 301/301, Selbst-FP-Gegenprobe bestanden (nur die vuln-Fixture triggert).**

## Phase 1 — Tests + Fixtures zuerst (rot)

- [x] **T001** `tests/fixtures/jsts/escalation_vuln.ts` + `escalation_clean.ts`.
- [x] **T002** `tests/test_false_error_escalation.py` (rot): US1 (Python
  Eskalation→MEDIUM, neutral→0), US2 (JS/TS paired), US3 (neutrale Sicherheits-
  texte→0, Verb-/Objekt-allein→0, unparsebar→0), Regression + Dogfood-Erwartung.

## Phase 2 — Check + Registry

- [x] **T003** `mcpfrisk/checks/false_error_escalation.py`: Muster-Familie
  (disable-safety, approve-all, grant-elevated, re-run-elevated,
  proceed-to-escalate), jede Verb+Objekt-kombiniert; `run` über
  `string_literals()`, Dedup je (Datei, Zeile, String) → MEDIUM (MCP01/CWE-441).
  `applies_to` = Quelldateien vorhanden.
- [x] **T004** Registrierung in `checks/registry.py` (`STATIC_CHECKS`);
  Integrationstest-Set (`test_all_static_checks_actually_run`) um den Check
  ergänzt.

## Phase 3 — Polish & Verifikation

- [x] **T005** Volle Suite grün (`pytest -q`); Dogfood `mcpfrisk scan .` auf das
  eigene Repo für FALSE_ERROR_ESCALATION befundfrei (Selbst-FP-Gegenprobe); keine
  Regression; dependency-frei.
- [x] **T006** Doku: README (Tier-1-Tabelle + Badge 11 statisch), CONTEXT.md,
  `.specify/feature.json`, commit + push, CI (Nutzer prüft manuell).

## Constitution-Leitplanke (alle Tasks)

stdlib-only (`re`); KEINE Check-zu-Check-Abhängigkeit (kein Import aus
tool_poisoning); doppeltes Signal (Verb UND Objekt im kurzen Fenster) → neutrale
Fehlertexte nie; unparsebar sauber übersprungen, nie Crash, nie „sicher"; Finding
nennt konkreten Text + Datei/Zeile; paired vuln/clean über Python UND JS/TS;
Selbst-FP-Gegenprobe am eigenen Repo; neue Dateien + ein Registry-Eintrag.
