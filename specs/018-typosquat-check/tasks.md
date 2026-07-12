# Tasks: TYPOSQUAT_CHECK (018-typosquat-check)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): erst Tests (rot), dann Helfer/Check/Registry (grün).
**Status: IMPLEMENTIERT (2026-07-12). Volle Suite 275/275, keine Regression.**

## Phase 1 — Tests zuerst (rot)

- [x] **T001** `tests/test_typosquat.py` (rot): `damerau_le_1`-Einheitentests;
  US1 (npm typosquat→MEDIUM, exakt→0), US2 (PyPI Damerau→MEDIUM, korrekt→0),
  US3 (unverwandt→0, kein Manifest→[], malformt→0), pyproject (tomllib-gated),
  Regression.

## Phase 2 — Helfer + Check + Registry

- [x] **T002** `mcpfrisk/checks/_name_similarity.py`: `damerau_le_1(a, b)`
  (Levenshtein-≤1 + Adjazenz-Vertauschung), geteilter Nicht-Check-Helfer.
- [x] **T003** `mcpfrisk/checks/typosquat.py`: kuratierte npm/PyPI-Allowlists
  (mit Refresh-Hinweis), Manifest-Parser (`package.json`/`requirements.txt`/
  `pyproject.toml` best-effort via `tomllib`), Normalisierung (npm lowercase /
  PyPI PEP 503), Vergleich (nicht exakt UND Damerau ≤ 1, Mindestlänge 5,
  ökosystem-getrennt) → MEDIUM (MCP04/CWE-829). `applies_to` = Manifest vorhanden.
- [x] **T004** Registrierung in `checks/registry.py` (`STATIC_CHECKS`).

## Phase 3 — Polish & Verifikation

- [x] **T005** Volle Suite grün (`pytest -q`); Integrationstest unverändert
  (ohne Manifest „skipped"); keine Regression; dependency-frei.
- [x] **T006** Doku: README (Tier-1-Tabelle + Badge 9 statisch), CONTEXT.md,
  Dogfood-Stichprobe, `.specify/feature.json`, commit + push, CI (Nutzer prüft
  manuell).

## Constitution-Leitplanke (alle Tasks)

stdlib-only (`json`/`re`/optional `tomllib`); KEINE Check-zu-Check-Abhängigkeit
(Distanz-Helfer im geteilten `_name_similarity.py`); kuratierte Allowlist als
FP-Bremse; doppeltes Signal (nah UND ≠); Mindestlänge 5; ökosystem-getrennt;
PEP-503-/lowercase-Normalisierung; malformtes/fehlendes Manifest sauber
übersprungen, nie Crash, nie „sicher"; Finding nennt Kandidat + ähnliches
bekanntes Paket + Datei; paired vuln/clean Fixtures über npm UND PyPI; neue
Dateien + ein Registry-Eintrag.
