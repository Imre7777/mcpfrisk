# Tasks: CI-Integration (010-ci-integration)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): pro Phase erst Tests, dann Implementierung (grün).
**Status: IMPLEMENTIERT (2026-07-02). Alle Phasen grün, volle Suite ohne
Regression.**

## Phase 1 — Baseline-Diffing

- [x] **T001** `tests/test_baseline.py` (rot): Fingerprint-Stabilität,
  Pfad-Relativierung, Load/Write-Round-Trip, korrupte/fehlende Datei →
  leeres Set, `split_new_vs_known`.
- [x] **T002** `mcpfrisk/core/baseline.py`: `fingerprint()`, `load_baseline()`,
  `write_baseline()`, `split_new_vs_known()`.
- [x] **T003** CLI: `--baseline PATH` + `--write-baseline PATH` für `scan`
  UND `probe`; nur "neue" Findings zählen für `--fail-on`; "bekannte"
  Findings bleiben im Report sichtbar (separat ausgewiesen).

## Phase 2 — SARIF-Output

- [x] **T004** `tests/test_sarif.py` (rot): Schema-Grundstruktur,
  Severity→level-Mapping, physicalLocation, leere Findings-Liste.
- [x] **T005** `mcpfrisk/core/sarif.py`: `write_sarif_report(result, path)`.
- [x] **T006** CLI: `--sarif PATH` für `scan` (nicht `probe` -- siehe
  Entschiedener Design-Punkt in plan.md).

## Phase 3 — GitHub Action

- [x] **T007** `action.yml` (Repo-Root): Composite Action, installiert aus
  `${{ github.action_path }}`, Inputs (`path`, `fail-on`, `skip`,
  `baseline`, `python-version`), SARIF-Upload via
  `github/codeql-action/upload-sarif@v3`, Upload auch bei fehlgeschlagenem
  Scan (`continue-on-error` + expliziter Fail-Step danach).
- [x] **T008** Bestehenden `.github/workflows/ci.yml` optional um einen
  Dogfood-Schritt ergänzen, der die eigene Action gegen die Test-Fixtures
  läuft lässt (Self-Test der Action im eigenen Repo).

## Phase 4 — Polish & Verifikation

- [x] **T009** Volle Suite grün (`pytest -q`); keine Regression.
- [x] **T010** Doku: README (Baseline/SARIF/Action-Nutzung, Beispiele),
  CONTEXT.md (Roadmap-Eintrag), `.specify/feature.json` auf
  `010-ci-integration` zeigen lassen.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; keine Regression; Baseline-Findings bleiben sichtbar (nie
kommentarlos verschwinden); korrupte/fehlende Baseline-Datei → leere
Baseline, kein Crash; SARIF nur für `scan`, Baseline für `scan` UND `probe`;
`action.yml` installiert aus dem eigenen Checkout, kein PyPI-Zwang.
