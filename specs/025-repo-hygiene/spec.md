# Feature Specification: Repo-Hygiene (ROADMAP Phase 2)

**Feature Branch**: `025-repo-hygiene`

**Created**: 2026-07-15

**Status**: In Implementierung. ROADMAP Phase 2 (P1) — Standard-Signale für ein
ernsthaftes Open-Source-Projekt. Reine **statische Dateien**: erzeugen KEINE
PRs/Branches/CI-Läufe (bewusst nach dem Dependabot-Vorfall).

## Kontext / Motivation

Der Code ist reif (19 Checks, 368 Tests, CI grün). Was fehlt, sind die
Community-/Projekt-Dateien, die GitHub unter „Community Standards" prüft und die
Beitragende erwarten. Ohne sie wirkt selbst ein technisch starkes Projekt
unfertig.

## Umfang & Abgrenzung

**Bereits vorhanden (nicht Teil dieses Features):** README-Badges (CI, Python,
License, Core-deps, Checks, OWASP) sind schon im README. LICENSE, SECURITY.md,
CONTRIBUTING.md, CHANGELOG.md existieren.

**Neu (dieses Feature):**
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1, Kontakt = die bereits in
  SECURITY.md/pyproject genannte Maintainer-Mail.
- `.github/ISSUE_TEMPLATE/bug_report.yml` + `feature_request.yml` + `config.yml`
  (GitHub-Issue-Forms; `config.yml` verlinkt Security-Meldungen bewusst NICHT als
  öffentliches Issue, sondern auf den SECURITY.md-Weg).
- `.github/PULL_REQUEST_TEMPLATE.md` — Checkliste entlang der Projekt-Constitution
  (Test-first, gepaarte Fixtures, Spec-Kit, ruff/CI grün).
- `.pre-commit-config.yaml` — ruff (Lint) + Basis-Hooks; Fixtures/Corpus bewusst
  ausgenommen (dort steht absichtlich „kaputter" Sample-Code).
- `CITATION.cff` — maschinenlesbare Zitier-Metadaten.
- `CONTRIBUTING.md` — um pre-commit-Setup + CoC-Verweis ergänzt.

**Nicht-Ziele:** CLI-Demo-GIF/asciinema (braucht Aufnahme-Tooling — später),
`.github/FUNDING.yml` (optional, ausgelassen), Dependabot (bewusst entfernt).

## Akzeptanzkriterien
- GitHub „Community Standards" zeigt CoC, Issue-Templates, PR-Template grün.
- Alle neuen YAML-Dateien parsen lokal fehlerfrei.
- `.pre-commit-config.yaml` nutzt die bestehende ruff-Konfig; Fixtures
  ausgenommen. (Hinweis: `pre-commit run --all-files` erfordert lokal
  installiertes pre-commit; der erste Lauf kann kleinere Whitespace-Fixe
  auto-anwenden — das ist beabsichtigt.)
- `CITATION.cff` valide (CFF 1.2.0).
