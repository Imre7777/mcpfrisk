# Implementation Plan: Repo-Hygiene

**Feature**: 025-repo-hygiene | **Constitution-Check**: n/a (Doku/Config, kein
Check, kein Laufzeit-Code, Zero-Dep-Kern unberührt).

## Dateien
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1, Kontakt imre.obermueller@gmail.com.
- `.github/ISSUE_TEMPLATE/bug_report.yml` — Issue-Form: Version, OS, Python,
  jsts-Extra?, Repro, erwartet/tatsächlich, Scan-Output.
- `.github/ISSUE_TEMPLATE/feature_request.yml` — Problem, Vorschlag, Alternativen.
- `.github/ISSUE_TEMPLATE/config.yml` — `blank_issues_enabled: false`,
  contact_links → Security (SECURITY.md) und Fragen.
- `.github/PULL_REQUEST_TEMPLATE.md` — Was/Warum + Constitution-Checkliste.
- `.pre-commit-config.yaml` — pre-commit-hooks (trailing-whitespace,
  end-of-file-fixer, check-yaml, check-merge-conflict, check-added-large-files)
  mit `exclude: ^(tests/fixtures/|benchmark/corpus/)`; ruff-pre-commit (ruff
  check, nutzt die pyproject-Konfig inkl. Excludes). KEIN ruff-format (würde die
  ganze Codebase umformatieren).
- `CITATION.cff` — CFF 1.2.0, Autor Imre Obermueller, Apache-2.0, Repo-URL, 0.1.0.
- `CONTRIBUTING.md` — Dev-Setup um `pip install pre-commit && pre-commit install`
  ergänzen; CoC verlinken.
- `ROADMAP.md` — Phase 2 abhaken (2.2 Badges bereits vorhanden vermerken).

## Verifikation
- YAML-Parse aller neuen `.yml`/`.yaml` + `CITATION.cff` (`python -c yaml.safe_load`).
- ruff check . bleibt grün (unverändert).
- pre-commit selbst nicht lokal ausführbar (nicht installiert, venv ohne pip) —
  ehrlich im Commit vermerken; Config ist Standard und Fixtures ausgenommen.
