# Implementation Plan: CI- & Repo-Härtung

**Feature**: 024-ci-repo-hardening | **Constitution-Check**: bestanden (Infra,
kein Check → kein Plugin-/FP-Bezug; Zero-Dep-Kern unberührt).

## Dateien
- `.github/workflows/ci.yml` — umschreiben:
  - `test`-Job: `runs-on: ${{ matrix.os }}`, Matrix (ubuntu 3.10/3.11/3.12 +
    include windows/macos 3.12), `fail-fast: false`, `defaults.run.shell: bash`.
  - Neuer Schritt „self-scan our own source": `mcpfrisk scan mcpfrisk/ --fail-on medium`.
  - Neuer Job `supply-chain`: `pip install -e ".[jsts]" pip-audit` → `pip-audit`.
  - Alle `uses:` SHA-pinnen (checkout, setup-python).
- `.github/dependabot.yml` — NEU (pip + github-actions, weekly).
- `.github/workflows/codeql.yml` — NEU, `on: workflow_dispatch` (dormant),
  SHA-gepinnte codeql-action init/analyze, `languages: python`.
- `action.yml` — setup-python + codeql-action/upload-sarif SHA-pinnen.
- `ROADMAP.md` — 1.1–1.4 abhaken.

## Risiken / Absicherung
- **Windows-Portabilität der Dogfood-Schritte**: `defaults.run.shell: bash`
  löst das (Git-Bash auf Windows-Runner). Lokale Suite auf Windows ist grün.
- **pip-audit-Blocking**: bewusst blockierend (Sinn der Sache). Scope auf
  `.[jsts]` statt `.[dev]` hält die Fläche klein.
- **CodeQL rot auf privatem Repo**: durch `workflow_dispatch`-Dormanz vermieden.
- **Falscher SHA bricht alle Jobs**: SHAs autoritativ via `gh api` verifiziert
  (Typ commit, Tag-Objekt dereferenziert).
- Lokale Validierung: YAML-Parse-Check aller Workflows vor Commit.
