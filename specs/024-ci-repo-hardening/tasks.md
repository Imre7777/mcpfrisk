# Tasks: CI- & Repo-Härtung

Infra (kein pytest-Rot/Grün) — Verifikation über lokale Suite + YAML-Parse + CI.

- **T001** Spec-Kit docs (spec/plan/tasks). ✅
- **T002** `ci.yml`: OS-Matrix + `fail-fast:false` + `defaults.run.shell: bash`
  im `test`-Job; Self-Scan-Schritt `mcpfrisk scan mcpfrisk/ --fail-on medium`;
  alle `uses:` SHA-gepinnt (checkout, setup-python) in allen Jobs.
- **T003** Neuer `supply-chain`-Job (pip-audit); `.github/dependabot.yml`
  (pip + github-actions); `.github/workflows/codeql.yml` dormant
  (`workflow_dispatch`, SHA-gepinnt).
- **T004** `action.yml` SHA-pinnen; ROADMAP 1.1–1.4 abhaken; alle YAML lokal
  parsen; Commit + Push.

## Verifikation
- `python -c "import yaml; yaml.safe_load(...)"` für jede Workflow-Datei.
- `mcpfrisk scan mcpfrisk/ --fail-on medium` lokal grün.
- Volle pytest-Suite lokal grün (Windows).
