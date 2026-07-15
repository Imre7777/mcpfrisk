# Feature Specification: CI- & Repo-Härtung (ROADMAP Phase 1)

**Feature Branch**: `024-ci-repo-hardening`

**Created**: 2026-07-15

**Status**: In Implementierung. ROADMAP Phase 1 („Nicht-blamieren"-Härtung, P1) —
Plattform-Nachweis + das Security-Tool muss selbst vorbildlich sein.

## Kontext / Motivation

Reine CI-/Repo-Infrastruktur, kein neuer Check (daher kein pytest-Rot/Grün —
Verifikation über lokale Suite auf Windows + YAML-Validierung + die CI selbst).

**Warum jetzt:** Wir entwickeln auf Windows, behaupten Cross-Platform, testen
aber nur auf `ubuntu-latest`. Ein Pfad-Bug (`\` vs `/`) — besonders im frischen
`is_excluded`/Ignore-Code aus 022 — würde unentdeckt durchrutschen. Und ein
Security-Tool, das seinen eigenen Code scannt, sich gegen Supply-Chain-Advisories
prüft und seine CI-Lieferkette pinnt, ist das stärkste Vertrauenssignal.

## Umfang (ROADMAP 1.1–1.4)

### 1.1 OS-Matrix
`test`-Job auf `ubuntu-latest` (voll: Py 3.10/3.11/3.12) **plus** je ein
`windows-latest` und `macos-latest` (Py 3.12). `fail-fast: false`, damit ein OS
die anderen nicht abbricht. `defaults.run.shell: bash` macht die bestehenden
bash-Dogfood-Schritte portabel (GitHub-Windows-Runner bringen Git-Bash mit).

### 1.2 Self-Scan-Gate (Dogfooding auf echtem Code)
Neuer Schritt `mcpfrisk scan mcpfrisk/ --fail-on medium` im `test`-Job. Zielt
bewusst auf **`mcpfrisk/`** (unseren echten Quellcode) — NICHT auf `.`, weil das
Repo absichtlich verwundbare `tests/fixtures/` enthält. Lokal verifiziert:
`mcpfrisk/` ist bei `--fail-on medium` sauber. Läuft auf allen drei OS und prüft
damit zugleich die Pfad-Behandlung des echten Scans unter Windows.

### 1.3 Supply-Chain-Sicherheit des eigenen Repos
- **pip-audit** als eigener Job: installiert `.[jsts]` (unsere einzige reale
  Laufzeit-Lieferkette: tree-sitter) und auditiert gegen bekannte Advisories.
- **`.github/dependabot.yml`**: wöchentliche Updates für `pip` **und**
  `github-actions` (hält u.a. die gepinnten SHAs aktuell).
- **`.github/workflows/codeql.yml`**: SAST auf unseren Python-Code —
  **dormant** (`workflow_dispatch`), weil das Repo privat **ohne GHAS** ist und
  CodeQL-Code-Scanning dort nicht hochladen kann (würde CI rot machen). Klar
  kommentiert: bei „public" auf `push`/`pull_request` umstellen.

### 1.4 GitHub Actions SHA-pinnen
Alle `uses:` in `ci.yml` und `action.yml` auf den vollen Commit-SHA pinnen
(mit `# vX`-Kommentar), autoritativ via `gh api` aufgelöst:
- `actions/checkout` v4 → `34e114876b0b11c390a56381ad16ebd13914f8d5`
- `actions/setup-python` v5 → `a26af69be951a213d495a4c3e4e4022e16d87065`
- `github/codeql-action` v3 → `02c5e83432fe5497fd85b873b6c9f16a8578e1d9`
Dependabot (github-actions) hält sie fortan aktuell.

## Akzeptanzkriterien
- Lokale Suite auf Windows grün (bereits: 368) — Cross-Platform-CI wird das auf
  Windows/macOS bestätigen.
- Self-Scan-Gate lokal grün (`mcpfrisk scan mcpfrisk/ --fail-on medium`).
- Keine beweglichen Action-Tags mehr in `ci.yml`/`action.yml`.
- Dependabot- und (dormant) CodeQL-Konfig valide.
- CI bleibt grün auf dem privaten Repo (kein CodeQL-Upload-Fehler).

## Nicht-Ziele
- Kein aktives CodeQL vor „public"/GHAS.
- Kein Release-Workflow (Phase 6).
