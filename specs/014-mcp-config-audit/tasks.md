# Tasks: MCP_CONFIG_AUDIT (014-mcp-config-audit)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): erst Fixtures + Tests (rot), dann Check (grün).
**Status: bereit zur Implementierung (Phase 1 des "Top-Produkt zuerst"-Plans).**

## Phase 1 — Fixtures & Tests zuerst (rot)

- [ ] **T001** Fixtures: `tests/fixtures/mcp_config_vuln.json` (Klartext-Secret
  in env + `sh -c` + ungepinntes npx + `enableAllProjectMcpServers` + remote-url
  ohne Auth), `tests/fixtures/mcp_config_clean.json` (Env-Referenzen, gepinnte
  Pakete, direktes Kommando, keine Risk-Flags, remote MIT Auth-Header).
- [ ] **T002** `tests/test_mcp_config_audit.py` (rot): US1 (Klartext-Secret HIGH
  + redigiert / Env-Ref 0), US2 (`sh -c`/`curl|sh` HIGH, ungepinntes npx MEDIUM,
  gepinnt/direkt 0), US3 (Auto-Approve MEDIUM, remote-url ohne Auth LOW, lokal 0),
  Degradation (malformte/Nicht-MCP-JSON 0, kein Crash), Discovery (Name +
  Struktur), Regression (Quellcode-Fixtures erzeugen keine Config-Findings).

## Phase 2 — Check

- [ ] **T003** `mcpfrisk/checks/mcp_config_audit.py`: Config-Discovery (Name +
  Top-Level-`mcpServers`/`servers`), fünf Befund-Klassen (PLAINTEXT_SECRET,
  INJECTION_COMMAND, UNPINNED_PACKAGE, AUTO_APPROVE_FLAG, REMOTE_NO_AUTH),
  config-lokale Secret-Heuristik (Präfixe + Entropie, Referenzen/Templates aus),
  Redaction, strikte Degradation. Kein Fremd-Check-Import.
- [ ] **T004** Registrierung in `checks/registry.py` (`STATIC_CHECKS`).

## Phase 3 — Polish & Verifikation

- [ ] **T005** Volle Suite grün (`pytest -q`); `test_all_static_checks_actually_run`
  korrekt anpassen (applies_to: bei reinem Quellcode-Ziel ist MCP_CONFIG_AUDIT
  „skipped", kein Fehler); keine Regression; Basis-Install dependency-frei.
- [ ] **T006** Doku: README (Tier-1-Check-Tabelle + Kurzbeschreibung: neuer
  Scan-Zieltyp Config), CONTEXT.md (Check-Tabelle/Architektur), Dogfood-
  Stichprobe, `.specify/feature.json`, commit + push, CI grün.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; KEINE Check-zu-Check-Abhängigkeit (Secret-Heuristik lokal, KEIN
Import aus hardcoded_secrets.py); Redaction (nie voller Secret-Wert im Report);
Finding nur bei konkretem Config-Fund mit Datei + Server-Name als Beleg;
FP-arm (Env-Referenzen/gepinnte Pakete/Templates befundfrei; Auto-Approve MEDIUM,
No-Auth LOW); malformte/Nicht-MCP-JSON sauber übersprungen, nie „sicher", nie
Crash; paired vulnerable/clean Config-Fixtures; neue Datei + ein Registry-Eintrag.
