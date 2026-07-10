# Implementation Plan: MCP_CONFIG_AUDIT (014-mcp-config-audit)

**Spec**: [`spec.md`](./spec.md) | **Status**: Design entschieden, bereit zur
Implementierung.

## Technical Context

Neuer statischer (Tier-1-)Check über `BaseCheck`, aber mit einem NEUEN
Scan-Zieltyp: JSON-Config statt Quellcode-AST. Rein stdlib (`json`, `re`,
`math`). KEINE `SourceModel`-Nutzung (Config wird direkt als JSON geparst),
KEINE Check-zu-Check-Abhängigkeit.

- **Neue Dateien**:
  - `mcpfrisk/checks/mcp_config_audit.py` — der Check.
  - `tests/fixtures/mcp_config_vuln.json` + `mcp_config_clean.json` (+ ggf.
    Template-/Malformed-Fälle).
  - `tests/test_mcp_config_audit.py`.
- **Geändert**: `mcpfrisk/checks/registry.py` (ein `STATIC_CHECKS`-Eintrag).
- **KEINE** Änderung an `core/*` oder anderen Checks.

## Architektur-Entscheidungen

1. **Config-Discovery über Name UND Struktur.** `applies_to`/`run` sammeln
   `*.json` unter dem Ziel (über `fs.rglob_or_file`, Build-Dirs ausgeschlossen),
   parsen sie best-effort und behandeln jede Datei mit Top-Level-`mcpServers`
   (oder `servers`) als MCP-Config — plus die bekannten Dateinamen als starkes
   Signal. So werden auch beliebig benannte Configs erfasst, ohne auf reine
   Namenslisten angewiesen zu sein.
2. **Fünf klar getrennte Befund-Klassen** (`McpConfigIssueKind`), jede mit
   eigener Severity/CWE/MCP-Ref und eigenem Finding-Text — analog zu den
   Probe-Klassen der dynamischen Checks. Ein Config-Server kann mehrere
   Findings erzeugen (z.B. Klartext-Secret UND ungepinntes Paket).
3. **Config-lokale, minimale Secret-Heuristik** (Prinzip II — KEIN Import aus
   `hardcoded_secrets.py`): ein `env`/`headers`-Wert ist verdächtig, wenn (a)
   er ein bekannt-formatiertes Key-Präfix trägt (`sk-`, `sk-ant-`, `ghp_`/
   `github_pat_`, `AKIA`/`ASIA`, `xox`, `-----BEGIN … PRIVATE KEY-----`) ODER
   (b) der Schlüssel credential-artig ist (key/secret/token/password/…) UND der
   Wert hohe Shannon-Entropie hat UND KEINE Referenz ist. Referenzen
   (`${VAR}`, `$VAR`, `%VAR%`, leer, Platzhalter) sind immer befundfrei.
4. **Injection-/Pinning-Analyse auf `command`+`args`.** Shell-Interpreter-Namen
   (sh/bash/zsh/dash/ksh/cmd/powershell/pwsh) als `command` mit `-c` in `args`
   → HIGH. Ein `args`-Element mit `curl|wget … | sh`/`| bash` → HIGH. Ein
   Runner (`npx`/`uvx`/`pipx`/`pip`/`bunx`) mit einem Paket-Argument ohne
   Versions-Pin (`@x.y.z` bzw. `==x.y.z`; `@latest`/kein `@` → ungepinnt) →
   MEDIUM.
5. **Redaction wie im Rest des Tools** — der geloggte Secret-Ausschnitt wird
   maskiert; nie der volle Wert.
6. **Degradation strikt.** Nicht-parsebare JSON oder fehlendes `mcpServers`
   → die Datei ist keine (verwertbare) MCP-Config → übersprungen, nie „sicher"
   gemeldet, nie Crash.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Fixtures + Tests zuerst (rot), dann Check. |
| II. Plugin Isolation | ✅ **zentral** | Neue Datei + ein Registry-Eintrag; KEIN Import aus einem anderen Check (Secret-Heuristik lokal). |
| III. FP over FN | ✅ | Env-Referenzen/gepinnte Pakete/Templates → befundfrei; Auto-Approve nur MEDIUM, No-Auth nur LOW (Hygiene). |
| IV. Zero Unnecessary Deps | ✅ | stdlib `json`/`re`/`math`. |
| V. Evidence-Grounded | ✅ | Finding nennt Datei + Server-Name/JSON-Pfad + (redigierten) Beleg. |
| VI. Paired Fixture Testing (NON-NEGOTIABLE) | ✅ | vulnerable + clean Config-Fixture (+ malformed/Template). |
| VII. Security-Research Currency | ✅ | Frischer Research-Pass (CVE-2025-59536, CVE-2026-21852, 2026-Ökosystem-Audit, OWASP MCP Cheat Sheet) in spec.md. |

**Gate-Ergebnis: PASS.**

## Test Strategy (TDD, Prinzip I & VI)

`tests/fixtures/`:
- `mcp_config_vuln.json` — ein `mcpServers` mit: Klartext-`sk-ant-…` in `env`;
  ein Server `command: "sh", args: ["-c", "…"]`; ein Server `npx -y @scope/x`
  (ungepinnt); Top-Level `enableAllProjectMcpServers: true`; ein remote-`url`-
  Server ohne Auth-Header.
- `mcp_config_clean.json` — env nutzt `${API_KEY}`; Pakete gepinnt (`@1.2.3`);
  direktes Kommando ohne Shell; keine Risk-Flags; remote-Server MIT
  `headers.Authorization`.
- Malformed-/Nicht-MCP-JSON-Fall (inline im Test, tmp_path).

`tests/test_mcp_config_audit.py`:
- US1: Klartext-Secret → HIGH + redigiert; Env-Referenz → 0.
- US2: `sh -c`/`curl|sh` → HIGH; ungepinntes npx → MEDIUM; gepinnt/direkt → 0.
- US3: Auto-Approve-Flag → MEDIUM; remote-url ohne Auth → LOW; lokaler stdio → 0.
- Degradation: malformte JSON / `*.json` ohne `mcpServers` → 0, kein Crash.
- Discovery: bekannte Dateinamen UND beliebig benannte `*.json` mit
  `mcpServers` werden erfasst.
- Regression: bestehende Fixtures (vulnerable_server.py/clean_server.py) sind
  keine Configs → erzeugen KEINE MCP_CONFIG_AUDIT-Findings; Integrationstest
  `test_all_static_checks_actually_run` um MCP_CONFIG_AUDIT ergänzen, sofern
  eine Config im Ziel liegt (sonst applies_to=False → skipped; Test
  entsprechend führen).

Reihenfolge: Fixtures+Tests (rot) → `mcp_config_audit.py` → Registry → volle
Suite grün → Doku.

## Risiken / Restunsicherheiten

- **applies_to & der bestehende Integrationstest**: MCP_CONFIG_AUDIT läuft nur,
  wenn eine Config im Ziel ist. `test_all_static_checks_actually_run` scannt
  `vulnerable_server.py` (kein Config) → MCP_CONFIG_AUDIT wäre dort korrekt
  „skipped". Der Test darf NICHT erwarten, dass es bei einem reinen
  Quellcode-Ziel „läuft" — beim Anpassen darauf achten (Prinzip: applies_to
  ist ein bewusster Vorfilter, kein Fehler).
- **Secret-FP**: die Entropie-Schwelle konservativ (wie HARDCODED_SECRETS);
  Referenzen/Templates hart ausgenommen.
- **Pinning-Erkennung**: nur die gängigen Runner (npx/uvx/pipx/pip/bunx);
  unbekannte Runner lösen kein Pinning-Finding aus (FP-arm).
- **Spätere Secret-Muster-Konsolidierung** (HARDCODED_SECRETS + dieser Check
  teilen sich einen Helfer) ist bewusst NICHT Teil von 014 — separater Cleanup.
