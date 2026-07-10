# Feature Specification: MCP_CONFIG_AUDIT (Tier 1, statisch)

**Feature Branch**: `014-mcp-config-audit`

**Created**: 2026-07-05

**Status**: Design entschieden — bereit für Implementierung. Phase 1 des
"Top-Produkt zuerst"-Plans (siehe Roadmap): die klarste Coverage-Parität-Lücke
gegen den direkten Konkurrenten `agent-audit`.

**Input**: Neuer statischer Check, der einen bislang gar nicht betrachteten
Scan-Zieltyp abdeckt: **MCP-Client-/Projekt-Konfigurationsdateien**
(`claude_desktop_config.json`, `mcp.json`, `.mcp.json`, `.cursor/mcp.json`,
`.vscode/mcp.json`, `.claude.json`). Alle bisherigen Checks lesen Server-
*Quellcode*; dieser liest die Config, über die MCP-Server *gestartet und
angebunden* werden.

## Kontext / Motivation

**Sicherheits-Recherche (Prinzip VII, Stand 2026-07-05):** Die MCP-Config ist
ein aktiver, real ausgenutzter Angriffsvektor:
- **CVE-2025-59536** (Check Point, 2026): RCE über bösartige Hooks/Kommandos in
  einer ins Repo eingecheckten Settings-/`.mcp.json` — beim Öffnen einer
  Claude-Code-Konversation werden die in der Config hinterlegten Kommandos
  ausgeführt.
- **CVE-2026-21852**: `enableAllProjectMcpServers` bzw. ein per Env-Override
  gekaperter Wert leakt Quellcode / exfiltriert API-Keys, ohne dass der Nutzer
  die Projekt-Server je freigegeben hat.
- Ökosystem-Audit 2026: **79% der MCP-Server handhaben Credentials im
  Klartext**, **40% haben keine Authentifizierung**, **43% sind command-
  injection-anfällig** — vieles davon manifestiert sich direkt in der Config
  (`env`-Blöcke mit hartkodierten Keys, `command: "sh" -c …`, ungepinnte
  `npx -y <paket>`-Starts, remote `url` ohne Auth-Header).
- OWASP MCP Security Cheat Sheet u.a. empfehlen ausdrücklich, `mcp.json`/
  `claude_desktop_config.json` regelmäßig auf **geänderte/unverifizierte
  Server, neue Localhost-Proxys und Klartext-Secrets** zu prüfen.

**Warum das ein echter Wettbewerbsvorteil ist:** `agent-audit` prüft MCP-Configs
(unverifizierte Server-Quellen, zu breite Rechte, fehlende Auth, ungepinnte
Versionen) — McpFrisk bisher **gar nicht**. Das ist die klarste benennbare
Coverage-Lücke gegen den stärksten direkten Konkurrenten, und sie ist
MCP-spezifisch (kein generisches SAST-Tool tut das).

**OWASP/CWE-Mapping (pro Befund-Klasse):** MCP01/CWE-798 (Klartext-Secrets),
MCP05/CWE-78 + MCP04 (command-injection-anfälliger/unverifizierter Start,
Supply-Chain), MCP07 (fehlende Auth / zu breite Auto-Approve-Flags).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Klartext-Credentials in der Server-Config (Priority: P1)

Als Server-/Repo-Betreiber:in möchte ich gewarnt werden, wenn eine MCP-Config
ein hartkodiertes Credential im `env`- oder `headers`-Block eines Servers trägt
(statt es aus der Host-Umgebung zu referenzieren).

**Why this priority**: mit Abstand häufigster realer Fund (79%); direkter
Secret-Leak, sobald die Config ins Repo/VCS gelangt.

**Independent Test**: verwundbare `mcp.json` mit
`"env": {"API_KEY": "sk-ant-…echt aussehend…"}` → Finding (HIGH, CWE-798), Wert
redigiert. Saubere Config, die `${API_KEY}`/`env:`-Referenzen nutzt → kein Finding.

**Acceptance Scenarios**:

1. **Given** ein Server-Eintrag mit einem hochentropischen bzw. bekannt-
   formatierten Credential-Wert in `env`/`headers`, **When** der Check läuft,
   **Then** ein Finding (HIGH, CWE-798, MCP01) mit **redigiertem** Beleg.
2. **Given** ein `env`-Wert, der nur eine Referenz ist (`${VAR}`,
   `$VAR`, leerer String, Platzhalter wie `changeme`), **When** der Check
   läuft, **Then** kein Finding.

---

### User Story 2 — Command-injection-anfälliger / unverifizierter Server-Start (Priority: P2)

Als Betreiber:in möchte ich erkennen, wenn ein Server über ein riskantes
Startkommando angebunden wird: eine Shell mit `-c`, eine `curl … | sh`-Pipe,
oder ein **ungepinntes** `npx -y <paket>` / `uvx <paket>` (Rug-Pull-/Supply-
Chain-Risiko), das beim Client-Start ungeprüft ausgeführt wird.

**Why this priority**: Config-getriebene Code-Ausführung (CVE-2025-59536-Klasse);
ungepinnte Pakete sind der Standard-Supply-Chain-Vektor.

**Independent Test**: `"command": "sh", "args": ["-c", "…"]` bzw.
`"command": "npx", "args": ["-y", "@scope/server"]` (ohne `@version`) → Finding
(HIGH bzw. MEDIUM). `"command": "npx", "args": ["-y", "@scope/server@1.2.3"]`
(gepinnt) → kein Finding; ein direkter Binär-/absoluter-Pfad-Start → kein Finding.

**Acceptance Scenarios**:

1. **Given** `command` ist ein Shell-Interpreter (sh/bash/cmd/powershell) mit
   `-c`, ODER ein `args`-Element enthält eine `curl|wget … | sh`-Pipe, **When**
   der Check läuft, **Then** Finding (HIGH, CWE-78, MCP05).
2. **Given** ein `npx`/`uvx`/`pip`-Start mit **ungepinntem** Paket (kein
   `@version`/`==version`, bzw. `latest`), **When** der Check läuft, **Then**
   Finding (MEDIUM, MCP04, Supply-Chain/Rug-Pull).
3. **Given** ein gepinnter Paket-Start oder ein direktes Binär-Kommando ohne
   Shell/Pipe, **When** der Check läuft, **Then** kein Finding.

---

### User Story 3 — Zu breite Flags / fehlende Auth (Priority: P3)

Als Betreiber:in möchte ich auf riskante Config-Schalter und fehlende Auth
hingewiesen werden: `enableAllProjectMcpServers`/`autoApprove`/`alwaysAllow`
(unbeaufsichtigtes Ausführen von Projekt-Servern, CVE-2026-21852-Klasse) sowie
remote `url`-Server (http/https) **ohne** irgendeinen Auth-Header.

**Why this priority**: real (40% ohne Auth), aber schwächeres Einzel-Signal;
teils Hygiene-Hinweis statt harter Defekt → niedrigere Severity.

**Independent Test**: Config mit `"enableAllProjectMcpServers": true` bzw.
`"autoApprove": [...]` → Finding (MEDIUM). Remote-`url`-Server ohne
`headers.Authorization` → Finding (LOW/INFO). Lokaler stdio-Server ohne url →
kein Auth-Finding.

**Acceptance Scenarios**:

1. **Given** ein Auto-Approve-/Enable-All-Flag ist gesetzt, **When** der Check
   läuft, **Then** Finding (MEDIUM, MCP07) mit Fundstelle.
2. **Given** ein remote-`url`-Server ohne erkennbaren Auth-Header, **When** der
   Check läuft, **Then** Finding (LOW, MCP07, Hygiene-Hinweis).

---

### Edge Cases

- **Keine MCP-Config im Ziel**: der Check meldet nichts (kein FP), applies_to
  greift nur, wenn eine Config gefunden wird.
- **Malformte JSON / kein `mcpServers`-Objekt**: sauber übersprungen (nie
  Crash, nie fälschlich „sicher").
- **`.env.example`/Template-Configs**: wie bei HARDCODED_SECRETS ausgenommen.
- **Config-Erkennung**: über bekannte Dateinamen UND über die Struktur (ein
  Top-Level-`mcpServers`- bzw. `servers`-Objekt) — eine beliebig benannte
  `*.json` mit `mcpServers` wird auch erfasst.
- **Secret-Redaction**: der Report zeigt nie den vollen Secret-Wert (Prinzip:
  der Scanner darf kein neues Leck erzeugen).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Der Check MUSS MCP-Config-Dateien erkennen — über bekannte
  Dateinamen (`claude_desktop_config.json`, `mcp.json`, `.mcp.json`,
  `.claude.json`, `.cursor/mcp.json`, `.vscode/mcp.json`) UND über ein
  Top-Level-`mcpServers`/`servers`-Objekt in einer beliebigen `*.json`.
- **FR-002**: Klartext-Credentials in `env`/`headers` eines Server-Eintrags
  MÜSSEN erkannt werden (bekannte Key-Formate ODER hohe Entropie bei
  credential-artigem Schlüsselnamen), als Finding HIGH (CWE-798, MCP01) mit
  **redigiertem** Beleg. Referenzen (`${VAR}`/`$VAR`/leer/Platzhalter) MÜSSEN
  befundfrei bleiben.
- **FR-003**: Ein command-injection-anfälliges Startkommando (Shell-Interpreter
  mit `-c`; `curl|wget … | sh`-Pipe) MUSS als Finding HIGH (CWE-78, MCP05)
  gemeldet werden.
- **FR-004**: Ein **ungepinntes** Paket in einem `npx`/`uvx`/`pip`-Start MUSS
  als Finding MEDIUM (MCP04, Supply-Chain) gemeldet werden; ein gepinntes
  (`@version`/`==version`) bleibt befundfrei.
- **FR-005**: Auto-Approve-/Enable-All-Flags (`enableAllProjectMcpServers`,
  `autoApprove`, `alwaysAllow`) MÜSSEN als Finding MEDIUM (MCP07) gemeldet
  werden; ein remote-`url`-Server ohne Auth-Header als Finding LOW (MCP07).
- **FR-006**: Eine fehlende/malformte Config MUSS sauber übersprungen werden
  (kein Crash, nie fälschlich „sicher") — Templates ausgenommen.
- **FR-007**: Es DARF KEINE neue Laufzeit-Abhängigkeit entstehen (stdlib
  `json`/`re`/`math`) und KEINE Check-zu-Check-Abhängigkeit (Prinzip II) —
  insbesondere KEIN Import aus `hardcoded_secrets.py`; eine kleine, config-
  taugliche Secret-Heuristik lebt lokal.
- **FR-008**: Findings MÜSSEN CWE + OWASP-MCP-Ref, die konkrete Config-
  Fundstelle (Datei + Server-Name/JSON-Pfad) und eine konkrete Remediation
  tragen.

### Key Entities

- **McpConfigIssueKind**: `PLAINTEXT_SECRET` | `INJECTION_COMMAND` |
  `UNPINNED_PACKAGE` | `AUTO_APPROVE_FLAG` | `REMOTE_NO_AUTH`.

## Success Criteria *(mandatory)*

- **SC-001**: Eine verwundbare Fixture-Config (Klartext-Secret + `sh -c` +
  ungepinntes npx + `enableAllProjectMcpServers`) erzeugt die passenden
  Findings in korrekter Severity; eine saubere Config (Env-Referenzen,
  gepinnte Pakete, direktes Kommando, keine Risk-Flags) bleibt befundfrei.
- **SC-002**: Kein voller Secret-Wert erscheint je im Report (Redaction).
- **SC-003**: Malformte/nicht-MCP-JSON → kein Crash, kein Finding.
- **SC-004**: Keine Regression; Basis-Install bleibt dependency-frei;
  Plugin-Isolation gewahrt (neue Datei + ein Registry-Eintrag, kein
  Fremd-Check-Import).

## Assumptions

- Config-Format ist das etablierte `{"mcpServers": {"<name>": {"command"|
  "url", "args", "env", "headers"}}}` (Claude Desktop/Code, Cursor, VS Code);
  `servers` als Alias wird mitgeführt.
- Out of scope (v1, entschieden): tiefe Hook-/Settings-Analyse jenseits der
  mcpServers-Config (eigene künftige Erweiterung); Auflösen von Env-Overrides
  zur Laufzeit (statisch nicht möglich); semantische „ist dieser Server
  vertrauenswürdig"-Bewertung (kein Reputations-Backend — Prinzip IV/lokal).
- Die Secret-Heuristik ist bewusst config-lokal und minimal (Entropie +
  wenige hochsichere Präfixe); eine spätere Konsolidierung der Secret-Muster
  in einen geteilten Nicht-Check-Helfer (analog `_dynamic_helpers.py`, damit
  HARDCODED_SECRETS und MCP_CONFIG_AUDIT eine Quelle teilen) ist ein separater,
  optionaler Cleanup — NICHT Teil dieses Features.
