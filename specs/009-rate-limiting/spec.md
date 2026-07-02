# Feature Specification: RATE_LIMITING (Tier 2, dynamisch)

**Feature Branch**: `009-rate-limiting`

**Created**: 2026-07-02

**Status**: Design entschieden — NICHT IMPLEMENTIERT. Bereit für Phase 1
(Modelle + rote Tests) auf Signal.

**Input**: Letzter Tier-2-Check der ursprünglichen Roadmap, nach
`ERROR_LEAKAGE` (008, implementiert). Baut wie 007/008 direkt auf dem
`call()`-basierten Transport-Port (HTTP **und** stdio, Feature 005) auf.

## Kontext / Motivation

**Sicherheits-Recherche (Prinzip VII, Stand 2026-07-02):**

Aktuelle Analysen des MCP-Ökosystems sind eindeutig: *"By default, no rate
limits are set on MCP servers [...] a single rogue client can bring down an
entire MCP deployment because nobody thought to set limits on tool
invocations."* Ein MCP-Server ohne Rate-Limiting wird unbenutzbar, sobald ein
Agent Tools in schneller Folge aufruft — andere verbundene Clients hungern
aus. Das Protokoll selbst definiert **kein** Rate-Limiting, **kein**
Execution-Budget und **keine** Loop-Detection: eine einzelne Nutzer-Anfrage
kann eine Kette von Tool-Aufrufen auslösen, die erst mit Session-Abbruch oder
einem Downstream-API-Fehler endet — Ressourcen-Erschöpfung (CPU, Speicher,
Downstream-Rate-Limits, Kosten) ist die unmittelbare Folge. Real beobachtet:
Agenten, die tausende Tool-Aufrufe über parallele Sessions feuern, bis die
zugrunde liegende API innerhalb von Sekunden drosselt und alle Sessions
kaskadierend fehlschlagen. Präzise CWE-Referenzen: **CWE-400** (Uncontrolled
Resource Consumption) und **CWE-770** (Allocation of Resources Without Limits
or Throttling) — dieselbe Klasse, die z.B. auch CVE-2026-53522 (Nezha
Dashboard, DoS durch Memory-/Goroutine-/Stream-Erschöpfung) trägt.

**OWASP-Mapping — bewusst KEIN Feld gesetzt (Unterschied zu `ERROR_LEAKAGE`):**
Anders als bei 008 (wo `MCP08` zumindest eine lose Näherung war) hat **keine**
der zehn offiziellen OWASP-MCP-Top-10-Kategorien (`OWASP/www-project-mcp-top-10`,
geprüft 2026-07-02: MCP01 Token Mismanagement, MCP02 Privilege Escalation,
MCP03 Tool Poisoning, MCP04 Supply Chain, MCP05 Command Injection, MCP06
Intent Flow Subversion, MCP07 Insufficient Auth, MCP08 Lack of Audit/
Telemetry, MCP09 Shadow MCP Servers, MCP10 Context Injection) einen
erkennbaren Bezug zu Resource-Exhaustion/DoS. Ein erzwungenes Mapping wäre
hier reine Fiktion (siehe Entschiedener Design-Punkt in `plan.md`). Zum
Vergleich: das *separate* OWASP-Top-10-für-LLM-Anwendungen kennt
"LLM10:2025 — Unbounded Consumption", aber das ist eine andere Liste als die
hier im Projekt referenzierte OWASP-MCP-Top-10 und wird daher nicht in
`owasp_mcp_ref` (das Feld ist für MCP-Top-10-IDs dokumentiert) missbraucht.

**Empfohlene Testmethodik (aus den Quellen):** einen kurzen, klar begrenzten
Burst von Aufrufen gegen ein lesendes Tool desselben, gerade getesteten
Servers senden und beobachten, ob (a) der Server explizit drosselt (HTTP 429
bzw. ein erkennbarer "rate limit"/"too many requests"-Fehler), (b) er unter
der Last abstürzt/unerreichbar wird (bewiesen wie bei `SCHEMA_FUZZING` per
Liveness-Recheck), oder (c) er zwar überlebt, aber messbar degradiert
(deutlich steigende Antwortzeiten ohne jede Drosselung) — ein Server, der den
Burst schnell und gleichbleibend abarbeitet oder explizit drosselt, ist
befundfrei.

**Kernidee des Checks:** McpFrisk misst zuerst eine Baseline-Latenz mit einem
einzelnen Aufruf, sendet dann einen kurzen, bewusst begrenzten Burst an
dasselbe lesende Tool und wertet **ausschließlich** harte Signale: ein
expliziter Drossel-Hinweis irgendwo im Burst → sofort befundfrei (Rate-Limiting
ist vorhanden); ein anschließend fehlschlagender Liveness-Recheck → bewiesener
DoS (HIGH); eine deutliche, gemessene Latenz-Degradation ohne Drosselung →
Beleg für unkontrollierten Ressourcenverbrauch (MEDIUM). Alles andere bleibt
befundfrei oder INCONCLUSIVE (Prinzip III/V).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Absturz/Unerreichbarkeit unter Last (Priority: P1)

Als Betreiber:in möchte ich beweisen, ob mein Server unter einem kurzen
Aufruf-Burst abstürzt oder unerreichbar wird, statt die Last kontrolliert
abzufangen.

**Why this priority**: Der direkteste, beweisbare Schaden — ein Server, der
unter einem trivialen Burst stirbt, ist ein realer DoS-Vektor (CWE-400).

**Independent Test**: Ein verwundbarer Fixture (stellt nach N Aufrufen im
Burst die Antwort komplett ein / beendet den Prozess) → Finding (HIGH); ein
sauberer Fixture (drosselt oder bleibt konstant schnell, lebt weiter) → kein
Finding.

**Acceptance Scenarios**:

1. **Given** ein gesunder Baseline-Call funktioniert, **When** ein kurzer
   Burst gesendet wird und der Server danach nicht mehr antwortet (per
   Liveness-Recheck bestätigt), **Then** NOT_ENFORCED (Finding, Severity HIGH).
2. **Given** derselbe Burst, **When** der Server explizit drosselt (HTTP 429
   bzw. erkennbarer Rate-Limit-Fehler) und danach weiter antwortet, **Then**
   ENFORCED (kein Finding) — unabhängig vom Rest des Bursts.

---

### User Story 2 — Messbare Latenz-Degradation ohne Drosselung (Priority: P2)

Als Betreiber:in möchte ich erkennen, ob mein Server zwar nicht abstürzt,
aber unter dem Burst spürbar und messbar langsamer wird, ohne jemals zu
drosseln — ein Vorbote von Ressourcen-Erschöpfung unter echter Last.

**Why this priority**: Zweithäufigstes, gut beweisbares Ergebnis; ergänzt
US1 (Server *überlebt* den kleinen Test-Burst, zeigt aber keinerlei
Gegenmaßnahme).

**Independent Test**: Verwundbarer Fixture liefert mit steigender
Aufrufzahl im Burst deterministisch steigende Antwortzeiten (kein Cap) →
Finding (MEDIUM) mit den gemessenen Latenzwerten als Beleg. Sauberer Fixture
bleibt gleichbleibend schnell → kein Finding.

**Acceptance Scenarios**:

1. **Given** ein Burst ohne Crash und ohne Drossel-Signal, **When** die
   gemessene Burst-Latenz einen klar definierten Vielfachen-Schwellenwert der
   Baseline-Latenz überschreitet, **Then** NOT_ENFORCED (Finding, Severity
   MEDIUM), mit den konkreten Latenzwerten (Baseline vs. Burst) als Beleg.

---

### User Story 3 — Sichere Degradation ohne belastbaren Burst (Priority: P3)

Als Nutzer:in möchte ich, dass der Check **niemals** ein stilles „sicher"
liefert, wenn er nicht sicher testen kann (kein lesendes Tool, Baseline schon
rot, Server nicht erreichbar).

**Why this priority**: Prinzip III. Ein nicht durchführbarer Test ist kein Pass.

**Acceptance Scenarios**:

1. **Given** kein lesendes Tool (oder nur mutierende), **When** der Check
   läuft, **Then** INCONCLUSIVE mit klarer Begründung.
2. **Given** ein Baseline-Call schlägt schon fehl (Server rot/Timeout),
   **When** der Check läuft, **Then** INCONCLUSIVE (kein Burst-Ergebnis wird
   als Ursache gewertet).
3. **Given** weder Crash noch Drossel-Signal noch signifikante Degradation
   im Burst, **When** der Check läuft, **Then** ENFORCED (kein Finding) — der
   Check konnte trotz Burst keinen Schaden nachweisen (Prinzip V: keine
   Vermutung ohne Beleg).

---

### Edge Cases

- **Gut provisionierter, schneller Server**: der Burst läuft in
  Sekundenbruchteilen ohne Degradation durch → ENFORCED, korrekt (kein
  Fehlalarm nur weil kein explizites 429 gesendet wurde).
- **Netzwerk-/Mess-Jitter**: der Degradations-Schwellenwert ist bewusst hoch
  (ein deutliches Vielfaches, keine 1,2x-Schwankung) angesetzt, um
  Messrauschen nicht als Finding zu werten (Prinzip V verlangt echten Beleg,
  trotz Prinzip III).
- **stdio-Burst ist sequenziell, nicht echt parallel** (bewusste
  v1-Einschränkung, siehe `plan.md`) — deckt trotzdem den Fall ab, dass ein
  Server ohne jegliches Rate-Limiting selbst eine simple, schnelle
  Aufruf-Serie unbegrenzt verarbeitet.
- **Mutierende Tools**: werden **nie** als Ziel verwendet (`_MUTATE_HINTS`
  wie bei allen bisherigen Tier-2-Checks).
- **Burst-Umfang bewusst begrenzt**: kein andauernder Last-Test — ein kurzer,
  endlicher Burst genügt als Beleg und bleibt CI-tauglich sowie ungefährlich
  für das Zielsystem (das typischerweise der eigene, gerade getestete
  Server ist).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Der Check MUSS vor dem Burst einen gesunden Baseline-Call
  gegen ein lesendes Tool bestätigen und dessen Latenz als Referenzwert
  messen; scheitert der Baseline-Call, ist das Verdikt INCONCLUSIVE.
- **FR-002**: Der Check MUSS einen kurzen, bewusst begrenzten, **schnellen
  sequenziellen** Burst von Aufrufen an dasselbe lesende Tool senden (v1:
  keine echte Multi-Thread-Parallelität, siehe `plan.md`).
- **FR-003**: Ein expliziter Drossel-Hinweis (HTTP 429 oder ein JSON-RPC-
  Fehler mit erkennbarem "rate limit"/"too many requests"-Wortlaut) an
  IRGENDEINER Stelle im Burst MUSS sofort als ENFORCED gewertet werden,
  unabhängig vom restlichen Burst-Verlauf.
- **FR-004**: Schlägt ein Liveness-Recheck (`tools/list`) NACH dem Burst
  fehl (Prozess-/Verbindungstod, nach gesundem Baseline), MUSS das als
  NOT_ENFORCED (Severity HIGH, CWE-400) gewertet werden.
- **FR-005**: Zeigt der Burst — ohne Crash und ohne Drossel-Signal — eine
  klar definierte, deutliche Latenz-Degradation gegenüber der Baseline, MUSS
  das als NOT_ENFORCED (Severity MEDIUM, CWE-400/CWE-770) mit den konkreten
  Latenzwerten als Beleg gewertet werden.
- **FR-006**: Weder Crash noch Drossel-Signal noch signifikante Degradation
  MUSS als ENFORCED (kein Finding) gewertet werden.
- **FR-007**: Der Check DARF **keine** mutierenden Tools als Ziel wählen
  (Namens-Heuristik, im Zweifel NICHT proben).
- **FR-008**: Kein lesendes Tool, roter Baseline oder Server nicht erreichbar
  → INCONCLUSIVE, niemals ein stilles „sicher", niemals geworfen.
- **FR-009**: Der Check MUSS über **HTTP und stdio** laufen (rein `call()`-
  basiert; keine Transport-Port-Erweiterung — v1 bewusst als schneller
  sequenzieller statt echter parallelisierter Burst, siehe `plan.md`).
- **FR-010**: Es DARF KEINE neue Laufzeit-Abhängigkeit entstehen
  (stdlib-only).
- **FR-011**: Der Burst-Umfang MUSS bewusst begrenzt/CI-tauglich bleiben —
  kein andauernder Last-Test gegen das Zielsystem.
- **FR-012**: Findings MÜSSEN CWE-400 (bei Degradation zusätzlich CWE-770),
  die konkreten Latenz-/Crash-Belege und eine Remediation (Rate-Limiting-
  Middleware, Concurrency-Caps, Timeouts, Backoff-Signale) tragen; **kein**
  `owasp_mcp_ref` (siehe Entschiedener Design-Punkt in `plan.md`).

### Key Entities

- **RateLimitProbeClass**: `BURST_CRASH` | `BURST_DEGRADATION` — bewusst
  **ohne** eigene "Throttle-erkannt"-Klasse (das ist der ENFORCED-Fall, kein
  Finding).
- **RateLimitProbe**: (Tool, Parameter, Probe-Klasse, Drei-Zustands-Verdikt,
  secret-bereinigte `observed`-Notiz inkl. Latenzwerten) —
  strukturkompatibel zu `ErrorProbe`/`FuzzProbe`/`RbacProbe`.

## Success Criteria *(mandatory)*

- **SC-001**: Ein verwundbarer Fixture (crasht unter Last ODER degradiert
  messbar ohne Drosselung) erzeugt RATE_LIMITING-Findings; der saubere
  Fixture (drosselt explizit oder bleibt konstant schnell) bleibt befundfrei.
- **SC-002**: Läuft nachweislich über **beide** Transporte (HTTP + stdio).
- **SC-003**: Ohne lesendes Tool / bei rotem Baseline / bei nicht
  erreichbarem Server → INCONCLUSIVE (kein Finding, kein Pass).
- **SC-004**: Keine Regression; Basis-Install bleibt dependency-frei; der
  Check fuzzt/belastet nachweislich **keine** mutierenden Tools; der
  Burst-Umfang ist nachweislich begrenzt (kein unbegrenzter Last-Test).

## Assumptions

- v1 testet **keine** echte Multi-Connection-/Multi-Thread-Parallelität
  (Architektur-Grund: der stdio-Transport-Kanal ist pro Identität ein
  gemeinsamer Subprozess-Kanal, echte parallele `call()`s wären dort ein
  Race Condition — siehe `plan.md`). Ein schneller sequenzieller Burst ist
  die v1-Definition von "Last".
- Ein kurzer, klar begrenzter Burst gegen den eigenen, gerade getesteten
  Server (typisch: lokal/Staging — genau McpFrisks Zielszenario) ist
  akzeptabel und kein echter Angriff.
- Out of scope (entschieden): echte verteilte Last-/Concurrency-Tests (andere
  Testmethodik, künftige Erweiterung); Kosten-/Budget-Erschöpfung bei
  Downstream-APIs (von außen nicht messbar); identitäts-/IP-basiertes
  Rate-Limiting differenzieren (das wäre ein RBAC-artiger Multi-Identity-
  Test, hier nicht Scope); Injection-/Schema-Payloads (SCHEMA_FUZZING-Scope).
