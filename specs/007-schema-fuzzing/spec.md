# Feature Specification: SCHEMA_FUZZING (Tier 2, dynamisch)

**Feature Branch**: `007-schema-fuzzing`

**Created**: 2026-07-02

**Status**: Design entschieden — NICHT IMPLEMENTIERT. Beide Design-Punkte nach
Best Practice festgelegt (v1 rein verhaltensbasiert, kein Schema-Deklarations-
Advisory; Crash-Erkennung via Liveness-Recheck ohne Transport-Umbau). Bereit für
Phase 1 (Modelle + rote Tests) auf Signal.

**Input**: Nächster Tier-2-Check laut Roadmap-Priorität nach `RBAC_CROSS_TENANT`.
Baut direkt auf dem `call()`-basierten Transport-Port (HTTP **und** stdio,
Feature 005) auf — keine Transport-Erweiterung nötig.

## Kontext / Motivation

**Sicherheits-Recherche (Prinzip VII, Stand 2026-07-02):**
Die mit Abstand häufigste Wurzel realer MCP-CVEs sind **unbeschränkte
Schema-Parameter** — ein `"type": "string"` ohne `maxLength`/`pattern`/`enum`/
`format`, dessen Wert ungeprüft in einen Sink fließt. Eine Ökosystem-Analyse
(8.216 Server) fand **4.512 hochriskante Parameter ohne jede Validierungs-
Constraint**; mind. 11 CVEs gehen direkt darauf zurück. Belegte Fälle:
- **CVE-2026-32871 (FastMCP OpenAPI-Provider)** — Path-Parameter ohne URL-
  Encoding in ein URL-Template substituiert → `../`-Ausbruch (SSRF) mit den
  Auth-Headern des Providers.
- **CVE-2025-6514 (mcp-remote, CVSS 9.6, 437k+ Installs)** — unbeschränkter
  OAuth-URL-Parameter → OS-Command-Injection.
- **VIPER-MCP (arXiv 2605.21392)** — taint-style Flows: der Agent füllt
  *schema-konforme* Argumente mit Angreifer-Strings, die der Handler ungefiltert
  in `exec`/`fetch`/`fs.readFile` reicht.

**OWASP-Mapping:** Fehlende Eingabe-Validierung ist die Vorbedingung für
**MCP05:2025 — Command Injection & Execution** (die häufigste Bug-Klasse in
offengelegten MCP-CVEs). Direkt einschlägige CWEs für *diesen* Check:
**CWE-20** (Improper Input Validation, Kern), **CWE-248** (Uncaught Exception),
**CWE-400** (Uncontrolled Resource Consumption / DoS), **CWE-209** (Information
Exposure Through an Error Message).

**Empfohlene Testmethodik (aus den Quellen):** systematisch malformte,
übergroße und typ-fremde Payloads in Tool-Parameter injizieren und das
**Antwortverhalten** analysieren — Crash, Hang oder geleakter Stacktrace/interne
Fehlerdetails belegen fehlende Validierung; eine saubere, strukturierte
Validierungs-Fehlermeldung (JSON-RPC `-32602 Invalid params`) ist das korrekte
Verhalten.

**Kernidee des Checks:** McpFrisk liest die deklarierten Tool-Schemata eines
laufenden Servers, baut daraus **schema-abgeleitete Fuzz-Payloads** und sendet
sie an **lesende** Tools. Ein Finding entsteht nur bei **hartem Beleg** fehlender
Robustheit/Validierung: der Server **crasht** (per Liveness nachgewiesen) oder
seine Fehlerantwort **leakt einen Stacktrace/interne Details**. Ein Server, der
strukturiert und ohne Leak ablehnt und am Leben bleibt, ist befundfrei. Alles
Unklare → *inconclusive* (Prinzip III/V).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Crash / Unhandled Exception bei malformer Eingabe (Priority: P1)

Als Betreiber:in eines MCP-Servers möchte ich beweisen, ob ein Tool bei typ-
fremder/übergroßer/fehlender Eingabe **abstürzt oder eine ungefangene Ausnahme**
produziert, statt die Eingabe sauber zu validieren.

**Why this priority**: Der direkteste, beweisbare Robustheits-Defekt. Ein
crashendes Tool ist ein DoS (bei stdio stirbt der ganze Server-Prozess) und ein
sicheres Signal für fehlende Eingabe-Validierung (CWE-20/248/400).

**Independent Test**: Ein verwundbarer Fixture (Handler wirft bei falschem Typ /
Übergröße eine ungefangene Exception → Prozess-Tod bzw. HTTP-500 mit Traceback)
→ Finding; ein sauberer (validiert, antwortet mit `-32602`, bleibt am Leben)
→ kein Finding.

**Acceptance Scenarios**:

1. **Given** ein gesunder Baseline-Call funktioniert, **When** ein typ-fremder/
   übergroßer Payload gesendet wird und der Server danach nicht mehr antwortet
   (Prozess tot / Verbindung tot, per Liveness-Recheck bestätigt), **Then** ist
   das Verdikt NOT_ENFORCED (Finding, Severity HIGH bei Prozess-Tod).
2. **Given** derselbe Payload, **When** der Server strukturiert ablehnt
   (JSON-RPC `-32602`/`-32600`) und weiter antwortet, **Then** ENFORCED (kein Finding).

---

### User Story 2 — Stacktrace-/Interna-Leak in der Fehlerantwort (Priority: P2)

Als Betreiber:in möchte ich erkennen, ob eine malforme Eingabe eine Fehlerantwort
provoziert, die **rohe Stacktraces, Exception-Klassen, absolute Pfade oder
SQL-/interne Fehlertexte** ausgibt (CWE-209).

**Why this priority**: Zweithäufigstes, gut beweisbares Fuzz-Ergebnis; verrät
Interna, die Folge-Angriffe erleichtern. Ergänzt US1 (Server *überlebt*, leakt
aber Details).

**Independent Test**: Verwundbarer Fixture reflektiert einen Python/JS-Traceback
im Fehler-Body → Finding (MEDIUM). Sauberer Fixture liefert eine generische,
strukturierte Meldung ohne Interna → kein Finding.

**Acceptance Scenarios**:

1. **Given** ein malformer Payload, **When** die Fehlerantwort einen
   Traceback-/Exception-/Pfad-Marker enthält, **Then** NOT_ENFORCED (Finding,
   Severity MEDIUM), mit dem geleakten (gekürzten, secret-bereinigten) Ausschnitt
   als Beleg.

---

### User Story 3 — Sichere Degradation ohne fuzzbaren Kontext (Priority: P3)

Als Nutzer:in möchte ich, dass der Check **niemals** ein stilles „sicher"
liefert, wenn er nicht sicher proben kann (kein lesendes Tool, opake Antworten,
Server nicht erreichbar, Baseline schon rot).

**Why this priority**: Prinzip III. Ein nicht durchführbarer Test ist kein Pass.

**Acceptance Scenarios**:

1. **Given** keine lesenden/fuzzbaren Tools (oder nur mutierende), **When** der
   Check läuft, **Then** INCONCLUSIVE mit klarer Begründung.
2. **Given** ein Baseline-Call schlägt schon fehl (Server rot/Timeout), **When**
   der Check läuft, **Then** INCONCLUSIVE (kein Payload wird als Ursache gewertet).
3. **Given** ein Payload führt zu einem **Timeout/Hang** (Baseline war gesund),
   **When** der Check läuft, **Then** INCONCLUSIVE **+ Triage-Hinweis** (möglicher
   DoS, manuell verifizieren) — **kein** eigenständiges Finding (FP-Vermeidung:
   Hang ≠ zweifelsfreier Crash).

---

### Edge Cases

- **Mutierende Tools**: werden **nie** gefuzzt (Namens-Heuristik `_MUTATE_HINTS`
  wie bei RBAC) — keine Datenveränderung durch den Check.
- **Legitime lange/valide Eingaben**: nur *schema-verletzende* bzw. klar
  übergroße Payloads werden gesendet; ein Server, der sie sauber annimmt oder
  ablehnt, bleibt befundfrei.
- **stdio-Crash-Semantik**: stirbt der Subprozess, ist der Kanal tot → der Check
  wertet das (nach gesundem Baseline) als Crash-Beleg und **stoppt** weiteres
  Fuzzing dieses Servers (ein Beweis genügt; keine verwaisten Prozesse).
- **Injection-Payloads** (Shell/URL/SQL) sind **out of scope** — das decken
  `CMD_INJECTION`/`SSRF_CHECK` (dynamisch/statisch) ab; hier geht es um
  Schema-*Robustheit*, nicht um Sink-Ausnutzung.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Der Check MUSS die Tool-Schemata via `tools/list` lesen und daraus
  **schema-abgeleitete** Fuzz-Payloads pro Parameter erzeugen (mind.: Typ-
  Mismatch, Übergröße, fehlendes Pflichtfeld, formatverletzend).
- **FR-002**: Der Check MUSS vor dem Fuzzen einen **gesunden Baseline-Call**
  bestätigen; scheitert der schon, ist das Verdikt INCONCLUSIVE (nicht Finding).
- **FR-003**: Der Check MUSS einen Crash nur dann als NOT_ENFORCED werten, wenn
  ein **Liveness-Recheck** nach dem Payload bestätigt, dass der Server nicht mehr
  antwortet (Prozess-Tod/Verbindungstod) — Prinzip V (Beleg, nicht Vermutung).
- **FR-004**: Der Check MUSS Fehlerantworten auf **Stacktrace-/Interna-Leaks**
  prüfen (Traceback-/Exception-/absolute-Pfad-/SQL-Marker) und einen Treffer als
  NOT_ENFORCED (MEDIUM) mit gekürztem Beleg werten (CWE-209).
- **FR-005**: Ein **strukturierter** Validierungsfehler (JSON-RPC `-32602`/
  `-32600`) ohne Interna-Leak, bei dem der Server am Leben bleibt, MUSS als
  ENFORCED (kein Finding) gewertet werden.
- **FR-006**: Der Check DARF **keine** mutierenden Tools fuzzen (nur lesende;
  im Zweifel NICHT proben).
- **FR-007**: Timeout/Hang, opake Antworten, kein fuzzbares Tool, Baseline-Fehler
  → INCONCLUSIVE (ggf. + Triage), niemals stilles „sicher", niemals geworfen.
- **FR-008**: Der Check MUSS über **HTTP und stdio** laufen (rein `call()`-
  basiert; keine Transport-Port-Erweiterung).
- **FR-009**: Es DARF KEINE neue Laufzeit-Abhängigkeit entstehen (stdlib-only).
- **FR-010**: Findings MÜSSEN OWASP **MCP05** (als ermöglichte Downstream-Klasse)
  + passende CWE (20/248/400/209), den auslösenden Payload-Typ + Parameter und
  eine konkrete Remediation tragen (Schema-Constraints: `maxLength`/`pattern`/
  `enum`/`format`; strukturierte Fehler ohne Interna; deny-by-default).

### Key Entities

- **FuzzPayload**: (Parameter, Payload-Klasse, konkreter Wert) — schema-abgeleitet.
- **FuzzProbe**: eine gesendete Payload + Drei-Zustands-Verdikt + secret-
  bereinigte `observed`-Notiz — strukturkompatibel zu `UrlFetchProbe`/`RbacProbe`.
- **FuzzProbeClass**: `TYPE_MISMATCH` | `OVERSIZED` | `MISSING_REQUIRED` |
  `MALFORMED_FORMAT` (bewusst **ohne** Injection-Klassen — die gehören anderen Checks).

## Success Criteria *(mandatory)*

- **SC-001**: Ein verwundbarer Fixture (crasht bei Typ-Mismatch/Übergröße;
  leakt Traceback) erzeugt SCHEMA_FUZZING-Findings; der saubere Fixture
  (validiert, `-32602`, kein Leak, bleibt am Leben) bleibt befundfrei.
- **SC-002**: Läuft nachweislich über **beide** Transporte (HTTP + stdio).
- **SC-003**: Ohne fuzzbares Tool / bei rotem Baseline / bei Hang → INCONCLUSIVE
  (kein Finding, kein Pass).
- **SC-004**: Keine Regression; Basis-Install bleibt dependency-frei; der Check
  fuzzt nachweislich **keine** mutierenden Tools.

## Assumptions

- Der Server deklariert brauchbare Schemata via `tools/list` (Typen/Required).
  Völlig schemalose/opake Server → INCONCLUSIVE.
- „Gesund" heißt: mind. ein lesendes Tool bzw. `tools/list` antwortet vor dem
  Fuzzen erfolgreich (Baseline).
- Ein einziger zweifelsfreier Crash/Leak genügt als Finding — der Check muss
  nicht erschöpfend alle Parameter durchfuzzen (FP-arm, schnell, CI-tauglich).
- Out of scope (entschieden): Injection-Sink-Ausnutzung (CMD/SSRF/SQL); reine
  Schema-Deklarations-Audits ohne Verhaltensbeleg (bewusst ausgeklammert — FP-arm
  bleiben; ggf. eigener künftiger Check); Last-/Rate-Limiting (künftiger
  `RATE_LIMITING`-Check).
