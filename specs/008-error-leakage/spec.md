# Feature Specification: ERROR_LEAKAGE (Tier 2, dynamisch)

**Feature Branch**: `008-error-leakage`

**Created**: 2026-07-02

**Status**: Design entschieden — NICHT IMPLEMENTIERT. Bereit für Phase 1
(Modelle + rote Tests) auf Signal.

**Input**: Nächster Tier-2-Check laut Roadmap-Priorität nach `SCHEMA_FUZZING`
(007, implementiert). Baut wie 007 direkt auf dem `call()`-basierten
Transport-Port (HTTP **und** stdio, Feature 005) auf — keine
Transport-Erweiterung nötig.

## Kontext / Motivation

**Sicherheits-Recherche (Prinzip VII, Stand 2026-07-02):**

Aktuelle Best-Practice-Leitfäden für MCP-Server-Autoren warnen explizit davor,
Upstream-Fehler (DB-Treiber, ORMs, HTTP-Clients) ungefiltert an den Client
durchzureichen: *"Don't include stack traces, internal paths, or database
details in production error messages [...] sanitize error messages from
upstream services before passing them through"* (mcpcat.io,
Error-Handling-Guide für MCP-Server, 2026). Das ist real beobachtbar:
**CVE-2026-20205** (Splunk MCP Server) ist eine Information-Disclosure-
Schwachstelle, bei der Session-/Autorisierungs-Tokens durch unzureichende
Sanitisierung beim Logging/Fehlerhandling im Klartext offengelegt werden.

**OWASP-Mapping (mit Unschärfe-Hinweis):** Die offizielle OWASP-MCP-Top-10-
Kategorienliste (`OWASP/www-project-mcp-top-10`, geprüft 2026-07-02) kennt
**keine** dedizierte "Information Disclosure via Error Message"-Kategorie.
Die inhaltlich nächstgelegene (aber unscharfe) Kategorie ist **MCP08:2025 —
Lack of Audit and Telemetry**, die den Umgang mit Diagnose-/Telemetriedaten
adressiert. Die präzise, technologie-unabhängige Referenz bleibt **CWE-209**
(Information Exposure Through an Error Message) — identisch zu US2 von
`SCHEMA_FUZZING`, dort jedoch nur als Nebensignal bei **schema-verletzenden**
Payloads. Dieser Check deckt das gleiche Leak-Signal über **andere, rein
schema-KONFORME** Auslöser ab (siehe Abgrenzung unten).

**Abgrenzung zu `SCHEMA_FUZZING` (007, bereits implementiert) — wichtig, um
Redundanz zwischen den beiden Checks zu vermeiden (Prinzip II):**

| | `SCHEMA_FUZZING` (007) | `ERROR_LEAKAGE` (008, dieser Check) |
|---|---|---|
| Auslöser | schema-**verletzende** Payloads (Typ-Mismatch, Übergröße, fehlendes Pflichtfeld) | schema-**konforme**, harmlose Werte gegen drei "natürliche" Fehlerpfade |
| Zielt auf | Robustheit/Crash (+ Leak als Nebensignal) | ausschließlich Interna-Leak |
| Wer könnte das auslösen? | ein Angreifer mit malformen Argumenten | jede/r normale Nutzer:in im Alltag (Tippfehler, veraltete Tool-Referenz, gelöschte Ressource) |
| Crash-Nachweis? | ja (Liveness-Recheck, Fail-Fast) | nein (bewusst kein zweites Crash-Signal — das bleibt 007s Verantwortung) |

**Empfohlene Testmethodik (aus den Quellen):** drei garantiert-harmlose,
"natürliche" Fehlerauslöser senden und die Antwort auf Interna-Leak-Marker
prüfen: (1) ein **nicht-existenter Tool-Name**, (2) eine **unbekannte
JSON-RPC-Methode** (Protokoll-Ebene, `-32601`), (3) eine **schema-valide,
aber garantiert nicht-existente Ressourcen-ID** bei einem lesenden Tool
("record not found"-Pfad — klassischer Ort für einen durchgereichten
ORM-/SQL-Fehler). Alle drei sind auf **jedem** Server sicher durchführbar,
ohne echte Tool-Logik anzurühren oder Daten zu verändern.

**Kernidee des Checks:** McpFrisk sendet die drei o.g. harmlosen Fehler-
Auslöser an einen laufenden Server und prüft **ausschließlich** die
Antworttexte auf Interna-Leak-Marker (Traceback/Exception-Klasse/absoluter
Pfad/SQL-Fehlertext) — dieselbe konservative Marker-Erkennung wie in
`SCHEMA_FUZZING` US2, aber ohne dessen Crash-Fokus. Ein Server, der auf allen
drei Wegen generisch und strukturiert ablehnt, ist befundfrei.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Leak über unbekannten Tool-Namen (Priority: P1)

Als Betreiber:in möchte ich wissen, ob mein Server bei einem Aufruf eines
nicht-existenten Tools (z.B. Tippfehler, veraltete Client-Version) Interna
(Registry-Pfade, Exception-Klassen, Stacktrace) preisgibt statt generisch
"tool not found" zu melden.

**Why this priority**: Der sicherste und universellste Auslöser — funktioniert
auf jedem Server, unabhängig davon, welche Tools er hat, und rührt keine
echte Tool-Logik an.

**Independent Test**: Ein verwundbarer Fixture (der Dispatcher wirft bei
unbekanntem Namen eine ungefangene Exception, deren Traceback im
Fehler-Body landet) → Finding; ein sauberer (generische `-32602`/eigene
"unknown tool"-Meldung ohne Interna) → kein Finding.

**Acceptance Scenarios**:

1. **Given** ein laufender Server, **When** `tools/call` mit einem garantiert
   nicht existenten, eindeutigen Tool-Namen aufgerufen wird, **Then** wird
   die Antwort auf Leak-Marker geprüft; ein Treffer → NOT_ENFORCED (Finding,
   Severity MEDIUM).
2. **Given** derselbe Aufruf, **When** der Server generisch/strukturiert
   ablehnt (kein Leak-Marker in der Antwort), **Then** ENFORCED (kein Finding).

---

### User Story 2 — Leak über unbekannte JSON-RPC-Methode (Priority: P2)

Als Betreiber:in möchte ich wissen, ob eine gänzlich unbekannte
Protokoll-Methode (kein `tools/call`, kein `tools/list` — z.B. eine
optionale/nicht implementierte Methode) zu einer Interna-Leak-Antwort statt
zum korrekten `-32601 Method not found` führt.

**Why this priority**: Zweithäufigster, ebenso sicherer Auslöser auf reiner
Protokoll-Ebene — deckt Fehlerpfade außerhalb von `tools/call` ab, die
`SCHEMA_FUZZING` nie berührt.

**Independent Test**: Verwundbarer Fixture leakt bei unbekannter Methode
einen Traceback → Finding (MEDIUM). Sauberer Fixture liefert `-32601` ohne
Interna → kein Finding.

**Acceptance Scenarios**:

1. **Given** ein laufender Server, **When** eine garantiert unbekannte
   Top-Level-JSON-RPC-Methode gesendet wird, **Then** wird die Antwort auf
   Leak-Marker geprüft; ein Treffer → NOT_ENFORCED (MEDIUM).

---

### User Story 3 — Leak über nicht-existente Ressourcen-ID (Priority: P3)

Als Betreiber:in möchte ich wissen, ob ein lesendes Tool bei einer
wohlgeformten, aber nicht existenten Ressourcen-ID (klassischer
Alltagsfall: gelöschter Datensatz, falsche ID) einen rohen
Datenbank-/ORM-Fehler statt eines generischen "not found" zurückgibt.

**Why this priority**: Realistischster Alltags-Fall (kein Angriff nötig),
aber abhängig davon, dass der Server überhaupt ein lesendes Tool mit
ID-artigem Pflichtparameter hat — daher niedrigste Priorität.

**Independent Test**: Verwundbarer Fixture reflektiert bei nicht-existenter
ID einen ORM-/SQL-Fehlertext → Finding (MEDIUM). Sauberer Fixture liefert
`{"item": null}`/generisches "not found" → kein Finding.

**Acceptance Scenarios**:

1. **Given** ein lesendes Tool mit einem ID-artigen Pflichtparameter,
   **When** ein schema-valider, aber garantiert nicht-existenter Wert
   gesendet wird, **Then** wird die Antwort auf Leak-Marker geprüft; ein
   Treffer → NOT_ENFORCED (MEDIUM).
2. **Given** kein lesendes Tool mit ID-artigem Parameter existiert,
   **When** der Check läuft, **Then** entfällt diese Probe ohne den
   Gesamtbefund zu beeinträchtigen (US1/US2 laufen unabhängig davon).

---

### Edge Cases

- **Server ganz ohne Tools**: US1/US2 bleiben trotzdem durchführbar (beide
  brauchen keine echten Tools); US3 entfällt mangels ID-Parameter.
- **Zufällige Namenskollision**: der Sentinel-Tool-Name für US1 MUSS
  praktisch garantiert nicht existieren (zufälliges, eindeutiges Suffix).
- **Mutierende Tools**: werden für US3 **nie** als Ziel verwendet (gleiche
  `_MUTATE_HINTS`-Namens-Heuristik wie `RBAC_CROSS_TENANT`/`SCHEMA_FUZZING`).
- **Server crasht unerwartet während einer Probe**: das ist NICHT die
  Verantwortung dieses Checks (kein Crash-Nachweis-Mechanismus hier, siehe
  Abgrenzungstabelle oben) — die betroffene Probe wird als nicht auswertbar
  übersprungen, die übrigen Proben werden trotzdem versucht; kein eigenes
  Finding daraus.
- **Injection-Payloads, schema-verletzende Payloads**: out of scope — das
  deckt `CMD_INJECTION`/`SSRF_CHECK`/`SCHEMA_FUZZING` ab.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Der Check MUSS `tools/call` mit einem garantiert nicht
  existenten, eindeutigen Tool-Namen aufrufen (US1) und die Antwort auf
  Interna-Leak-Marker prüfen.
- **FR-002**: Der Check MUSS eine garantiert unbekannte, gänzlich erfundene
  Top-Level-JSON-RPC-Methode aufrufen (US2) und die Antwort auf
  Interna-Leak-Marker prüfen.
- **FR-003**: Der Check MUSS, sofern mindestens ein lesendes Tool mit
  ID-artigem Pflichtparameter existiert, diesem einen schema-validen, aber
  garantiert nicht-existenten Wert senden (US3) und die Antwort auf
  Interna-Leak-Marker prüfen. Existiert kein solches Tool, entfällt US3 ohne
  das Gesamtergebnis negativ zu beeinflussen.
- **FR-004**: Ein Leak-Marker-Treffer (Traceback-/Exception-Klassen-/
  absoluter-Pfad-/SQL-Fehler-Muster) MUSS als NOT_ENFORCED (Severity MEDIUM,
  CWE-209) mit einem gekürzten, secret-bereinigten Beleg gewertet werden.
- **FR-005**: Eine strukturierte, generische Fehlerantwort ohne Leak-Marker
  MUSS als ENFORCED (kein Finding) gewertet werden.
- **FR-006**: Der Check DARF **keine** mutierenden Tools als US3-Ziel wählen
  (Namens-Heuristik, im Zweifel NICHT proben).
- **FR-007**: Der Check DARF **keine** schema-verletzenden/malformen
  Payloads senden (das ist `SCHEMA_FUZZING`-Scope) und implementiert **keinen**
  eigenen Crash-Nachweis-Mechanismus (kein Liveness-Recheck) — ein
  Transportfehler während einer Probe macht NUR diese Probe nicht auswertbar.
- **FR-008**: Ist der Server nicht erreichbar oder ist **keine** der drei
  Proben durchführbar/auswertbar, MUSS der Check INCONCLUSIVE liefern —
  niemals ein stilles „sicher", niemals eine Exception nach außen werfen.
- **FR-009**: Der Check MUSS über **HTTP und stdio** laufen (rein `call()`-
  basiert; keine Transport-Port-Erweiterung).
- **FR-010**: Es DARF KEINE neue Laufzeit-Abhängigkeit entstehen
  (stdlib-only).
- **FR-011**: Findings MÜSSEN CWE-209, eine best-effort OWASP-MCP-Referenz
  (siehe Kontext-Abschnitt zur Unschärfe), die auslösende Probe-Klasse und
  eine konkrete Remediation (generische, strukturierte Fehler; Sanitisierung
  von Upstream-Fehlern; Details ausschließlich serverseitig loggen) tragen.

### Key Entities

- **ErrorProbeClass**: `UNKNOWN_TOOL` | `UNKNOWN_METHOD` |
  `NONEXISTENT_RESOURCE` — bewusst **ohne** Crash- oder Injection-Klassen.
- **ErrorProbe**: (Tool/Methode, Parameter, Probe-Klasse, Drei-Zustands-
  Verdikt, secret-bereinigte `observed`-Notiz) — strukturkompatibel zu
  `FuzzProbe`/`RbacProbe`/`UrlFetchProbe`.

## Success Criteria *(mandatory)*

- **SC-001**: Ein verwundbarer Fixture (leakt bei allen drei Triggern
  Interna) erzeugt ERROR_LEAKAGE-Findings; der saubere Fixture (generische,
  strukturierte Fehler) bleibt befundfrei.
- **SC-002**: Läuft nachweislich über **beide** Transporte (HTTP + stdio).
- **SC-003**: Server unreachable / keine der drei Proben durchführbar →
  INCONCLUSIVE (kein Finding, kein Pass); fehlt nur das US3-Tool, laufen
  US1/US2 trotzdem regulär und liefern ein belastbares ENFORCED/NOT_ENFORCED.
- **SC-004**: Keine Regression; Basis-Install bleibt dependency-frei; der
  Check berührt nachweislich **keine** mutierenden Tools.

## Assumptions

- Der Server ist per `tools/list` ansprechbar (für US1/US2 genügt bereits
  eine leere Toolliste — beide brauchen keine echten Tools).
- Kein separater Baseline-Call wie bei `SCHEMA_FUZZING` nötig: alle drei
  Probe-Klassen lösen per Definition einen *erwarteten* Fehlerpfad aus, es
  gibt keinen "gesunden" Vergleichsfall, gegen den man abgrenzen müsste.
- Out of scope (entschieden): Crash-Nachweis (bleibt `SCHEMA_FUZZING`-
  Verantwortung, Prinzip II — keine Redundanz zwischen Checks);
  Injection-Sink-Ausnutzung (CMD/SSRF-Scope); schema-verletzende Payloads
  (SCHEMA_FUZZING-Scope); serverseitige Log-Leaks (von außen nicht prüfbar —
  reine Response-Analyse).
