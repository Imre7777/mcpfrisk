# Feature Specification: TOOL_NAME_COLLISION (Tier 1, statisch)

**Feature Branch**: `011-tool-name-collision`

**Created**: 2026-07-05

**Status**: IMPLEMENTIERT (2026-07-05). checks/tool_name_collision.py, registriert in STATIC_CHECKS. Volle Suite grün (185/185).

**Input**: Erster von zwei neuen Checks aus dem Backlog-Punkt "neue Checks"
(MARKET-RESEARCH.md §4.5/§6.2): eine statische Erkennung, die noch KEIN
untersuchtes Produkt-Tool explizit anbietet und die mit der bestehenden
`SourceModel`-API (`tool_definitions()` liefert bereits Name + Datei + Zeile
pro Tool) nahezu ohne neue Infrastruktur baubar ist.

## Kontext / Motivation

**Sicherheits-Recherche (Prinzip VII, Stand 2026-07-05):** Tool-Name-Collision
/ Tool-Shadowing ist eine dokumentierte, benannte MCP-Angriffsklasse:
- **Invariant Labs** hat in einer Responsible Disclosure gezeigt, wie ein
  einzelner bösartiger MCP-Server über **Cross-Server Tool Shadowing**
  benachbarte, vertrauenswürdige Server "bewaffnet" -- ein Tool mit dem Namen
  eines vertrauten Tools registrieren, damit der Agent das falsche wählt.
- **Akto MCP Attack Matrix** führt "Tool Shadowing" als eigene
  Execution-Layer-Angriffstechnik.
- **Mend.io** prägte 2025 "**Shadow MCP**": ungeprüfte Server, die oft
  **kollidierende Namen** nutzen, um die freigegebenen ("approved") Server zu
  überschatten.
- Der akademische **MSB-Benchmark (arXiv 2510.15994)** listet
  "**Name-Collision**" als eigene der 12 Angriffskategorien.

Gemeinsamer Kern: ohne Namespacing hängt das Verhalten bei gleichnamigen Tools
von der Client-Implementierung und Verbindungsreihenfolge ab -- ein Tool kann
ein anderes still überschatten, und der Nutzer sieht keinen Hinweis darauf.

**Was McpFrisk hier realistisch prüfen kann (Scope-Ehrlichkeit, Prinzip V):**
Der eigentliche Angriff ist *cross-server* -- zwei verschiedene Server mit
gleichnamigen Tools. McpFrisk scannt aber den Quellcode **eines** Servers und
sieht andere Server nicht. Beweisbar aus einem Repo heraus sind daher:
1. **Exakte Namensduplikate INNERHALB des gescannten Servers** -- zwei
   Tool-Registrierungen mit identischem Namen. Das Client-Verhalten ist
   undefiniert; eine Registrierung überschattet die andere. Ein bösartig/
   nachlässig gebauter Server (oder eine eingebettete Dependency, die selbst
   Tools registriert) kann so ein harmlos aussehendes Tool durch ein
   zweites, gleichnamiges verdecken.
2. **Near-Duplicate-Namen INNERHALB des gescannten Servers** -- Namen, die
   sich nur minimal unterscheiden (Edit-Distanz 1, oder nur Groß/Klein-
   schreibung bzw. `_`/`-`-Trennung, oder einer ist Präfix des anderen):
   `get_user` vs. `get_users`, `read_file` vs. `readfile`, `sendMail` vs.
   `send_mail`. Das erzeugt Agent-Verwechslungsrisiko (dieselbe Confusion, die
   Shadowing ausnutzt), auch ohne exakte Kollision.

Beides ist **belegbar** (McpFrisk zitiert beide Fundstellen mit Datei+Zeile)
und wird von keinem generischen SAST-Tool erkannt -- genau die
MCP-spezifische Tiefe, die McpFrisks Nische ausmacht.

**OWASP/CWE-Mapping:** OWASP **MCP03** (Tool Poisoning -- Shadowing zählt zur
selben Execution-Layer-Manipulations-Familie, so gruppiert von Akto u.a.).
Präzise CWE: **CWE-706** (Use of Incorrectly-Resolved Name or Reference) --
genau die Namensauflösungs-Ambiguität, um die es geht.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Exaktes Tool-Namensduplikat (Priority: P1)

Als Server-Autor:in möchte ich gewarnt werden, wenn mein Server (über eine
oder mehrere Dateien) zwei Tools mit **identischem** Namen registriert -- eine
still überschattet die andere, und welche der Client wählt, ist undefiniert.

**Why this priority**: der direkteste, eindeutig belegbare Kollisionsfall;
plausibler Shadowing-Vektor (ein verstecktes Duplikat verdeckt ein
harmlos wirkendes Tool).

**Independent Test**: ein verwundbarer Fixture mit zwei `@mcp.tool()`-Funktionen
gleichen Namens (bzw. zwei `server.tool("x", …)`-Registrierungen in JS/TS) →
Finding (MEDIUM), das BEIDE Fundstellen nennt. Ein sauberer Fixture mit
eindeutigen Namen → kein Finding.

**Acceptance Scenarios**:

1. **Given** zwei Tool-Registrierungen mit demselben Namen im Scan-Ziel,
   **When** der Check läuft, **Then** genau EIN Finding (MEDIUM) für diesen
   Namen, dessen Beschreibung/Snippet beide Fundstellen (Datei:Zeile) nennt.
2. **Given** ein Scan-Ziel, dessen Tool-Namen alle eindeutig sind, **When**
   der Check läuft, **Then** kein Finding.

---

### User Story 2 — Near-Duplicate-Tool-Namen (Priority: P2)

Als Server-Autor:in möchte ich auf Tool-Namen hingewiesen werden, die sich so
ähnlich sind, dass ein Agent sie verwechseln kann (Edit-Distanz 1, reiner
Groß/Klein- bzw. `_`/`-`-Unterschied, oder Präfix-Beziehung).

**Why this priority**: schwächerer, aber realer Confusion-/Shadowing-
Vorbereitungs-Indikator; niedrigere Severity, weil häufiger legitim.

**Independent Test**: verwundbarer Fixture mit `get_item`/`get_items` (oder
`readFile`/`read_file`) → Finding (LOW), das beide nennt. Klar verschiedene
Namen (`get_item`/`delete_order`) → kein Finding.

**Acceptance Scenarios**:

1. **Given** zwei Tool-Namen mit Edit-Distanz 1 bzw. reinem Case/Separator-
   Unterschied, **When** der Check läuft, **Then** ein Finding (LOW) mit
   beiden Namen + Fundstellen.
2. **Given** zwei inhaltlich klar verschiedene Namen (Edit-Distanz > Schwelle,
   kein Präfix), **When** der Check läuft, **Then** kein Finding.

---

### User Story 3 — Keine False Positives bei normalem, eindeutigem Toolset (Priority: P3)

Als Nutzer:in möchte ich, dass ein Server mit einer normalen Menge klar
benannter Tools befundfrei bleibt (Prinzip III/V: keine Vermutung ohne
konkrete Kollision).

**Acceptance Scenarios**:

1. **Given** ein Scan-Ziel ganz OHNE Tool-Definitionen, **When** der Check
   läuft, **Then** kein Finding (nichts zu kollidieren).
2. **Given** Tools, die zwar ein gemeinsames Wort teilen, aber klar
   unterscheidbar sind (`list_users`, `create_user`, `delete_user`), **When**
   der Check läuft, **Then** kein Finding (Präfix/Suffix-Wortteilung allein
   ist keine Kollision).

---

### Edge Cases

- **Dasselbe Tool über denselben Namen an derselben Stelle doppelt gezählt**:
  darf nicht passieren -- jede Tool-Definition zählt einmal (Fundstelle =
  Datei+Zeile ist der Identitäts-Schlüssel gegen Doppelzählung).
- **Groß/Kleinschreibung**: `GetUser` vs. `getuser` gelten als
  Near-Duplicate (Case-insensitive-Gleichheit), nicht als exaktes Duplikat.
- **Sehr kurze Namen**: bei Namen ≤ 2 Zeichen ist Edit-Distanz 1 fast immer
  erfüllt -- Near-Duplicate-Prüfung wird für sehr kurze Namen unterdrückt
  (FP-Vermeidung), exakte Duplikate weiterhin gemeldet.
- **Cross-Server-Kollision**: bewusst OUT OF SCOPE -- McpFrisk sieht nur einen
  Server. Der Finding-Text macht diese Grenze transparent (kein Anspruch,
  Kollisionen mit fremden Servern zu erkennen).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Der Check MUSS `tool_definitions()` über ALLE Quelldateien des
  Scan-Ziels aggregieren (Tools können über mehrere Dateien verteilt sein) --
  für Python UND JS/TS über den bestehenden `SourceModel`-Port.
- **FR-002**: Zwei Tool-Definitionen mit **exakt identischem** Namen MÜSSEN
  als ein Finding (Severity MEDIUM, CWE-706, MCP03) gemeldet werden, das BEIDE
  Fundstellen (Datei:Zeile) im Beleg nennt.
- **FR-003**: Zwei Tool-Namen, die **near-duplicate** sind (Edit-Distanz 1 ODER
  Gleichheit nach Normalisierung von Case und `_`/`-`, ODER Präfix-Beziehung
  bei hinreichender Länge) und NICHT exakt gleich, MÜSSEN als ein Finding
  (Severity LOW) mit beiden Namen + Fundstellen gemeldet werden.
- **FR-004**: Ein Scan-Ziel ohne Tool-Definitionen oder mit ausschließlich
  klar verschiedenen Namen MUSS befundfrei bleiben (kein FP).
- **FR-005**: Der Check DARF jede Kollisions-Paarung nur EINMAL melden (keine
  A-B- und B-A-Doppelmeldung; keine Doppelzählung derselben Fundstelle).
- **FR-006**: Es DARF KEINE neue Laufzeit-Abhängigkeit entstehen (stdlib-only;
  Edit-Distanz per eigener kleiner Funktion, kein `python-Levenshtein`).
- **FR-007**: Findings MÜSSEN CWE-706 + MCP03, beide beteiligten Tool-Namen und
  ihre Fundstellen und eine konkrete Remediation (eindeutige, präfixierte
  Tool-Namen; Namespacing; keine gleichnamigen Registrierungen) tragen.

### Key Entities

- **ToolNameOccurrence**: (Name, Datei, Zeile) -- eine Tool-Registrierung
  (kommt direkt aus `tool_definitions()`).
- **CollisionKind**: `EXACT` (MEDIUM) | `NEAR_DUPLICATE` (LOW).

## Success Criteria *(mandatory)*

- **SC-001**: Ein verwundbarer Fixture (exaktes Duplikat) erzeugt ein
  MEDIUM-Finding mit beiden Fundstellen; ein Near-Duplicate-Fixture ein
  LOW-Finding; ein sauberer (eindeutige Namen) bleibt befundfrei.
- **SC-002**: Funktioniert nachweislich für Python UND JS/TS über den
  gemeinsamen `SourceModel`-Port (paired fixtures je Sprache).
- **SC-003**: Keine Kollisions-Paarung wird doppelt gemeldet; keine
  Doppelzählung derselben Fundstelle.
- **SC-004**: Keine Regression; Basis-Install bleibt dependency-frei;
  Plugin-Isolation gewahrt (neue Datei + ein Registry-Eintrag).

## Assumptions

- `tool_definitions()` erfasst die relevanten Registrierungsformen bereits
  (Python `@mcp.tool()`-Funktionen inkl. Name; JS/TS `server.tool(...)`/
  `.registerTool(...)`). Formen, die der Port nicht erkennt, sind auch für
  diesen Check unsichtbar -- das ist konsistent mit TOOL_POISONING und kein
  neuer Anspruch.
- Out of scope (entschieden): Cross-Server-Kollision (McpFrisk sieht einen
  Server); ein kuratierter Korpus "bekannter populärer Tool-Namen" zum
  Abgleich (fragil, FP-anfällig -- bewusst nicht in v1); semantische
  Ähnlichkeit jenseits der einfachen String-Heuristik (kein LLM/Embedding,
  zero-dependency-Anspruch).
