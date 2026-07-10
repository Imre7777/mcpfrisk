# Feature Specification: TOOL_DESCRIPTION_DRIFT (Tier 1, statisch, baseline-basiert)

**Feature Branch**: `015-tool-description-drift`

**Created**: 2026-07-05

**Status**: Design entschieden — IMPLEMENTIERT (2026-07-05). Phase 1b des
"Top-Produkt zuerst"-Plans: Rug-Pull-/Tool-Pinning-Erkennung, nutzt eine
Baseline-Datei (analog zu Feature 010).

**Input**: Neuer statischer Check + eine kleine CLI-Erweiterung. Erkennt, ob
sich eine Tool-Beschreibung seit einem **gepinnten, reviewten Stand** still
geändert hat — die Kern-Verteidigung gegen Rug-Pull-Angriffe.

## Kontext / Motivation

**Sicherheits-Recherche (Prinzip VII, Stand 2026-07-05):** Der **Rug-Pull /
Silent Redefinition** ist eine benannte, formalisierte MCP-Angriffsklasse:
- **CVE-2025-54136** (Rug-Pull-Attack in MCP): ein Server zeigt zunächst
  harmlose, nützliche Tools, um die einmalige Nutzer-Freigabe zu erhalten, und
  ändert danach **still** Tool-Definitionen/-Beschreibungen/-Verhalten.
- Cisco (Bhatt, Narajala, Habler) formalisieren Rug-Pull + Tool-Squatting als
  primäre MCP-Bedrohungsklassen; empfohlene Gegenmittel: **kryptografische
  Signierung von Tool-Definitionen, immutable Versionierung, Pinning**.
- Kernproblem: *„The MCP specification has no built-in mechanism for tracking
  tool definition changes or requiring re-approval"* — kein Signatur-/Versions-
  Zwang, keine Notification bei Änderung; der Agent ruft ein Tool weiter auf,
  dessen Bedeutung sich unter ihm verschoben hat. Die Änderung kann graduell/
  bedingt sein (Aufrufzahl, Uhrzeit) — Laufzeit-Erkennung ist schwer, ein
  **gepinnter Baseline der reviewten Definitionen** ist die praktische Abwehr.
- Existierende Tools: `mcp-scan` (Invariant) und `mcp-warden` erkennen
  Tool-Description-Änderungen über Pinning.

**Wie McpFrisk das pre-deploy/CI-nativ nutzt:** Ein Server-Autor (oder ein Team,
das einen Server vendored) **pinnt** die reviewten Tool-Beschreibungen als
Baseline-Datei im Repo (`.mcpfrisk-tools.json`, wie eine Lockfile). Bei jedem
Scan/PR flaggt McpFrisk jede Tool-Beschreibung, die sich gegenüber dem
gepinnten Stand geändert hat — und fängt so einen bösartigen Contributor, eine
tool-injizierende Dependency oder eine AI-generierte Description-Änderung, die
still eine Poisoning-Instruktion einschmuggelt. Der Check **komponiert** mit
`TOOL_POISONING` (jener sagt, *ob* der neue Text bösartig ist; dieser sagt,
*dass* er sich seit dem Review geändert hat).

**OWASP/CWE-Mapping:** OWASP **MCP04** (Supply Chain / Dependency Tampering —
eine über die Zeit veränderte Definition ist Tampering); präzise CWE:
**CWE-471** (Modification of Assumed-Immutable Data).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Geänderte Tool-Beschreibung seit dem Pin (Priority: P1)

Als Server-Autor:in / Reviewer:in möchte ich in CI gewarnt werden, wenn sich
die Beschreibung eines Tools gegenüber dem zuletzt **gepinnten, reviewten**
Stand geändert hat — damit eine still eingeschmuggelte Änderung (Rug-Pull /
Poisoning) nicht unbemerkt durch einen großen PR rutscht.

**Why this priority**: der Kern-Rug-Pull-Fall; ein reviewter Approval-Stand ist
die einzige verlässliche Referenz (die MCP-Spec bietet keine).

**Independent Test**: eine gepinnte `.mcpfrisk-tools.json` + eine Quelle, in der
die Beschreibung von Tool `get_item` seit dem Pin geändert wurde → Finding
(MEDIUM, CWE-471), das das Tool nennt und den aktuellen Text als Beleg zeigt.
Unveränderte Beschreibungen → kein Finding.

**Acceptance Scenarios**:

1. **Given** eine gepinnte Baseline und eine seither geänderte Tool-
   Beschreibung, **When** der Check läuft, **Then** ein Finding (MEDIUM,
   MCP04/CWE-471), das das Tool + einen Hinweis „prüfen und ggf. neu pinnen"
   trägt.
2. **Given** dieselbe Baseline und **unveränderte** Beschreibungen, **When**
   der Check läuft, **Then** kein Finding.

---

### User Story 2 — Neues, nicht gepinntes Tool (Priority: P2)

Als Reviewer:in möchte ich sehen, wenn ein Tool auftaucht, das nicht im
gepinnten Baseline steht — es wurde nie reviewt.

**Why this priority**: schwächeres Signal (neue Tools sind im Alltag normal),
aber ein untergeschobenes Tool ist genau der Vektor → niedrigere Severity.

**Independent Test**: Baseline ohne Tool `exfiltrate`, Quelle mit `exfiltrate`
→ Finding (LOW). Ein Tool, das im Baseline steht, → kein „neu"-Finding.

**Acceptance Scenarios**:

1. **Given** ein Tool in der Quelle, das nicht im Baseline ist, **When** der
   Check läuft, **Then** ein Finding (LOW, MCP04) „neues, nicht gepinntes Tool".

---

### User Story 3 — Opt-in + sichere Degradation (Priority: P3)

Als Nutzer:in möchte ich, dass das Feature **opt-in** ist (kein Rauschen ohne
Pin) und dass ich den Baseline bequem erzeugen/aktualisieren kann.

**Why this priority**: Prinzip III — ohne einen bewusst gepinnten Referenz-
Stand gibt es keine belastbare „Drift"-Aussage; der Check darf dann nichts
behaupten.

**Acceptance Scenarios**:

1. **Given** KEINE `.mcpfrisk-tools.json` im Ziel, **When** gescannt wird,
   **Then** erzeugt der Check nichts (skipped, kein FP).
2. **Given** `mcpfrisk scan <ziel> --write-tools-baseline`, **When** ausgeführt,
   **Then** wird `.mcpfrisk-tools.json` mit dem aktuellen Tool-Beschreibungs-
   Snapshot geschrieben (zum Review-Commit), Bestätigung ausgegeben.
3. **Given** eine beschädigte/nicht-parsebare Baseline, **When** gescannt wird,
   **Then** wird sie wie „nicht vorhanden" behandelt (kein Crash, kein Finding).

---

### Edge Cases

- **Kosmetische Reformatierung** (Whitespace): der Hash normalisiert Whitespace
  (führend/folgend strippen, interne Folgen kollabieren) — reine Umformatierung
  löst KEINE Drift aus, inhaltliche Änderung schon.
- **Entferntes Tool**: nicht geflaggt (v1) — Entfernen ist kein Rug-Pull.
- **Tool ganz ohne Beschreibung**: als leere Beschreibung gepinnt; das spätere
  Hinzufügen einer Beschreibung ist „geändert", nicht „neu".
- **Namensgleiche Tools**: Identität = Tool-Name (Kollisionen sind 011s Thema).
- **Python UND JS/TS**: die Snapshots kommen aus `tool_definitions()` über den
  gemeinsamen `SourceModel`-Port (beide Sprachen).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Es MUSS eine Tool-Beschreibungs-Snapshot-Funktion geben, die über
  alle Quelldateien des Ziels (Python + JS/TS) via `tool_definitions()` je Tool
  einen stabilen Hash der (whitespace-normalisierten) Beschreibung bildet.
- **FR-002**: Die Baseline wird als `<ziel>/.mcpfrisk-tools.json`
  (`{"version":1,"tools":{"<name>":"<hash>"}}`) gepinnt; ist das Ziel eine
  Datei, liegt sie neben der Datei.
- **FR-003**: Der Check `TOOL_DESCRIPTION_DRIFT` MUSS nur laufen, wenn eine
  Baseline existiert (`applies_to`); sonst ist er skipped (opt-in, kein FP).
- **FR-004**: Ein Tool, dessen aktueller Beschreibungs-Hash vom gepinnten
  abweicht, MUSS ein Finding MEDIUM (MCP04, CWE-471) mit Tool-Name + aktuellem
  Beschreibungs-Ausschnitt + Re-Pin-Hinweis erzeugen.
- **FR-005**: Ein Tool in der Quelle, das nicht im Baseline steht, MUSS ein
  Finding LOW (MCP04) „neues, nicht gepinntes Tool" erzeugen. Entfernte Tools
  werden nicht geflaggt.
- **FR-006**: `mcpfrisk scan <ziel> --write-tools-baseline` MUSS den aktuellen
  Snapshot nach `.mcpfrisk-tools.json` schreiben (Pin-Aktion, kein Scan-Gate),
  mit Bestätigung; eine beschädigte vorhandene Baseline blockiert das Schreiben
  nicht.
- **FR-007**: Eine beschädigte/nicht-parsebare Baseline MUSS wie „nicht
  vorhanden" behandelt werden (kein Crash, kein Finding).
- **FR-008**: stdlib-only (`hashlib`, `json`); KEINE Check-zu-Check-
  Abhängigkeit; nutzt den bestehenden `SourceModel`-Port + `iter_source_files`.

### Key Entities

- **Tool-Baseline**: JSON `{"version":1,"tools":{"<name>":"<sha256(desc)[:16]>"}}`.
- **DriftKind**: `CHANGED` (MEDIUM) | `NEW` (LOW).

## Success Criteria *(mandatory)*

- **SC-001**: Ein geänderter Beschreibungs-Hash → MEDIUM-Finding; ein neues,
  nicht gepinntes Tool → LOW; unveränderte + gepinnte Tools → befundfrei.
- **SC-002**: Ohne Baseline erzeugt der Check nichts (opt-in); malformte
  Baseline → kein Crash, kein Finding.
- **SC-003**: `--write-tools-baseline` erzeugt eine Baseline, die ein
  anschließender Scan als „kein Drift" liest (Round-Trip).
- **SC-004**: Funktioniert für Python UND JS/TS (paired fixtures); keine
  Regression; Basis-Install dependency-frei; Plugin-Isolation gewahrt.

## Assumptions

- Der Baseline wird bewusst ins Repo eingecheckt und im Review aktualisiert
  (Snapshot-/Lockfile-Muster) — genau wie bei `.mcpfrisk`-Findings-Baselines.
- Der Hash normalisiert Whitespace, damit reine Reformatierung kein Rauschen
  erzeugt; er speichert bewusst NUR den Hash (kompakt, kein Text-Leak) — der
  aktuelle (neue) Text steht als Beleg im Finding, der Reviewer vergleicht mit
  der Git-History.
- Out of scope (v1): dynamischer Rug-Pull-Check gegen einen laufenden Server
  (tools/list-Baseline über die Zeit — mögliche Tier-2-Erweiterung); Erkennung
  entfernter Tools; kryptografische Signatur (das wäre ein anderes, größeres
  Vorhaben — hier reicht das Pinning für den CI-Gate-Zweck).
