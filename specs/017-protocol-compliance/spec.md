# Feature Specification: PROTOCOL_COMPLIANCE (Tier 2, dynamisch)

**Feature Branch**: `017-protocol-compliance`

**Created**: 2026-07-12

**Status**: Design entschieden — in Implementierung. Phase 3 (Tier 3) des
"Top-Produkt zuerst"-Plans: der erste Spec-Compliance-Check. Braucht zuerst eine
kleine **Transport-Port-Erweiterung** (`call_response()` — die volle JSON-RPC-
Antwort inkl. `error`-Objekt), dann einen neuen dynamischen Check.

**Input**: Ein laufender MCP-Server, der auf eine **unbekannte JSON-RPC-Methode**
nicht mit dem korrekten, strukturierten JSON-RPC-2.0-Fehler antwortet — sondern
Erfolg vortäuscht (fail-open), einen falschen/nicht-standardkonformen Fehlercode
liefert oder ein malformtes Fehler-/Envelope-Objekt zurückgibt.

## Kontext / Motivation

**Sicherheits-Recherche (Prinzip VII, Stand 2026-07-12):**

- MCP baut auf **JSON-RPC 2.0** auf (modelcontextprotocol.io/specification).
  JSON-RPC 2.0 schreibt für eine unbekannte Methode zwingend einen Fehler mit
  **`code == -32601` ("Method not found")** vor; das `error`-Objekt MUSS ein
  ganzzahliges `code`- und ein String-`message`-Feld tragen, und jede Antwort
  MUSS `"jsonrpc": "2.0"` führen.
- **Fail-open-Fehlerbehandlung als Sicherheitsproblem:** Antwortet ein Server auf
  eine unbekannte/fehlerhafte Methode mit HTTP 200 + einem `result` (statt einem
  `error`), kann der aufrufende **Agent/Client nicht zuverlässig zwischen
  „fehlgeschlagen" und „erfolgreich" unterscheiden** — er läuft weiter, als sei
  der Aufruf geglückt. Das ist die klassische Improper-Handling-of-Exceptional-
  Conditions-Lücke (**CWE-703**) und ein realer Vertrauens-/Robustheitsbruch in
  einer Agenten-Pipeline.
- Spec-Conformance-Dimensionen tauchen in den akademischen MCP-Benchmarks
  (MCPSecBench, MSB) als eigene Achse auf; kein untersuchtes Pre-Deploy-Produkt
  prüft die JSON-RPC-Fehlersemantik eines **laufenden** Servers.

**Ehrliche Einordnung (Prinzip V):** Das ist primär ein **Protokoll-Korrektheits-/
Robustheits-Check** mit einem konkreten Sicherheits-Winkel (fail-open →
CWE-703). Die Severities bleiben entsprechend moderat: fail-open = MEDIUM,
falscher Code / malformtes Fehler- bzw. Envelope-Objekt = LOW. Das OWASP-MCP-
Top-10 hat (Stand 2026-07-12) **keine** dedizierte Kategorie dafür — der Check
trägt bewusst **keinen** `owasp_mcp_ref` (wie RATE_LIMITING), CWE-703 ist die
präzise Referenz.

**Warum FP-arm (Prinzip III):** Geprüft wird gegen die **eindeutige, universelle**
JSON-RPC-2.0-Vorgabe für eine garantiert unbekannte Methode — kein
Interpretationsspielraum. Ein spec-konformer Server (`-32601` + wohlgeformtes
Envelope) ist befundfrei. Der Trigger (eine zufällige, nie existente Methode) ist
gegen JEDEN Server sicher und braucht keine echten Tools.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Fail-open auf unbekannte Methode (Priority: P1)

Als Betreiber:in einer Agenten-Pipeline möchte ich erkennen, wenn ein MCP-Server
auf eine unbekannte JSON-RPC-Methode **keinen** Fehler zurückgibt, sondern
Erfolg vortäuscht — weil mein Agent dann nicht merkt, dass der Aufruf nie
ausgeführt wurde.

**Why this priority**: der sicherheitsrelevanteste Fall (fail-open, CWE-703).

**Independent Test**: Ein Server, der auf `mcpfrisk/probe_<rand>` mit
`{"result": {}}` (kein `error`) antwortet → 1 Finding (MEDIUM, CWE-703,
`MISSING_ERROR`). Ein Server, der korrekt `-32601` liefert → kein Finding.

**Acceptance Scenarios**:

1. **Given** ein Server, der eine unbekannte Methode mit einem `result` statt
   einem `error` beantwortet, **When** der Check läuft, **Then** ein Finding
   (MEDIUM, CWE-703) „fehlt strukturierter JSON-RPC-Fehler (fail-open)".
2. **Given** ein Server, der korrekt `error.code == -32601` + String-`message` +
   `"jsonrpc":"2.0"` liefert, **When** der Check läuft, **Then** kein Finding
   (ENFORCED).

---

### User Story 2 — Falscher/malformter Fehlercode (Priority: P2)

Als Reviewer:in möchte ich sehen, wenn der Server zwar einen Fehler liefert, aber
mit falschem Code oder malformtem Fehler-/Envelope-Objekt — ein schwächeres, aber
belastbares Nichtkonformitäts-Signal.

**Why this priority**: echte, aber weniger gravierende Spec-Abweichung → LOW.

**Independent Test**: unbekannte Methode → `error.code == -32000` (statt -32601)
→ 1 Finding (LOW, `WRONG_ERROR_CODE`). `error` ohne ganzzahliges `code` /
ohne String-`message` → LOW (`MALFORMED_ERROR`). Antwort ohne `"jsonrpc":"2.0"`
→ LOW (`MALFORMED_ENVELOPE`).

**Acceptance Scenarios**:

1. **Given** ein `error` mit anderem Code als -32601, **When** der Check läuft,
   **Then** 1 Finding (LOW, `WRONG_ERROR_CODE`).
2. **Given** ein `error` ohne int-`code` oder ohne String-`message`, **When** der
   Check läuft, **Then** 1 Finding (LOW, `MALFORMED_ERROR`).

---

### User Story 3 — Sichere Degradation + beide Transporte (Priority: P3)

Als Nutzer:in möchte ich, dass ein nicht erreichbarer/timeout-ender Server
INCONCLUSIVE ist (nie ein stiller Pass) und dass der Check über HTTP UND stdio
funktioniert.

**Acceptance Scenarios**:

1. **Given** ein nicht erreichbarer Server, **When** der Check läuft, **Then**
   INCONCLUSIVE (kein Finding, kein Pass).
2. **Given** derselbe fail-open-Server über **stdio**, **When** der Check läuft,
   **Then** dasselbe MEDIUM-Finding (Transport-Parität).

---

### Edge Cases

- **Read-only**: Der Check sendet ausschließlich EINE unbekannte, nie existente
  Methode — er ruft **kein** Tool auf, löst also nie eine Mutation aus.
- **HTTP 4xx/5xx mit JSON-RPC-Body**: Ein Server darf einen JSON-RPC-Fehler auch
  mit einem HTTP-Fehlerstatus transportieren; `call_response()` liest den Body
  dennoch und wertet das JSON-RPC-`error` aus (kein FP nur wegen HTTP-Status).
- **Envelope-Prüfung nur bei sonst korrektem Fehler**: fehlt der Fehler ganz
  (fail-open, MEDIUM), dominiert dieses Signal; das schwächere Envelope-Signal
  wird nicht zusätzlich gemeldet (ein Finding pro Probe, worst-case gewinnt).
- **protocolVersion / Handshake-Prüfung ist v1-out-of-scope** (s. Assumptions).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Der Transport-Port MUSS eine additive Methode `call_response(method,
  params, timeout_s, identity) -> dict` bereitstellen, die die **vollständige**
  geparste JSON-RPC-Antwort (inkl. `error`, `id`, `jsonrpc`) liefert — für HTTP
  UND stdio. `call()` bleibt unverändert (`= extract_jsonrpc_result(call_response
  (...))`), sodass alle bestehenden Checks byte-gleich weiterlaufen.
- **FR-002**: `call_response()` MUSS bei Transportfehlern (unreachable/Timeout/
  Größenlimit) eine `DynamicTransportError` werfen (der Check → INCONCLUSIVE);
  ein HTTP-4xx/5xx mit lesbarem Body wird als JSON-RPC-Antwort geparst, nicht als
  Transportfehler.
- **FR-003**: Der Check `PROTOCOL_COMPLIANCE` MUSS genau eine garantiert
  unbekannte Top-Level-JSON-RPC-Methode senden und die Antwort in dieser
  Priorität klassifizieren: kein `error` (fail-open) → `MISSING_ERROR` (MEDIUM);
  `error` ohne int-`code`/String-`message` → `MALFORMED_ERROR` (LOW); int-`code`
  ≠ -32601 → `WRONG_ERROR_CODE` (LOW); korrekter Fehler, aber Envelope ohne
  `"jsonrpc":"2.0"` → `MALFORMED_ENVELOPE` (LOW); sonst ENFORCED (kein Finding).
- **FR-004**: Transportfehler bei der Probe → INCONCLUSIVE (nie Finding, nie
  Pass). Der Check ruft kein Tool auf (read-only per Konstruktion).
- **FR-005**: Der Finding-Text nennt die beobachtete Abweichung + einen
  secret-bereinigten Antwort-Ausschnitt (Prinzip V), CWE-703, kein
  `owasp_mcp_ref`.
- **FR-006**: stdlib-only; KEINE Check-zu-Check-Abhängigkeit; nutzt die neue
  Port-Methode + `BaseDynamicCheck`. Registrierung in `DYNAMIC_CHECKS`.

### Key Entities

- **ProtocolProbeClass**: `MISSING_ERROR` (MEDIUM) | `WRONG_ERROR_CODE` (LOW) |
  `MALFORMED_ERROR` (LOW) | `MALFORMED_ENVELOPE` (LOW).
- **ProtocolProbe**: `outcome` + `to_dict()` (strukturkompatibel zu den anderen
  Tier-2-Proben, aggregiert von `BoundaryResult`).

## Success Criteria *(mandatory)*

- **SC-001**: fail-open → MEDIUM; falscher/malformter Code/Envelope → LOW;
  spec-konform → befundfrei.
- **SC-002**: nicht erreichbar → INCONCLUSIVE; nie ein stiller Pass.
- **SC-003**: Funktioniert über HTTP UND stdio (paired fixtures, beide
  Transporte).
- **SC-004**: `call()` byte-gleich wie zuvor; keine Regression in den fünf
  bestehenden dynamischen Checks. Read-only (keine Mutation ausgelöst).

## Assumptions

- Der Trigger ist eine zufällige `mcpfrisk/probe_<uuid>`-Methode — gegen jeden
  Server sicher und garantiert unbekannt.
- Out of scope (v1): (a) **protocolVersion-/Handshake-Compliance** — die Session
  verhandelt die Ära intern und HTTP macht gar kein `initialize`; eine saubere,
  transport-symmetrische protocolVersion-Prüfung wäre ein eigenes, größeres
  Vorhaben; (b) Prüfung der `-32700`/`-32600`/`-32602`-Pfade (Parse/Invalid-
  Request/Invalid-Params) — mehrdeutig gegenüber MCP-Tool-Result-Fehlern
  (`isError`), daher bewusst nur die **eindeutige** Method-not-found-Semantik;
  (c) Batch-Requests.
