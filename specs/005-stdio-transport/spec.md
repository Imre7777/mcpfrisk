# Feature Specification: Stdio-Transport für dynamische Checks

**Feature Branch**: `005-stdio-transport`

**Created**: 2026-06-29

**Status**: Draft

**Input**: User description: "stdio-Transport für den dynamischen Runner —
entriegelt AUTH_BOUNDARY + SSRF gegen echte stdio-Server."

## Kontext / Motivation

Die Real-Repo-Validierung (Feature 004) hat eine harte Abdeckungsgrenze
offengelegt: Die fertigen Tier-2-Checks (`AUTH_BOUNDARY`, `SSRF_CHECK`)
sprechen **ausschließlich HTTP**, aber die *große Mehrheit* echter MCP-Server
(inkl. `egoist/fetch-mcp` und fast aller Referenz-Server) läuft über den
**stdio-Transport**. Dynamische Checks erreichen die reale Mehrheit der Server
also bislang gar nicht — `probe` gegen einen stdio-Server endet heute korrekt,
aber unbefriedigend, als *inconclusive*.

Dieses Feature gibt dem `DynamicRunner` einen zweiten Transport: McpFrisk startet
den MCP-Server als Subprozess und kommuniziert per **newline-delimited JSON-RPC**
über dessen `stdin`/`stdout` (Logs auf `stderr`), exakt wie ein echter MCP-Client.

**Sicherheits-Recherche (Prinzip VII, Stand Juni 2026):** Der stdio-Transport ist
„Subprozess + zeilenweise JSON-RPC, keine eingebetteten Newlines". Es existieren
zwei Protokoll-Ären, die der Client unterscheiden muss:

- **Legacy** (≤ `2025-11-25`, stateful): erfordert den `initialize`- +
  `notifications/initialized`-Handshake, bevor `tools/list`/`tools/call` erlaubt sind.
- **Modern** (`DRAFT-2026-v1` / `2026-07-28`, stateless): kein Handshake;
  Protokollversion/Client-Info reisen pro Request in `_meta`; Discovery über die
  Methode `server/discover`.

Empfohlenes Client-Verhalten auf stdio: zuerst `server/discover` (mit bevorzugter
moderner Version in `_meta`) senden; bei einem erkannten modernen Fehler →
moderne Ära; bei *irgendeinem anderen* Fehler oder keiner Antwort → Fallback auf
den Legacy-`initialize`-Handshake. (Quelle: modelcontextprotocol.io
`/specification/draft/basic/transports/stdio`, Changelog SEP-2575.)

## User Scenarios & Testing *(mandatory)*

### User Story 1 - SSRF gegen einen stdio-Server beweisen (Priority: P1)

Als Server-Autor:in eines stdio-MCP-Servers (der Normalfall) möchte ich
`mcpfrisk probe` so gegen meinen Server richten können, dass der `SSRF_CHECK`
URL-akzeptierende Tools entdeckt und (out-of-band) beweist, ob mein Server zu
Requests gegen kontrollierte/interne Ziele gebracht werden kann — genau wie
heute schon gegen HTTP-Server.

**Why this priority**: Größter Hebel des Features. SSRF_CHECK ist gebaut, aber
für die reale Server-Mehrheit unerreichbar. Diese Story macht ihn praktisch nutzbar.

**Independent Test**: Ein Fixture-stdio-Server (Python-Skript, newline-JSON-RPC)
im `vulnerable`-Modus wird über `probe --stdio "<cmd>"` geprüft → ein
SSRF_CHECK-Finding. Im `clean`-Modus → kein Finding. Im `unreachable`-Fall
(Befehl existiert nicht / crasht) → inconclusive (kein Pass, kein Finding).

**Acceptance Scenarios**:

1. **Given** ein über stdio gestarteter, SSRF-verwundbarer MCP-Server, **When**
   `mcpfrisk probe --stdio "<cmd>"` läuft, **Then** entsteht ein SSRF_CHECK-Finding
   (out-of-band-Callback beobachtet).
2. **Given** ein über stdio gestarteter, abgesicherter Server, **When** geprüft
   wird, **Then** entsteht kein Finding (Build PASSED).
3. **Given** ein Befehl, der sofort crasht oder nicht existiert, **When** geprüft
   wird, **Then** ist das Ergebnis inconclusive (Prinzip III: nie stilles „sicher").

---

### User Story 2 - Tool-Discovery über beide Protokoll-Ären (Priority: P2)

Als Nutzer:in möchte ich, dass die Tool-Discovery (`tools/list`, `tools/call`)
sowohl gegen einen Legacy-Server (`initialize`-Handshake) als auch gegen einen
modernen, stateless Server (`server/discover` + `_meta`) funktioniert, damit das
Tool nicht an der Protokollversion des Ziels scheitert.

**Why this priority**: Ohne korrekte Era-Negotiation liefert `tools/list` bei
einem der beiden Server-Typen leer/Fehler → der Check würde fälschlich
inconclusive statt zu finden. Robustheit der P1-Funktion.

**Independent Test**: Derselbe verwundbare Fixture-Server einmal im
`legacy`-Handshake-Modus und einmal im `modern`-stateless-Modus → in beiden
Fällen wird das URL-Tool entdeckt und das Finding erzeugt.

**Acceptance Scenarios**:

1. **Given** ein stdio-Server, der nur den Legacy-`initialize`-Handshake kann,
   **When** geprobt wird, **Then** wird nach dem Handshake `tools/list` erfolgreich
   abgefragt.
2. **Given** ein moderner stateless stdio-Server, der auf `server/discover`
   antwortet, **When** geprobt wird, **Then** wird ohne Handshake (mit `_meta`)
   `tools/list` erfolgreich abgefragt.

---

### User Story 3 - Sauberer, zeitbegrenzter Prozess-Lebenszyklus (Priority: P3)

Als Nutzer:in (insb. in CI) möchte ich sicher sein, dass McpFrisk den gestarteten
Server-Subprozess zuverlässig wieder beendet und niemals unbegrenzt hängt, auch
wenn der Server nicht oder fehlerhaft antwortet.

**Why this priority**: Ein hängender oder verwaister Subprozess bricht das
CI-Gate und verschmutzt die Umgebung. Sicherheit/Betriebstauglichkeit.

**Independent Test**: Ein Fixture-Server, der nie antwortet → die Probe endet
innerhalb des Timeouts als inconclusive, und der Subprozess ist danach beendet
(kein verwaister Prozess).

**Acceptance Scenarios**:

1. **Given** ein stdio-Server, der auf Anfragen nicht antwortet, **When** geprobt
   wird, **Then** kehrt die Probe innerhalb des `--timeout` als inconclusive zurück.
2. **Given** eine abgeschlossene Probe (egal welches Ergebnis), **When** die
   Session schließt, **Then** ist der Subprozess terminiert (notfalls gekillt).

---

### Edge Cases

- **AUTH_BOUNDARY auf stdio**: stdio hat keinen Transport-Level-Auth-Boundary
  (keine HTTP-Header/Token). Der Check meldet hier weiterhin INCONCLUSIVE mit
  klarer Begründung — das ist korrekt, kein Fehler (und keine Regression der
  bestehenden HTTP-Logik).
- **Server schreibt Nicht-JSON auf stdout** (z.B. Banner-Logs): Zeilen, die kein
  gültiges JSON-RPC sind, werden ignoriert (Logs gehören laut Spec auf `stderr`).
- **Mehrere Zeilen / Out-of-order responses**: Antworten werden per JSON-RPC-`id`
  korreliert; Notifications (ohne `id`) werden übersprungen.
- **server/discover nicht implementiert (Legacy)**: Fallback auf `initialize`
  gemäß Recherche — der Fallback ist NICHT an einen einzigen Fehlercode gekoppelt.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Das System MUSS einen MCP-Server als Subprozess starten können und
  per newline-delimited JSON-RPC über `stdin`/`stdout` mit ihm kommunizieren
  (`stderr` = Logs/Diagnose, nicht Protokoll).
- **FR-002**: Das System MUSS eine generische `call(method, params)`-Operation über
  stdio bereitstellen, semantisch identisch zur bestehenden HTTP-`call()`, damit
  bestehende Checks (SSRF_CHECK) ohne Änderung darüber laufen.
- **FR-003**: Das System MUSS die Protokoll-Ära aushandeln: zuerst `server/discover`
  (modern, `_meta`), bei „anderem Fehler/keiner Antwort" Fallback auf den
  Legacy-`initialize`-+`notifications/initialized`-Handshake.
- **FR-004**: Das System MUSS Antworten per JSON-RPC-`id` korrelieren und
  Nicht-JSON-/Notification-Zeilen ignorieren.
- **FR-005**: Das System MUSS jede stdio-Operation zeitbegrenzen (`--timeout`) und
  bei Timeout/Transportfehler INCONCLUSIVE liefern statt zu hängen oder zu werfen.
- **FR-006**: Das System MUSS den Subprozess am Ende der Session zuverlässig
  beenden (graceful terminate, dann kill), ohne verwaiste Prozesse.
- **FR-007**: Die CLI MUSS ein stdio-Ziel akzeptieren (`probe --stdio "<command>"`),
  wechselseitig ausschließend mit `--server <url>`; genau eines ist erforderlich.
- **FR-008**: `AUTH_BOUNDARY` bleibt unverändert HTTP-spezifisch und meldet auf
  stdio INCONCLUSIVE mit klarer Begründung (keine Regression).
- **FR-009**: Es DARF KEINE neue Laufzeit-Abhängigkeit entstehen — stdio nutzt
  ausschließlich die Standardbibliothek (`subprocess`, `json`, `threading`).
- **FR-010**: Die Doku MUSS den Sicherheitshinweis enthalten, dass `--stdio` den
  angegebenen Befehl **ausführt** (Code-Ausführung) — nur gegen Server richten,
  denen man vertraut bzw. die man gerade testet.

### Key Entities

- **Transport (Port)**: gemeinsame Schnittstelle (`probe()`, `call()`,
  Lifecycle) mit zwei Adaptern: `HttpTransport` (bestehend) und `StdioTransport`.
- **DynamicSession**: hält genau einen Transport; die Checks bleiben transport-agnostisch.
- **StdioServerHandle**: kapselt den Subprozess (spawn, read-loop, write, terminate).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `mcpfrisk probe --stdio "<vulnerable fixture cmd>"` erzeugt ein
  SSRF_CHECK-Finding; der `clean`-Fixture-Server bleibt befundfrei.
- **SC-002**: Die Tool-Discovery gelingt sowohl gegen einen Legacy- als auch
  gegen einen modernen (stateless) Fixture-Server (US2).
- **SC-003**: Eine Probe gegen einen nicht-antwortenden Server endet innerhalb des
  Timeouts und hinterlässt keinen laufenden Subprozess (verifizierbar).
- **SC-004**: Keine Regression: alle bestehenden Tests bleiben grün; HTTP-`probe`
  verhält sich unverändert; Basis-Install bleibt dependency-frei.

## Assumptions

- Das stdio-Ziel wird als Shell-/Argument-Kommando angegeben; McpFrisk startet es
  und betrachtet es als „den laufenden Server" (analog zum HTTP-Endpunkt heute).
- Für die Era-Negotiation genügt ein pragmatischer Client (discover→initialize-
  Fallback); McpFrisk implementiert keinen vollständigen MCP-Client, nur so viel,
  wie `tools/list`/`tools/call` für die Checks brauchen.
- Default-Timeout bleibt `--timeout` (5s); pro Operation angewandt.
- Out of scope: HTTP+SSE-Sonderfälle, Sampling/Roots/Logging, Session-Resumption.
