# Feature Specification: RBAC_CROSS_TENANT (Tier 2, dynamisch)

**Feature Branch**: `006-rbac-cross-tenant`

**Created**: 2026-06-29

**Status**: Design entschieden (CLI-Identitäten + stdio-Env-Overlay festgelegt) —
bereit zur Implementierung auf Signal

**Input**: Roadmap-Punkt mit höchstem persönlichen Erfahrungswert (LeoWiki:
Student/Teacher-Namespace-Trennung). Nächster Tier-2-Check nach `SSRF_CHECK`,
jetzt dank stdio-Transport (Feature 005) gegen die reale Server-Mehrheit testbar.

## Kontext / Motivation

**Sicherheits-Recherche (Prinzip VII, Stand 2026-06-29):**
Tenant-/rollenübergreifende Datenleckage ist *Broken Access Control* und in der
**OWASP MCP Top 10** als **MCP07:2025 — Insufficient Authentication &
Authorization** geführt (verwandt: **MCP02** Privilege Escalation via Scope
Creep, **MCP10** Context Injection & Over-Sharing). Relevante CWEs:
**CWE-639** (IDOR / Authorization Bypass Through User-Controlled Key),
**CWE-862** (Missing Authorization), **CWE-863** (Incorrect Authorization),
**CWE-441** (Confused Deputy), **CWE-284** (Improper Access Control).

Dokumentierte reale Vorfälle:
- **Asana MCP (2025)** — Confused Deputy: gecachte Antworten wurden ohne
  erneute Tenant-Prüfung über Organisationsgrenzen hinweg ausgeliefert.
- **CVE-2026-54052 (n8n-mcp)** — DB-Queries nicht nach verifizierter `tenant_id`
  gescoped → Zugriff/Änderung/Löschung fremder Tenant-Daten.
- MCP-Spec `2025-06-18` machte **RFC 8707** (audience-bound Resource Indicators)
  verpflichtend, *weil* Confused-Deputy/Token-Passthrough real ausgenutzt wurden.

**Empfohlene Testmethodik (direkt aus den Quellen, u.a. OWASP Multi-Tenant
Cheat Sheet):** zwei Test-Identitäten/Tenants mit *unterschiedlichen* Daten
anlegen und beweisen, dass Identität A's Kontext **nie** B's Tool-Antworten,
Credentials oder Fehlermeldungen sieht. Jedes Tool, das Objekte per ID auflöst,
auf einen Ownership-Check (`id AND tenant_id`) prüfen. **Anti-Pattern**, das der
Check gezielt triggert: dem Server eine Tenant-/Owner-Kennung aus
Client-Header/Tool-Argument *vertrauen* zu lassen statt aus der verifizierten
Session.

**Kernidee des Checks:** McpFrisk agiert als zwei verschiedene Aufrufer (A und B)
gegen denselben laufenden Server und **beweist** einen Leak nur dann, wenn B eine
*nachweislich A-eigene* Ressource zu sehen bekommt (eindeutiger Fingerprint).
Kein Raten — wo kein Beweis möglich ist, lautet das Verdikt *inconclusive*.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — IDOR-Replay: B liest A's Ressource (Priority: P1)

Als Betreiber:in eines multi-tenant MCP-Servers möchte ich beweisen, ob ein
Aufrufer B eine Ressource abrufen kann, die nachweislich Aufrufer A gehört,
indem dieselbe Ressourcen-ID/-Referenz unter B's Identität wiederholt wird.

**Why this priority**: Der direkteste, beweisbare Cross-Tenant-Leak (IDOR,
CWE-639). Liefert das eindeutigste Verdikt mit geringstem False-Positive-Risiko.

**Independent Test**: Ein verwundbarer Fixture-Server (löst IDs ohne
Owner-Prüfung auf) → Finding; ein sauberer (scoped per verifizierter Identität)
→ kein Finding.

**Acceptance Scenarios**:

1. **Given** zwei Identitäten A/B und eine unter A entdeckte Ressourcen-ID mit
   eindeutigem A-Fingerprint, **When** B genau diese ID abruft, **Then** ist das
   Verdikt NOT_ENFORCED (Finding), sofern B's Antwort den A-Fingerprint enthält.
2. **Given** ein korrekt isolierender Server, **When** B A's ID abruft, **Then**
   erhält B 403/leer/eigene Daten (kein A-Fingerprint) → ENFORCED (kein Finding).

---

### User Story 2 — Tenant-Argument-Vertrauen (Priority: P2)

Als Betreiber:in möchte ich erkennen, ob der Server eine **aus dem Tool-Argument**
gelieferte Tenant-/Owner-Kennung vertraut (statt aus der verifizierten Session),
weil das der häufigste Cross-Tenant-Pfad ist.

**Why this priority**: Deckt die explizit als Anti-Pattern dokumentierte Klasse
ab (Tenant-ID aus Client-Eingabe). Ergänzt US1 um die Argument-Injection-Variante.

**Independent Test**: Verwundbarer Server, der ein `tenant`/`owner`/`org`-Argument
ungeprüft als Filter nutzt → B injiziert A's Tenant-Wert und sieht A's
Fingerprint → Finding. Sauberer Server ignoriert das Argument zugunsten der
Session → kein Finding.

**Acceptance Scenarios**:

1. **Given** ein Tool mit einem tenant-/owner-artigen Parameter, **When** B den
   Tool-Call mit A's Tenant-Wert ausführt, **Then** ist es NOT_ENFORCED, wenn die
   Antwort A's Fingerprint trägt.

---

### User Story 3 — Sichere Degradation ohne ausreichenden Kontext (Priority: P3)

Als Nutzer:in möchte ich, dass der Check **niemals** ein stilles „sicher"
liefert, wenn er den Beweis nicht führen kann (z.B. nur eine Identität
übergeben, keine tenant-scoped Ressource auffindbar, Server nicht multi-tenant).

**Why this priority**: Prinzip III. Ein nicht durchführbarer Test darf nie als
Pass missverstanden werden.

**Acceptance Scenarios**:

1. **Given** weniger als zwei Identitäten, **When** der Check läuft, **Then** ist
   das Verdikt INCONCLUSIVE mit klarer Begründung (keine Findings, kein Pass).
2. **Given** zwei Identitäten, aber unter A keine eindeutig identifizierbare
   Ressource auffindbar, **When** der Check läuft, **Then** INCONCLUSIVE.
3. **Given** ein mehrdeutiges Listing-Overlap (A und B sehen dieselben IDs, ohne
   beweisbaren A-Fingerprint), **When** der Check läuft, **Then** INCONCLUSIVE mit
   **Triage-Hinweis** (möglicher Leak, manuell verifizieren) — kein eigenständiges
   Finding (FP-Vermeidung).

---

### Edge Cases

- **Legitim geteilte Ressourcen** (öffentliche Tools, geteilte Kataloge): dürfen
  kein Finding erzeugen. Nur ein *eindeutiger, A-privater* Fingerprint in B's
  Antwort zählt als Beweis.
- **Server nicht multi-tenant / keine Auth**: außerhalb des Scopes dieses Checks
  (das deckt `AUTH_BOUNDARY` ab) → INCONCLUSIVE.
- **Identität über stdio** (keine HTTP-Header): eine Identität = ein
  **Env-Overlay**, mit dem McpFrisk je Identität einen eigenen Subprozess spawnt
  (real-world: env-basierte Credentials). Damit sind US1 **und** US2 auch über
  stdio abgedeckt (siehe plan.md).
- **Schreibende Proben**: der Check führt **keine** mutierenden Tool-Calls aus
  (kein create/delete) — nur lesende Discovery/Replay, um Fremd-Daten nicht zu
  verändern.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Der Check MUSS mit **zwei** Aufrufer-Identitäten (A, B) gegen
  denselben Server arbeiten können und Anfragen je Identität korrekt markieren.
- **FR-002**: Der Check MUSS unter A eine Ressource samt **eindeutigem
  Fingerprint** entdecken (read-only discovery), bevor er als B repliziert.
- **FR-003**: Der Check MUSS einen Leak nur als NOT_ENFORCED werten, wenn B's
  Antwort A's eindeutigen Fingerprint **nachweislich** enthält (Prinzip V: Beleg).
- **FR-004**: Der Check MUSS die Tenant-Argument-Injection-Variante prüfen (US2).
- **FR-005**: Der Check DARF **keine** mutierenden Operationen ausführen
  (nur lesend), um Fremd-Daten nicht zu verändern.
- **FR-006**: Bei < 2 Identitäten, fehlender scoped Ressource, Transport-/Timeout-
  Fehler oder mehrdeutigem Signal MUSS das Verdikt INCONCLUSIVE sein (Prinzip III),
  ggf. mit Triage-Hinweis — niemals stilles „sicher", niemals geworfen.
- **FR-007**: Identitäten MÜSSEN über die CLI angebbar sein: `--identity
  NAME=CREDENTIAL` (wiederholbar, erste zwei = A/B). `CREDENTIAL` unterstützt
  `env:VARNAME`, damit Secrets **nicht** in argv/Shell-History landen
  (Best Practice). Ohne bzw. mit < 2 Identitäten überspringt sich der Check sauber
  (INCONCLUSIVE). HTTP bindet die Identität als Header (Default
  `Authorization: Bearer <cred>`, via `--auth-header` überschreibbar); stdio als
  Env-Overlay je Identitäts-Prozess (`--identity-env VAR`).
- **FR-008**: Es DARF KEINE neue Laufzeit-Abhängigkeit entstehen (stdlib-only).
- **FR-009**: Findings MÜSSEN OWASP **MCP07** + passende CWE (639/863/441),
  Beleg (welcher Fingerprint wo gesehen) und eine konkrete Remediation tragen
  (Identität aus verifizierter Session, Ownership-Check `id AND tenant_id`,
  RFC 8707 audience-bound Tokens, keine Tenant-ID aus Client-Eingabe).

### Key Entities

- **CallerIdentity**: Label + Credential + Anbindung an Requests
  (HTTP: Header, Default `Authorization: Bearer`; stdio: Env-Overlay je Prozess).
- **ResourceFingerprint**: eindeutige, unter A beobachtete Markierung (ID +
  charakteristischer Antwort-Inhalt), die einen Leak zweifelsfrei macht.
- **RbacProbe**: eine A→discover / B→replay-Probe mit Drei-Zustands-Verdikt.

## Success Criteria *(mandatory)*

- **SC-001**: Ein verwundbarer Multi-Tenant-Fixture (IDOR + Tenant-Arg-Vertrauen)
  erzeugt je ein RBAC_CROSS_TENANT-Finding; der saubere Fixture bleibt befundfrei.
- **SC-002**: Mit nur einer Identität / ohne scoped Ressource → INCONCLUSIVE
  (kein Finding, kein Pass).
- **SC-003**: Keine Regression: bestehende Checks und Transporte unverändert;
  Basis-Install bleibt dependency-frei.
- **SC-004**: Der Check führt nachweislich keine mutierenden Calls aus.

## Assumptions

- Der/die Nutzer:in kann zwei test-Identitäten bereitstellen (z.B. zwei Bearer-
  Tokens für zwei Test-Tenants) — analog zur empfohlenen CI-Praxis „zwei
  Test-Tenants anlegen". Ohne sie ist der Check definitionsgemäß inconclusive.
- Lesbare, vergleichbare Tool-Antworten (Discovery liefert IDs/Inhalt). Völlig
  opake Server → inconclusive.
- HTTP-Identität via Header und stdio-Identität via Env-Overlay sind beide
  vollwertig unterstützt (Details in plan.md); Secrets werden über `env:`-
  Indirektion aus der Umgebung gelesen statt auf der Kommandozeile übergeben.
- Out of scope: Schreib-/Lösch-Tests, vollständige RBAC-Matrix-Exploration,
  Privilege-Escalation über Scope-Creep (eigener künftiger Check).
