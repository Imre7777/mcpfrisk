# Implementation Plan: RBAC_CROSS_TENANT (006-rbac-cross-tenant)

**Spec**: [`spec.md`](./spec.md) | **Status**: Design entschieden — bereit zur Implementierung (auf Signal)

## Technical Context

Neuer dynamischer (Tier-2-)Check über `BaseDynamicCheck`/`DynamicRunner`. Im
Unterschied zu `AUTH_BOUNDARY`/`SSRF_CHECK` ist dieser Check **konfigurations-
getrieben**: er braucht **zwei Aufrufer-Identitäten**. Das ist die zentrale neue
Anforderung an die Transportschicht.

- **Sprache/Runtime**: Python 3.10+, **stdlib-only** (kein neuer Dep).
- **Voraussichtlich betroffene Dateien** (zur Review, noch nicht angefasst):
  - `mcpfrisk/checks/rbac_cross_tenant.py` *(neu)* — der Check.
  - `mcpfrisk/checks/registry.py` — ein Listeneintrag in `DYNAMIC_CHECKS`.
  - `mcpfrisk/core/dynamic_runner.py` / `core/stdio_transport.py` — **Identitäts-
    Erweiterung** des Transport-Ports (per-Identität Header/Token bzw. stdio-
    Mittel). Additiv, ohne bestehendes Verhalten zu ändern.
  - `mcpfrisk/cli.py` — Identitäts-Flags für `probe`.
  - `mcpfrisk/core/models.py` — ggf. `RbacProbe`/Fingerprint-Modell.
- **Neue Test-Artefakte** *(neu)*:
  - `tests/fixtures/rbac_servers.py` — multi-tenant HTTP-Fixture: `vulnerable`
    (IDOR + Tenant-Arg-Vertrauen) und `clean` (scoped per verifizierter Identität).
  - `tests/test_rbac_cross_tenant.py`.

## Architektur-Entscheidungen (entschieden — Best Practice)

1. **Identitäts-Anbindung = additive Transport-Erweiterung.** Der Transport-Port
   bekommt einen optionalen Identitäts-Parameter: `call(method, params, *,
   identity=None)`. Bestehende Aufrufe (ohne `identity`) bleiben **unverändert**
   (rückwärtskompatibel; auth/ssrf/stdio-Tests unberührt). Symmetrische API über
   beide Transporte:
   - **HttpTransport**: eine Verbindung, pro Call der identitäts-spezifische
     Header (Default `Authorization: Bearer <cred>`).
   - **StdioTransport**: **eine Subprozess-Instanz pro Identität** (lazily, in
     einem `dict` gehalten), jeweils mit identitäts-spezifischem **Env-Overlay**
     gespawnt. `close()` beendet alle Identitäts-Prozesse.
2. **CLI-Syntax (entschieden):** `--identity NAME=CREDENTIAL`, **wiederholbar**;
   die ersten zwei Identitäten werden als A und B verwendet.
   - **Secret-Hygiene (Best Practice, wichtig für ein Security-Tool):**
     `CREDENTIAL` darf `env:VARNAME` sein → der Wert wird aus der Umgebung gelesen,
     nicht in argv/Shell-History exponiert. Literale sind erlaubt, `env:` empfohlen.
   - `--auth-header NAME` (optional, HTTP): überschreibt den Header-Namen; bei
     Custom-Header wird `<cred>` **verbatim** gesendet (sonst `Bearer <cred>`).
   - `--identity-env VAR` (optional, stdio): Name der Env-Variable, die je
     Identitäts-Prozess auf `<cred>` gesetzt wird (Default z.B. `MCP_AUTH_TOKEN`).
   - Ohne `--identity` (oder mit < 2): der Check überspringt sich sauber
     (INCONCLUSIVE, FR-006/FR-007).
3. **stdio-Identität (entschieden): Env-Overlay pro Identitäts-Prozess.**
   Begründung Best Practice: die Recherche verlangt „Identität aus verifizierter
   Session, nicht aus Client-Header/Argument". Der reale stdio-Mechanismus dafür
   sind **env-basierte Credentials** (die Recherche nennt PATs in Env-Variablen
   ausdrücklich). Damit laufen **US1 (Replay) UND US2 (Arg-Injection) auch über
   stdio** — Parität zu HTTP, statt stdio auf inconclusive zu beschränken.
4. **Beweis statt Heuristik (Prinzip V).** Ein Finding entsteht nur, wenn B's
   Antwort einen **unter A erhobenen, eindeutigen Fingerprint** enthält
   (A-spezifische ID **und** ein nur unter A sichtbarer Inhaltsmarker müssen in
   B's Antwort auftauchen). Mehrdeutiges Listing-Overlap → INCONCLUSIVE +
   Triage-Hinweis, **kein** Finding.
5. **Read-only.** Discovery und Replay nutzen ausschließlich lesende Operationen
   (`tools/list`, lesende `tools/call`). Heuristik zur Erkennung „lesender" Tools
   (Name/Schema: `get|list|read|fetch|search|view` …); mutierende Namen
   (`create|update|delete|write|set|remove|patch|put`) werden für Proben
   konservativ gemieden (im Zweifel NICHT proben).

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Fixtures + Tests zuerst (rot), dann Check. |
| II. Plugin Isolation | ⚠️→✅ | Check ist isoliert; die **Identitäts-Erweiterung** berührt den Transport-Port — bewusst **additiv** (optionaler `identity`-Parameter, Default-None = altes Verhalten), kein Bruch bestehender Checks. Im Complexity-Tracking vermerkt. |
| III. FP over FN | ✅ | Beweis-gebunden; jeder Unklarheits-/Fehlerfall → INCONCLUSIVE (+Triage), nie stilles „sicher", nie geworfen. |
| IV. Zero Unnecessary Deps | ✅ | stdlib-only. |
| V. Evidence-Grounded | ✅ **zentral** | Finding nur bei nachweisbarem A-Fingerprint in B's Antwort. |
| VI. Paired Fixture Testing (NON-NEGOTIABLE) | ✅ | `vulnerable` (IDOR + Tenant-Arg) UND `clean` (scoped) Fixture. |
| VII. Security-Research Currency | ✅ | Frischer Research-Pass (OWASP MCP07, Asana, CVE-2026-54052, RFC 8707) in spec.md. |

**Gate-Ergebnis: PASS** mit einem Complexity-Tracking-Eintrag (Transport-Port-
Erweiterung um Identität — gerechtfertigt, weil kein RBAC-Test ohne zwei
Identitäten möglich ist; Alternative „Header im Check hart verdrahten" würde die
Plugin-Isolation stärker verletzen).

## Test Strategy (TDD, Prinzip I & VI)

`tests/fixtures/rbac_servers.py` (stdlib `http.server`, analog zu auth/ssrf):
- **vulnerable**: hält Daten für Tenant A und B; ein `get_record(id)`-Tool löst
  IDs **ohne** Owner-Prüfung auf (IDOR) und ein `list_records(tenant=…)`-Tool
  vertraut dem Argument (Tenant-Arg). A's Datensatz trägt einen eindeutigen
  Fingerprint.
- **clean**: leitet die Identität aus dem Token ab, scoped jede Antwort per
  verifiziertem Tenant; B sieht nie A's Fingerprint.

`tests/test_rbac_cross_tenant.py`:
- US1: vulnerable→Finding (B liest A's ID), clean→kein Finding.
- US2: vulnerable→Finding (Tenant-Arg-Injection), clean→kein Finding.
- US3: eine Identität → INCONCLUSIVE; mehrdeutiges Overlap → INCONCLUSIVE+Hinweis.
- Negativ/Sicherheit: keine mutierenden Calls (Fixture zählt Schreibversuche = 0).
- Regression: bestehende dynamische Tests (auth/ssrf) bleiben grün; Transport-
  Erweiterung ist rückwärtskompatibel.

Reihenfolge: Fixtures+Tests (rot) → Transport-Identitäts-Erweiterung →
Check (US1) → US2 → US3-Degradation → CLI-Flags → volle Suite grün → Doku.

## Risiken / Restunsicherheiten (Design entschieden)

- **Fingerprint-Robustheit**: „eindeutig A" = A-spezifische ID **und** ein nur
  unter A sichtbarer Inhaltsmarker müssen **beide** in B's Antwort auftauchen —
  so werden legitim geteilte Inhalte nicht fälschlich als Leak gewertet. Bei
  Restzweifel: INCONCLUSIVE + Triage-Hinweis statt Finding.
- **Lese-/Schreib-Klassifikation** der Tools ist heuristisch — konservativ (im
  Zweifel ein Tool **nicht** proben, nie mutieren).
- **stdio-Doppelspawn**: zwei Identitäts-Prozesse bedeuten doppelten Lifecycle;
  wird über den bestehenden, getesteten `StdioServerHandle` (Feature 005)
  abgewickelt (`close()` beendet alle). Test deckt „keine verwaisten Prozesse" ab.
- **Scope-Disziplin**: nur Cross-Tenant-Read-Leak; Privilege-Escalation/Scope-
  Creep (MCP02) bleibt ein separater künftiger Check.
