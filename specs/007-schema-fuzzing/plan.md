# Implementation Plan: SCHEMA_FUZZING (007-schema-fuzzing)

**Spec**: [`spec.md`](./spec.md) | **Status**: Design entschieden — NICHT
IMPLEMENTIERT. Beide Design-Punkte nach Best Practice festgelegt (siehe unten).
Bereit für Phase 1 auf Signal.

## Technical Context

Neuer dynamischer (Tier-2-)Check über `BaseDynamicCheck`/`DynamicRunner`. Im
Gegensatz zu `RBAC_CROSS_TENANT` braucht dieser Check **keine** Konfiguration und
**keine** Transport-Erweiterung — er ist rein `call()`-basiert und läuft damit
sofort über HTTP **und** stdio. Das macht ihn architektonisch „billig"
(Plugin-Isolation voll erfüllt).

- **Sprache/Runtime**: Python 3.10+, **stdlib-only** (kein neuer Dep).
- **Voraussichtlich betroffene Dateien** (zur Review, noch nicht angefasst):
  - `mcpfrisk/checks/schema_fuzzing.py` *(neu)* — der Check.
  - `mcpfrisk/checks/registry.py` — ein Listeneintrag in `DYNAMIC_CHECKS`.
  - `mcpfrisk/core/models.py` — `FuzzProbe` + `FuzzProbeClass` (analog `RbacProbe`).
  - **KEINE** Änderung an `dynamic_runner.py`/`stdio_transport.py` (Ziel-Design;
    siehe „Offene Entscheidung 2" zur Crash-Erkennung).
- **Neue Test-Artefakte** *(neu)*:
  - `tests/fixtures/fuzzing_servers.py` — HTTP-Fixture: `vulnerable` (crasht /
    leakt Traceback) und `clean` (validiert, `-32602`, kein Leak).
  - Erweiterung von `tests/fixtures/stdio_server.py` um einen `fuzz`-Modus
    (bzw. eigener stdio-Fuzz-Server) für die stdio-Transport-Abdeckung.
  - `tests/test_schema_fuzzing.py`.

## Architektur-Entscheidungen (Entwurf)

1. **Rein `call()`-basiert, transport-blind.** Der Check nutzt ausschließlich
   `session.call("tools/list")` und `session.call("tools/call", …)`. Damit läuft
   er ohne Sonderfall über beide Transporte — keine neue Port-Fläche.
2. **Beweis statt Vermutung (Prinzip V).** Zwei harte Signale ergeben ein Finding:
   - **Crash** = nach *gesundem Baseline* führt ein Payload dazu, dass ein
     **Liveness-Recheck** (`tools/list`) fehlschlägt (Prozess-/Verbindungstod).
     → NOT_ENFORCED, Severity **HIGH** (stdio-Prozess-Tod) bzw. **MEDIUM**
     (HTTP-500 mit Traceback, Server überlebt).
   - **Interna-Leak** = die Fehlerantwort enthält einen Traceback-/Exception-/
     absolute-Pfad-/SQL-Marker. → NOT_ENFORCED, Severity **MEDIUM** (CWE-209).
   Ein **strukturierter** JSON-RPC-Fehler (`-32602`/`-32600`) ohne Leak, Server
   lebt → ENFORCED. **Hang/Timeout** → INCONCLUSIVE + Triage (kein Finding).
3. **Schema-abgeleitete Payloads.** Pro lesendem Tool wird das `inputSchema`
   gelesen und je Parameter eine kleine, gezielte Payload-Menge erzeugt:
   `TYPE_MISMATCH` (Zahl/Objekt/Array/null statt String etc.), `OVERSIZED`
   (sehr langer String / tief geschachteltes Objekt), `MISSING_REQUIRED`
   (Pflichtfeld weglassen), `MALFORMED_FORMAT` (formatverletzend, z.B. Nicht-URL
   für `format: uri`). **Kein** Injection-Payload (anderer Check-Scope).
4. **Read-only + Fail-fast.** Nur lesend klassifizierte Tools (Namens-Heuristik
   wie bei RBAC) werden gefuzzt; beim ersten zweifelsfreien Crash wird gestoppt
   (ein Beweis genügt, keine verwaisten stdio-Prozesse, CI-schnell).
5. **Leak-Marker konservativ.** Erkennung über eindeutige Muster
   (`Traceback (most recent call last)`, `at Object.<anonymous>`, `File "…", line`,
   Exception-Klassennamen, absolute Pfade `/…`/`C:\…`, SQL-Fehlertexte). Kurze/
   generische Strings zählen **nicht** → FP-arm.

## Entschiedene Design-Punkte (Best Practice)

1. **Schema-Deklarations-Advisory → ausgeklammert (entschieden).** v1 bleibt
   **rein verhaltensbasiert**. Begründung Best Practice: ein statisches
   „unconstrained param"-Audit ist inhärent FP-anfällig (viele Parameter sind
   legitim unbeschränkt) und würde Prinzip V (Beleg statt Vermutung) und die
   Rausch-Armut verwässern. Ein solches Deklarations-Audit gehört — wenn
   überhaupt — in einen separaten, klar abgegrenzten künftigen Check, nicht in
   die Default-Findings von SCHEMA_FUZZING.
2. **Crash-Erkennung → Liveness-Recheck, kein Transport-Umbau (entschieden).**
   Nach gesundem Baseline belegt ein fehlschlagender `call('tools/list')` nach dem
   Payload den Crash. Kleinster Eingriff mit solidem Beleg; **Plugin-Isolation
   bleibt unangetastet** (Prinzip II voll erfüllt). Eine additive
   `Transport.is_alive()`-Fläche wird **nur** eingeführt, falls Tests zeigen, dass
   Crash vs. bloße Ablehnung sonst nicht sauber trennbar ist — Default-Design ist
   der Recheck.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Fixtures + Tests zuerst (rot), dann Check. |
| II. Plugin Isolation | ✅ | Reiner Plugin-Check, **keine** Transport-/Core-Änderung (Ziel-Design). |
| III. FP over FN | ✅ | Crash nur per Liveness-Beleg; Hang → INCONCLUSIVE+Triage; strukturierter Fehler → Pass. |
| IV. Zero Unnecessary Deps | ✅ | stdlib-only. |
| V. Evidence-Grounded | ✅ **zentral** | Finding nur bei bewiesenem Crash oder konkret geleaktem Interna-Ausschnitt. |
| VI. Paired Fixture Testing (NON-NEGOTIABLE) | ✅ | `vulnerable` (crasht/leakt) UND `clean` (validiert, `-32602`) Fixture, HTTP + stdio. |
| VII. Security-Research Currency | ✅ | Frischer Research-Pass (OWASP MCP05, VIPER-MCP 2605.21392, CVE-2026-32871, CVE-2025-6514) in spec.md. |

**Gate-Ergebnis: PASS** (keine Complexity-Tracking-Einträge nötig — anders als
006 gibt es keine Transport-Erweiterung).

## Test Strategy (TDD, Prinzip I & VI)

`tests/fixtures/fuzzing_servers.py` (stdlib `http.server`, analog auth/ssrf/rbac):
- **vulnerable**: `get_item(id: string)`-Tool, dessen Handler bei nicht-String/
  Übergröße eine ungefangene Exception wirft → HTTP-500 **mit Python-Traceback**
  im Body; eine Variante beendet den Prozess (für stdio-Crash-Test).
- **clean**: validiert jeden Parameter, antwortet mit JSON-RPC `-32602 Invalid
  params` (generisch, kein Interna-Leak), bleibt am Leben.

`tests/fixtures/stdio_server.py`: `fuzz`-Modus ergänzen (Crash bei Payload =
`sys.exit`/unhandled → Prozess-Tod; clean = strukturierter Fehler), damit
US1/US2 auch über stdio getestet werden (Prinzip VI, Transport-Parität).

`tests/test_schema_fuzzing.py`:
- US1: vulnerable→Finding (Crash per Liveness bestätigt; HIGH bei Prozess-Tod),
  clean→kein Finding. Beide Transporte.
- US2: vulnerable→Finding (Traceback-Leak, MEDIUM), clean→kein Finding.
- US3: kein lesendes Tool → INCONCLUSIVE; roter Baseline → INCONCLUSIVE;
  Hang → INCONCLUSIVE + Triage-Hinweis (kein Finding).
- Sicherheit: kein mutierendes Tool wird gefuzzt (Fixture zählt Aufrufe = 0).
- Regression: bestehende dynamische Tests (auth/ssrf/rbac/stdio) bleiben grün.

Reihenfolge: Fixtures+Tests (rot) → `FuzzProbe`/`FuzzProbeClass` in models →
Check US1 (Crash) → US2 (Leak) → US3-Degradation → Registry → volle Suite grün → Doku.

## Risiken / Restunsicherheiten

- **Crash vs. bloße Ablehnung** sauber trennen (→ Liveness-Recheck; Fallback
  `is_alive()` nur bei Bedarf, siehe Offene Entscheidung 2).
- **stdio-Kanaltod**: nach Crash ist der Kanal unbrauchbar → nach erstem Beweis
  stoppen; Test deckt „keine verwaisten Prozesse" ab (`close()` beendet alles).
- **Leak-Marker-Präzision**: konservative, eindeutige Muster, um FP durch
  harmlose Fehlertexte zu vermeiden.
- **Scope-Disziplin**: keine Injection-Payloads (CMD/SSRF-Scope), kein Last-Test
  (RATE_LIMITING), kein reines Schema-Audit (Offene Entscheidung 1).
