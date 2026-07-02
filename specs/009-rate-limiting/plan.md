# Implementation Plan: RATE_LIMITING (009-rate-limiting)

**Spec**: [`spec.md`](./spec.md) | **Status**: IMPLEMENTIERT (2026-07-02).
Beide Design-Punkte wie unten festgelegt umgesetzt; keine Transport-/Core-
Änderung war nötig. Volle Suite grün (123/123).

## Technical Context

Letzter dynamischer (Tier-2-)Check der ursprünglichen Roadmap, strukturell
wie `SCHEMA_FUZZING`/`ERROR_LEAKAGE`: keine Konfiguration, keine
Transport-Erweiterung, rein `call()`-basiert.

- **Sprache/Runtime**: Python 3.10+, **stdlib-only** (kein neuer Dep, `time`
  für Latenzmessung genügt).
- **Voraussichtlich betroffene Dateien** (zur Review, noch nicht angefasst):
  - `mcpfrisk/checks/rate_limiting.py` *(neu)* — der Check.
  - `mcpfrisk/checks/registry.py` — ein Listeneintrag in `DYNAMIC_CHECKS`.
  - `mcpfrisk/core/models.py` — `RateLimitProbe` + `RateLimitProbeClass`
    (analog `ErrorProbe`/`FuzzProbe`).
  - **KEINE** Änderung an `dynamic_runner.py`/`stdio_transport.py`.
- **Neue Test-Artefakte** *(neu)*:
  - `tests/fixtures/rate_limiting_servers.py` — HTTP-Fixture mit
    deterministischen Modi: `throttled` (429 ab fester Schwelle, sonst
    schnell), `degrading` (Antwortzeit steigt deterministisch mit der
    Aufrufzahl im Burst, kein Cap), `crash` (stellt Antworten nach fester
    Aufrufzahl im Burst komplett ein, analog `fuzzing_servers.py`s
    `_kill_server`), `fast` (konstant schnell, kein Drossel-Signal nötig).
  - Erweiterung von `tests/fixtures/stdio_server.py` um ein viertes
    `--toolset burst` (gleiches Muster wie `fuzz`/`errors`).
  - `tests/test_rate_limiting.py`.

## Architektur-Entscheidungen (Entwurf)

1. **Rein `call()`-basiert, transport-blind** (wie 007/008) — Baseline +
   Burst rein über `session.call(...)`.
2. **v1 = schneller SEQUENZIELLER Burst, keine echte Multi-Thread-
   Parallelität** (Details siehe Entschiedener Design-Punkt 1 unten).
3. **Zwei harte Signale, ein sofortiger Pass-Fall:**
   - Ein Drossel-Hinweis (HTTP 429 / erkennbarer Rate-Limit-Fehlertext) an
     JEDER Stelle im Burst → sofort ENFORCED, Rest des Bursts wird nicht
     mehr bewertet.
   - **Crash** = Liveness-Recheck (`tools/list`) nach dem Burst schlägt fehl
     (nach gesundem Baseline) → NOT_ENFORCED, Severity **HIGH** (CWE-400).
   - **Degradation** = kein Crash, kein Drossel-Signal, aber die
     Burst-Latenz überschreitet einen klar definierten Vielfachen-
     Schwellenwert der Baseline-Latenz → NOT_ENFORCED, Severity **MEDIUM**
     (CWE-400/CWE-770), mit den konkreten Latenzwerten als Beleg.
   - Weder Crash noch Degradation noch Drossel-Signal → ENFORCED.
4. **Kleiner, fester Burst-Umfang** (CI-tauglich, kein andauernder Last-Test)
   — analog `SCHEMA_FUZZING`s "ein Beweis genügt"-Philosophie: der Burst
   stoppt vorzeitig bei einem eindeutigen Drossel-Signal oder Crash.
5. **Read-only.** Gleiche `_MUTATE_HINTS`-Namens-Heuristik wie alle
   bisherigen Tier-2-Checks.
6. **Kein `owasp_mcp_ref`** (siehe Entschiedener Design-Punkt 2).

## Entschiedene Design-Punkte (Best Practice)

1. **v1 = schneller sequenzieller Burst statt echter Multi-Thread-
   Parallelität (entschieden).** Begründung: `StdioTransport` nutzt einen
   **gemeinsamen** Subprozess-Kanal pro Identität (`StdioServerHandle`, siehe
   `core/stdio_transport.py`) mit einer einzelnen stdin/stdout-Pipe und einer
   `_next_id`-Zähler-Korrelation über eine gemeinsame Queue. Echte parallele
   `call()`s von mehreren Threads auf diesem EINEN Kanal wären ein Race
   Condition (verschachtelte stdin-Writes könnten das newline-delimited
   JSON-RPC-Protokoll korrumpieren) — eine thread-sichere Umgestaltung wäre
   eine Transport-Core-Änderung, die Prinzip II (Plugin-Isolation, minimaler
   Blast-Radius) zuwiderläuft, wenn sie nicht zwingend nötig ist. Ein
   schneller sequenzieller Burst (keine künstliche Pause zwischen Aufrufen)
   bleibt ein valider, transport-blinder Test: ein Server ganz ohne
   Rate-Limiting/Concurrency-Cap sollte auch eine schnelle Folge unbegrenzt
   verarbeiten, und das zeigt sich in denselben Crash-/Degradations-Belegen.
   Eine spätere additive Erweiterung um echte Multi-Connection-Last (neue,
   optionale `Transport`-Fläche) bliebe möglich, ist aber nicht v1-Scope —
   nur einzuführen, falls künftige Tests zeigen, dass sequenzielle Bursts
   nicht genug Signal liefern (gleiches Vorgehen wie bei SCHEMA_FUZZINGs
   zurückgestelltem `is_alive()`).
2. **Kein `owasp_mcp_ref` (entschieden).** Anders als bei `ERROR_LEAKAGE`
   (wo MCP08 zumindest eine lose Näherung war) hat KEINE der zehn
   offiziellen OWASP-MCP-Top-10-Kategorien (Stand 2026-07-02 geprüft) einen
   erkennbaren Bezug zu Resource-Exhaustion/DoS. Ein erzwungenes Mapping
   (z.B. wieder MCP08) wäre hier reine Fiktion, nicht mal eine lose
   Näherung — anders als bei 008, wo "Lack of Audit and Telemetry"
   wenigstens thematisch angrenzt. CWE-400/CWE-770 bleiben die einzigen,
   dafür präzisen Referenzen. Alternative (ein falsches Mapping erzwingen,
   um dem Muster aller bisherigen Checks zu folgen) wurde bewusst verworfen
   — Ehrlichkeit der Beleglage geht vor Konsistenz der Feldbefüllung.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Fixtures + Tests zuerst (rot), dann Check. |
| II. Plugin Isolation | ✅ | Reiner Plugin-Check, **keine** Transport-/Core-Änderung (v1-Scope-Entscheidung vermeidet die stdio-Race-Condition-Falle). |
| III. FP over FN | ✅ | Degradations-Schwellenwert bewusst hoch (kein Mess-Jitter-Fehlalarm); Drossel-Signal sofort ENFORCED. |
| IV. Zero Unnecessary Deps | ✅ | stdlib-only (`time`). |
| V. Evidence-Grounded | ✅ **zentral** | Finding nur bei bewiesenem Crash (Liveness) oder konkret gemessener Latenz-Degradation mit Zahlenbeleg. |
| VI. Paired Fixture Testing (NON-NEGOTIABLE) | ✅ | `throttled`/`fast` (clean) UND `degrading`/`crash` (vulnerable) Fixture, HTTP + stdio. |
| VII. Security-Research Currency | ✅ | Frischer Research-Pass (Ökosystem-Analysen zu fehlendem Rate-Limiting, CVE-2026-53522, OWASP-MCP-Top-10-Kategorienliste) in spec.md. |

**Gate-Ergebnis: PASS** (keine Complexity-Tracking-Einträge nötig — die
stdio-Race-Condition-Problematik wird durch die v1-Scope-Entscheidung
vermieden, nicht durch eine Transport-Änderung gelöst).

## Test Strategy (TDD, Prinzip I & VI)

`tests/fixtures/rate_limiting_servers.py` (stdlib `http.server`, analog
`fuzzing_servers.py`/`error_leakage_servers.py`) — **deterministische** Modi
(kein Verlass auf reale Netzwerk-Timing-Races):
- **throttled**: zählt Aufrufe pro Testlauf; ab einer festen Schwelle (z.B.
  dem 5. Aufruf) antwortet der Server mit HTTP 429 + erkennbarem
  "rate limit exceeded"-Text; davor konstant schnell.
- **degrading**: die Antwortzeit steigt deterministisch mit der Aufrufzahl
  (z.B. `sleep(0.05 * call_index)`, kein Cap) — kein Drossel-Signal, kein
  Crash, aber klar messbare Degradation.
- **crash**: stellt nach einer festen Aufrufzahl im Burst die Antwort
  komplett ein (Server-Shutdown aus dem Handler-Thread, analog
  `fuzzing_servers.py`s `_kill_server` — **kein** `os._exit()`, um den
  Test-Prozess nicht zu töten).
- **fast**: konstant schnell, nie ein Drossel-Signal — Positivfall ohne
  jedes explizite Gegenmittel (zeigt: kein Fehlalarm nur weil kein 429 kam).

`tests/fixtures/stdio_server.py`: `--toolset burst` ergänzen (gleiches
`get_item`-Tool; `--mode` steuert `throttled`/`degrading`/`crash`/`fast`
analog) für stdio-Transport-Parität — bestehendes `fetch`/`fuzz`/`errors`-
Verhalten unverändert.

`tests/test_rate_limiting.py`:
- US1: `crash` → Finding (HIGH, per Liveness bestätigt); `throttled`/`fast`
  → kein Finding. Beide Transporte.
- US2: `degrading` → Finding (MEDIUM, mit Latenzwerten im Beleg);
  `throttled`/`fast` → kein Finding.
- US3: kein lesendes Tool → INCONCLUSIVE; roter Baseline → INCONCLUSIVE;
  unreachable → INCONCLUSIVE.
- Sicherheit: kein mutierendes Tool wird belastet (Fixture zählt Aufrufe = 0);
  Burst-Umfang ist nachweislich begrenzt (fester Obergrenzen-Test).
- Regression: bestehende dynamische Tests (auth/ssrf/rbac/fuzzing/errors/
  stdio) bleiben grün.

Reihenfolge: Fixtures+Tests (rot) → `RateLimitProbe`/`RateLimitProbeClass` in
models → Check US1 (Crash) → US2 (Degradation) → US3-Degradation → Registry
→ volle Suite grün → Doku.

## Risiken / Restunsicherheiten

- **Degradations-Schwellenwert-Kalibrierung**: zu niedrig → Mess-Jitter-
  Fehlalarme; zu hoch → echte Degradation wird übersehen. Deterministische
  Fixture-Werte (feste `sleep()`-Steigung) machen den Schwellenwert in Tests
  verlässlich kalibrierbar, ohne auf reale Timing-Races angewiesen zu sein.
- **stdio-Sequenzialität**: v1 testet keine echte Parallelität (siehe
  Design-Punkt 1) — dokumentierte, bewusste Einschränkung, kein Bug.
- **Scope-Disziplin**: kein andauernder/unbegrenzter Last-Test, keine
  Multi-Identity-Differenzierung (RBAC-Scope), keine Injection-/
  Schema-Payloads (SCHEMA_FUZZING-Scope).
