# Implementation Plan: Stdio-Transport (005-stdio-transport)

**Spec**: [`spec.md`](./spec.md) | **Status**: Awaiting design review

## Technical Context

Erweiterung der Tier-2-Transportschicht um einen zweiten Adapter. Der Kern der
Änderung ist eine kleine **Ports-&-Adapters-Refaktorierung** von `DynamicSession`:
heute ist sie ein konkreter HTTP-Client; künftig delegiert sie an ein
`Transport`-Protokoll mit zwei Implementierungen.

- **Sprache/Runtime**: Python 3.10+, **stdlib-only** (`subprocess`, `json`,
  `threading`, `queue`) — kein neuer Dep (Prinzip IV).
- **Betroffene Dateien**:
  - `mcpfrisk/core/dynamic_runner.py` — `Transport`-Protokoll; `HttpTransport`
    (bestehende Logik extrahiert); `DynamicSession` delegiert; `DynamicRunner`
    wählt Transport nach Ziel.
  - `mcpfrisk/core/stdio_transport.py` *(neu)* — `StdioTransport` +
    `StdioServerHandle` (Subprozess-Lifecycle, newline-JSON-RPC, Era-Negotiation).
  - `mcpfrisk/cli.py` — `probe --stdio "<cmd>"` (exklusiv zu `--server`).
- **Neue Test-Artefakte**:
  - `tests/fixtures/stdio_server.py` *(neu)* — minimaler stdio-MCP-Server (newline
    JSON-RPC) mit Modi: `legacy`/`modern` × `vulnerable`/`clean`/`silent`.
  - `tests/test_stdio_transport.py` *(neu)*.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Fixture-Server + Tests zuerst (rot), dann Transport. |
| II. Plugin Isolation | ✅ | Checks bleiben unverändert/transport-agnostisch; nur die Transportschicht wächst. Kein Check-File wird angefasst. |
| III. FP over FN | ✅ | Jeder Transport-/Timeout-/Crash-Fall → INCONCLUSIVE (nie stilles „sicher", nie geworfen). |
| IV. Zero Unnecessary Deps | ✅ **kritisch** | Reiner stdlib-Client (`subprocess`); bewusst KEIN `mcp`-SDK als Pflicht. |
| V. Evidence-Grounded | ✅ | Findings tragen weiterhin Beleg (observed/Probe); unverändertes Finding-Modell. |
| VI. Paired Fixture Testing (NON-NEGOTIABLE) | ✅ | `vulnerable` UND `clean` Fixture-Server, je in Legacy- und Modern-Ära. |
| VII. Security-Research Currency | ✅ | Frischer Research-Pass zur stdio-Ära-Negotiation (discover→initialize, SEP-2575) ist in spec.md dokumentiert. |

**Gate-Ergebnis: PASS.** Keine Complexity-Tracking-Einträge nötig (stdlib, additiv).

## Architektur-Entscheidungen (zur Review)

1. **Transport-Port statt `if is_http`-Verzweigung im Check.** `DynamicSession`
   bekommt im Konstruktor einen `Transport`; `probe()`/`call()` delegieren. Vorteil:
   Clean-Architecture-konsistent zum `SourceModel`-Port (002); Checks bleiben
   transport-blind. `BoundaryOutcome`/`AuthProbe`/`UrlFetchProbe` unverändert.
2. **CLI: `--stdio "<command>"` (neuer Flag), exklusiv zu `--server`.** Klarer als
   `--server stdio:...` zu überladen; genau eines erforderlich (argparse mutually
   exclusive group). Begründung: explizit signalisiert „ich starte einen Prozess".
3. **Era-Negotiation pragmatisch:** erst `server/discover` (modern, `_meta` mit
   `io.modelcontextprotocol/protocolVersion`+`clientInfo`); bei „anderem Fehler/
   keiner Antwort" Fallback auf `initialize`+`notifications/initialized` (legacy).
   Ergebnis (Ära) wird einmal pro Session gecacht; `call()` hängt im Modern-Fall
   `_meta` an, im Legacy-Fall nicht.
4. **Lifecycle & Robustheit:** Subprozess via `subprocess.Popen` (stdin/stdout
   `PIPE`, stderr `DEVNULL` oder gepuffert für Diagnose). Ein Reader-Thread liest
   Zeilen in eine `queue`; `call()` schreibt eine Zeile + wartet `timeout`-begrenzt
   auf die Antwort mit passender `id`. `close()` → `terminate()`, dann `kill()` nach
   Grace. Context-Manager garantiert Cleanup auch bei Exceptions.
5. **AUTH_BOUNDARY** bleibt unangetastet: `probe()` des Stdio-Transports liefert für
   die Auth-Frage INCONCLUSIVE mit Begründung „stdio: kein Transport-Auth-Boundary".

## Test Strategy (TDD, Prinzip I & VI)

`tests/fixtures/stdio_server.py` ist ein eigenständig startbares Python-Skript
(`python stdio_server.py --mode vulnerable --era legacy`), das newline-JSON-RPC
spricht: beantwortet `server/discover` (nur im `modern`-Modus), `initialize`/
`notifications/initialized` (nur `legacy`), `tools/list` (bietet ein URL-Tool),
`tools/call` (im `vulnerable`-Modus holt es die übergebene URL → out-of-band-Hit;
im `clean`-Modus mit Denylist). `silent`-Modus antwortet nie (für US3).

`tests/test_stdio_transport.py`:
- US1: vulnerable→Finding; clean→kein Finding; unreachable/crash→inconclusive.
- US2: Discovery gelingt in `legacy` UND `modern`.
- US3: silent→Timeout-inconclusive innerhalb der Zeit; Subprozess danach beendet.
- Unit: newline-Framing (Nicht-JSON-Zeilen ignoriert, id-Korrelation, notifications).
- Regression: HTTP-`probe`-Pfad unverändert grün; SSRF-HTTP-Tests unverändert.

Reihenfolge: Fixture+Tests (rot) → Transport-Port-Refaktor (HTTP grün halten) →
StdioTransport → Era-Negotiation → CLI-Flag → volle Suite grün → Doku
(README Tier-2 + CONTEXT.md + Sicherheitshinweis FR-010).

## Risiken / offene Punkte

- **Plattform**: Subprozess-Kill-Verhalten unterscheidet sich Windows/POSIX;
  Tests müssen auf beiden grün sein (CI = ubuntu, Dev = Windows). `Popen.terminate`
  reicht i.d.R.; ggf. `CREATE_NEW_PROCESS_GROUP` auf Windows.
- **Flakiness** durch reale Subprozesse/Ports (SSRF-Callback) — Timeouts großzügig,
  aber zeitbegrenzt; Reader-Thread sauber beenden.
- **Scope-Disziplin**: kein vollständiger MCP-Client; nur discover/initialize +
  tools/list + tools/call.
