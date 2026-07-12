# Implementation Plan: PROTOCOL_COMPLIANCE (017)

**Spec**: [`spec.md`](./spec.md) | **Status**: Design entschieden, in Implementierung (2026-07-12).

## Technical Context

Ein neuer dynamischer (Tier-2-)Check plus eine additive **Transport-Port-
Erweiterung** (`call_response()`). stdlib-only, nutzt `BaseDynamicCheck` +
`DynamicSession`. KEINE Check-zu-Check-Abhängigkeit.

- **Geänderte Dateien (Port, additiv)**:
  - `mcpfrisk/core/models.py` — `ProtocolProbeClass` + `ProtocolProbe`.
  - `mcpfrisk/core/dynamic_runner.py` — `Transport.call_response()` (Protocol),
    `HttpTransport.call_response()` (+ Refactor: `call()` nutzt sie),
    `DynamicSession.call_response()`. Neuer Helfer `extract_jsonrpc_payload`.
  - `mcpfrisk/core/stdio_transport.py` — `StdioTransport.call_response()`
    (der Handle liefert bereits das volle Payload; `call()` wrappt es nur).
- **Neue Dateien**:
  - `mcpfrisk/checks/protocol_compliance.py` — der Check.
  - `tests/fixtures/protocol_servers.py` — HTTP-Fixture (compliant/fail_open/
    wrong_code/malformed_error/malformed_envelope).
  - `tests/test_protocol_compliance.py`.
- **Geändert**: `mcpfrisk/checks/registry.py` (`DYNAMIC_CHECKS`);
  `tests/fixtures/stdio_server.py` (`--toolset protocol`, Modi compliant/
  fail_open/wrong_code für die stdio-Parität).

## Architektur-Entscheidungen

1. **`call_response()` ist die additive Kern-Erweiterung.** Beide `call()`-
   Implementierungen verwerfen heute das `error`-Objekt (`extract_jsonrpc_result`
   liefert nur `result`). `call_response()` gibt die **volle** Payload zurück;
   `call()` wird zu `extract_jsonrpc_result(call_response(...))` — byte-gleiches
   Verhalten für alle fünf bestehenden Checks (Regressionslauf beweist es).
2. **Ein Probe, Entscheidungsbaum, worst-case gewinnt.** Der Check sendet EINE
   unbekannte Methode und klassifiziert die Antwort in Prioritätsreihenfolge
   (MISSING_ERROR > MALFORMED_ERROR > WRONG_ERROR_CODE > MALFORMED_ENVELOPE >
   ENFORCED). Genau eine `ProtocolProbe` pro Lauf.
3. **Nur die eindeutige `-32601`-Semantik (FP-Disziplin, Prinzip III).** Andere
   Fehlerpfade (-32602 invalid params etc.) sind gegen MCP-Tool-Result-Fehler
   (`isError`) mehrdeutig → bewusst out of scope. Method-not-found ist universell
   und unmissverständlich.
4. **Read-only per Konstruktion.** Der Check ruft kein Tool auf, nur eine
   nie-existente Top-Level-Methode → nie eine Mutation.
5. **Kein OWASP-Ref, CWE-703.** Wie RATE_LIMITING: das OWASP-MCP-Top-10 hat keine
   passende Kategorie; ehrlich `owasp_mcp_ref=None`, CWE-703 als präzise Referenz.
   Severity graduell im `to_finding` je `ProtocolProbeClass`.
6. **protocolVersion out of scope (v1).** HTTP macht kein `initialize`; die
   Ära-Negotiation ist stdio-intern. Eine saubere, transport-symmetrische Prüfung
   wäre ein eigenes Feature — v1 bleibt auf die transport-gleiche Method-not-
   found-Prüfung fokussiert.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Tests zuerst (rot: Port + Check + Fixtures), dann Implementierung. |
| II. Plugin Isolation | ✅ | Neue Check-Datei + ein Registry-Eintrag; Port bleibt check-agnostisch, kein Fremd-Check-Import. |
| III. FP over FN | ✅ | Nur die eindeutige JSON-RPC-2.0-`-32601`-Vorgabe; spec-konform → befundfrei; unreachable → INCONCLUSIVE. |
| IV. Zero Unnecessary Deps | ✅ | stdlib (urllib/json/uuid). |
| V. Evidence-Grounded | ✅ | Finding nennt die konkrete Abweichung + secret-bereinigten Antwort-Ausschnitt. |
| VI. Paired Fixture Testing | ✅ | compliant (clean) UND fail_open/wrong_code/malformed (vuln), HTTP + stdio. |
| VII. Security-Research Currency | ✅ | Frischer Pass (JSON-RPC 2.0 Fehlercodes, MCP-Spec, fail-open/CWE-703, MSB/MCPSecBench Conformance) in spec.md. |

**Gate-Ergebnis: PASS.**

## Test Strategy (TDD, Prinzip I & VI)

`tests/test_protocol_compliance.py`:
- Port zuerst: `call_response()` liefert das volle Payload inkl. `error`
  (HTTP-Fixture) — macht die Port-Erweiterung rot, bevor der Check existiert.
- US1: fail_open (HTTP) → MEDIUM (MISSING_ERROR); compliant → 0 (ENFORCED).
- US2: wrong_code → LOW (WRONG_ERROR_CODE); malformed_error → LOW; 
  malformed_envelope → LOW.
- US3: unreachable → INCONCLUSIVE; fail_open über **stdio** → MEDIUM; compliant
  über stdio → 0. Read-only: keine Mutation (der Check ruft kein Tool).
- Regression: `call()` unverändert; DynamicRunner-Integration meldet das Finding
  und listet den Check in `checks_run`; die fünf bestehenden dynamischen Checks
  bleiben grün.

Reihenfolge: Tests (rot) → models → dynamic_runner (`call_response` + Refactor)
→ stdio_transport (`call_response`) → Fixtures (HTTP + stdio `--toolset protocol`)
→ `checks/protocol_compliance.py` → Registry → volle Suite grün → Doku.

## Risiken / Restunsicherheiten

- **`call()`-Regression**: der Refactor muss `call()` exakt erhalten — ein
  Regressionslauf aller Tier-2-Tests (SSRF/Auth/RBAC/Fuzz/Error/Rate) ist das
  Sicherheitsnetz.
- **stdio-Envelope**: `_send` setzt immer `"jsonrpc":"2.0"` → der
  `MALFORMED_ENVELOPE`-Fall wird nur über HTTP getestet (stdio deckt
  compliant/fail_open/wrong_code ab). Das ist akzeptabel: die Klassifikations-
  Logik ist transport-unabhängig, nur die Payload-Quelle unterscheidet sich.
- **HTTP 4xx/5xx mit Body**: `call_response` muss (wie `call`) den HTTPError-Body
  lesen — sonst FP „unreachable" statt Fehler-Auswertung. Test deckt das ab.
