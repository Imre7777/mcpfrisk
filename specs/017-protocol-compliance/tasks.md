# Tasks: PROTOCOL_COMPLIANCE (017-protocol-compliance)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): erst Tests + Fixtures (rot), dann Port/Check/Registry (grün).
**Status: IMPLEMENTIERT (2026-07-12). Volle Suite 256/256, keine Regression.**

## Phase 1 — Tests + Fixtures zuerst (rot)

- [x] **T001** `tests/fixtures/protocol_servers.py` (HTTP): Modi compliant,
  fail_open, wrong_code, malformed_error, malformed_envelope. `state["mutations"]`
  zählt (Read-only-Beleg), auch wenn der Check nie ein Tool ruft.
- [x] **T002** `tests/fixtures/stdio_server.py`: `--toolset protocol` + Modi
  compliant/fail_open/wrong_code (stdio-Parität).
- [x] **T003** `tests/test_protocol_compliance.py` (rot): Port (`call_response`
  liefert `error`), US1 (fail_open→MEDIUM, compliant→0), US2 (wrong_code/
  malformed_error/malformed_envelope→LOW), US3 (unreachable→INCONCLUSIVE, stdio-
  Parität, Read-only), Runner-Integration, `call()`-Regression.

## Phase 2 — Port + Check + Registry

- [x] **T004** `mcpfrisk/core/models.py`: `ProtocolProbeClass` +
  `ProtocolProbe`.
- [x] **T005** `mcpfrisk/core/dynamic_runner.py`: `extract_jsonrpc_payload`,
  `Transport.call_response` (Protocol), `HttpTransport.call_response` (+ `call()`
  refactored darauf), `DynamicSession.call_response`.
- [x] **T006** `mcpfrisk/core/stdio_transport.py`: `StdioTransport.call_response`.
- [x] **T007** `mcpfrisk/checks/protocol_compliance.py`: eine unbekannte Methode
  senden, klassifizieren (MISSING_ERROR/WRONG_ERROR_CODE/MALFORMED_ERROR/
  MALFORMED_ENVELOPE/ENFORCED), `to_finding` mit gradueller Severity + CWE-703,
  kein OWASP-Ref.
- [x] **T008** Registrierung in `checks/registry.py` (`DYNAMIC_CHECKS`).

## Phase 3 — Polish & Verifikation

- [x] **T009** Volle Suite grün (`pytest -q`); die fünf bestehenden dynamischen
  Checks unverändert (`call()`-Regression); Read-only; dependency-frei.
- [x] **T010** Doku: README (Tier-2-Tabelle + Badge 7 dynamisch), CONTEXT.md,
  `.specify/feature.json`, commit + push, CI (Nutzer prüft manuell).

## Constitution-Leitplanke (alle Tasks)

stdlib-only; KEINE Check-zu-Check-Abhängigkeit; `call_response` additiv, `call()`
byte-gleich (Regressionsbeleg); nur die eindeutige `-32601`-Semantik (kein
mehrdeutiger Fehlerpfad → kein FP); unreachable/Timeout sauber INCONCLUSIVE, nie
Crash, nie „sicher"; Read-only (kein Tool-Aufruf); Finding nennt Abweichung +
Antwort-Ausschnitt; paired vuln/clean Fixtures über HTTP UND stdio; neue Dateien
+ ein Registry-Eintrag.
