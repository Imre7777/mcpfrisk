# Tasks: Stdio-Transport (005-stdio-transport)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): pro Phase erst Tests/Fixture (rot), dann Implementierung (grün).
`[P]` = parallelisierbar. **Status: IMPLEMENTIERT — 85/85 Tests grün, CLI End-to-End
gegen vulnerable+clean Fixture (beide Ären) verifiziert.**

## Phase 0 — Setup & Port-Refaktor (Grundlage, keine Verhaltensänderung)

- [x] **T001** `Transport`-Protokoll in `dynamic_runner.py` definieren
  (`probe()`, `call()`, `close()`); `HttpTransport` aus der bestehenden
  `DynamicSession`-Logik extrahieren (1:1, keine Verhaltensänderung).
- [x] **T002** `DynamicSession` an einen `Transport` delegieren lassen; `DynamicRunner`
  wählt vorerst weiterhin HTTP. Regression: bestehende HTTP-Tests bleiben grün.

## Phase 1 — Fixture & Tests zuerst (rot)

- [x] **T003** `tests/fixtures/stdio_server.py`: newline-JSON-RPC-Server mit Modi
  `--era {legacy,modern}` × `--mode {vulnerable,clean,silent}`; Methoden
  `server/discover` / `initialize` / `tools/list` / `tools/call`.
- [x] **T004** `tests/test_stdio_transport.py`: US1 (vulnerable/clean/unreachable),
  US2 (legacy+modern discovery), US3 (silent→timeout + Prozess beendet), Banner-Framing.

## Phase 2 — StdioTransport (US1 + US2)

- [x] **T005** `core/stdio_transport.py`: `StdioServerHandle` (Popen, Reader-Thread,
  zeilenweises Schreiben/Lesen, id-Korrelation, timeout, terminate/kill).
- [x] **T006** `StdioTransport.call()` über den Handle; Nicht-JSON/Notifications ignorieren.
- [x] **T007** Era-Negotiation: `server/discover` → Fallback `initialize`+`initialized`;
  Ergebnis cachen; im Modern-Fall `_meta` an Requests hängen.
- [x] **T008** `StdioTransport.probe()` → INCONCLUSIVE „stdio: kein Auth-Boundary"
  (AUTH_BOUNDARY unverändert), ohne den Server zu starten.

## Phase 3 — Verdrahtung (CLI)

- [x] **T009** `cli.py`: `probe --stdio "<cmd>"` als mutually-exclusive group mit
  `--server`; genau eines erforderlich.
- [x] **T010** `make_transport()` wählt Transport nach Zielart
  (http(s):// → HTTP, sonst/`stdio:` → stdio).

## Phase 4 — Lifecycle-Härtung (US3)

- [x] **T011** Sauberer Shutdown (terminate→kill, Reader-Thread join, Runner-`finally`);
  Test: kein verwaister Prozess, Timeout hält die Zeit ein.

## Phase 5 — Polish & Verifikation

- [x] **T012** Volle Suite grün (`pytest -q`, 85 passed); Dev/Windows verifiziert.
- [x] **T013** Doku: README Tier-2 (stdio-Beispiel + Sicherheitshinweis FR-010),
  `CONTEXT.md` Roadmap/Architektur/Projektstruktur aktualisiert.

## Constitution-Leitplanke (alle Tasks)

stdlib-only (kein neuer Dep), jeder Fehler/Timeout → INCONCLUSIVE (nie „sicher",
nie geworfen), Checks bleiben unangetastet, paired vulnerable/clean Fixtures.
