# Tasks: ERROR_LEAKAGE (008-error-leakage)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): pro Phase erst Tests/Fixtures (rot), dann Implementierung (grün).
**Status: IMPLEMENTIERT (2026-07-02). Alle Phasen grün: `pytest -q` 111/111
(102 bestehende + 9 neue), keine Regression. Drei adversarial-freie
Probe-Klassen (UNKNOWN_TOOL/UNKNOWN_METHOD/NONEXISTENT_RESOURCE), reines
Leak-Signal ohne eigenen Crash-Nachweis, OWASP-Mapping best-effort MCP08 +
CWE-209 -- Ziel-Design vollständig eingehalten.**

## Phase 0 — Design-Punkte (entschieden)

- [x] **T001** OWASP-Mapping-Unschärfe → **CWE-209 + best-effort MCP08**
  (keine dedizierte OWASP-MCP-Kategorie für Error-Info-Disclosure vorhanden,
  Stand 2026-07-02; im Code klar als Best-Effort kommentiert).
- [x] **T002** Kein eigener Crash-Nachweis → **reines Leak-Signal**, um
  Redundanz mit `SCHEMA_FUZZING` zu vermeiden (Prinzip II); Transportfehler
  während einer Probe macht nur diese Probe nicht auswertbar.

## Phase 1 — Modelle

- [x] **T003** `core/models.py`: `ErrorProbeClass` (`UNKNOWN_TOOL`,
  `UNKNOWN_METHOD`, `NONEXISTENT_RESOURCE`) + `ErrorProbe` (tool/method,
  parameter, probe_class, outcome, observed) — strukturkompatibel zu
  `FuzzProbe`/`RbacProbe`/`UrlFetchProbe`.

## Phase 2 — Fixtures & Tests zuerst (rot)

- [x] **T004** `tests/fixtures/error_leakage_servers.py`: HTTP-Fixture,
  Modi `vulnerable` (leakt bei unbekanntem Tool-Namen, unbekannter Methode
  UND nicht-existenter ID) und `clean` (durchgängig generische, strukturierte
  Fehler bzw. `{"item": null}`). Zählt Aufrufe mutierender Tools (muss 0
  bleiben).
- [x] **T005** `tests/fixtures/stdio_server.py`: `--toolset errors` ergänzen
  (gleiches `get_item`-Tool, `--mode vulnerable|clean` steuert alle drei
  Trigger) für stdio-Transport-Parität — bestehendes `fetch`/`fuzz`-
  Verhalten unverändert.
- [x] **T006** `tests/test_error_leakage.py` (rot): US1 (unbekannter
  Tool-Name, HTTP+stdio), US2 (unbekannte Methode), US3 (nicht-existente ID;
  Entfall ohne ID-Tool), Read-only-Nachweis, Degradation (unreachable),
  Regression.

## Phase 3 — Check US1 (Unbekannter Tool-Name)

- [x] **T007** `checks/error_leakage.py`: `tools/call` mit garantiert
  eindeutigem, nicht-existentem Tool-Namen aufrufen, Antwort auf konservative
  Leak-Marker prüfen (Traceback/Exception-Klasse/absoluter Pfad/SQL) →
  NOT_ENFORCED (MEDIUM, CWE-209) mit gekürztem Beleg; generische Ablehnung →
  ENFORCED.
- [x] **T008** Registrierung in `checks/registry.py` (`DYNAMIC_CHECKS`).

## Phase 4 — Check US2 (Unbekannte JSON-RPC-Methode)

- [x] **T009** Eine garantiert unbekannte Top-Level-Methode senden, Antwort
  auf dieselben Leak-Marker prüfen → NOT_ENFORCED (MEDIUM) bzw. ENFORCED.

## Phase 5 — Check US3 (Nicht-existente Ressourcen-ID)

- [x] **T010** Lesende Tools mit ID-artigem Pflichtparameter entdecken
  (Namens-Heuristik wie RBAC `_ID_HINTS`, `_MUTATE_HINTS` meiden), einen
  schema-validen, garantiert nicht-existenten Wert senden, Antwort auf
  Leak-Marker prüfen. Kein passendes Tool → Probe entfällt, kein Fehlschlag.
- [x] **T011** Read-only-Garantie: nie ein mutierendes Tool als US3-Ziel
  (Test über den Aufruf-Zähler des Fixtures, bleibt 0).

## Phase 6 — Polish & Verifikation

- [x] **T012** Sichere Degradation: Server unreachable / keine der drei
  Proben durchführbar → INCONCLUSIVE; ein Transportfehler während einer
  Probe macht nur diese nicht auswertbar (kein eigenes Finding daraus). Nie
  stilles „sicher", nie geworfen.
- [x] **T013** Volle Suite grün (`pytest -q`); keine Regression in
  auth/ssrf/rbac/fuzzing/stdio; Basis-Install bleibt dependency-frei.
- [x] **T014** Doku: README Tier-2 (ERROR_LEAKAGE als implementiert),
  `CONTEXT.md` Roadmap/Architektur.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; **keine** Transport-/Core-Änderung; Finding nur bei konkret
geleaktem Interna-Ausschnitt (kein eigener Crash-Nachweis — bleibt
SCHEMA_FUZZING-Scope); jeder Unklarheits-/Fehlerfall → INCONCLUSIVE, nie
„sicher", nie geworfen; **keine mutierenden Operationen**; **keine**
schema-verletzenden oder Injection-Payloads (Scope von SCHEMA_FUZZING/
CMD_INJECTION/SSRF_CHECK); paired vulnerable/clean Fixtures über HTTP
**und** stdio.
