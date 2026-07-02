# Implementation Plan: ERROR_LEAKAGE (008-error-leakage)

**Spec**: [`spec.md`](./spec.md) | **Status**: IMPLEMENTIERT (2026-07-02).
Beide Design-Punkte wie unten festgelegt umgesetzt; keine Transport-/Core-
Änderung war nötig. Volle Suite grün (111/111).

## Technical Context

Neuer dynamischer (Tier-2-)Check über `BaseDynamicCheck`/`DynamicRunner`,
strukturell wie `SCHEMA_FUZZING` (007): keine Konfiguration, keine
Transport-Erweiterung, rein `call()`-basiert — läuft sofort über HTTP **und**
stdio.

- **Sprache/Runtime**: Python 3.10+, **stdlib-only** (kein neuer Dep).
- **Voraussichtlich betroffene Dateien** (zur Review, noch nicht angefasst):
  - `mcpfrisk/checks/error_leakage.py` *(neu)* — der Check.
  - `mcpfrisk/checks/registry.py` — ein Listeneintrag in `DYNAMIC_CHECKS`.
  - `mcpfrisk/core/models.py` — `ErrorProbe` + `ErrorProbeClass` (analog
    `FuzzProbe`/`RbacProbe`).
  - **KEINE** Änderung an `dynamic_runner.py`/`stdio_transport.py`.
- **Neue Test-Artefakte** *(neu)*:
  - `tests/fixtures/error_leakage_servers.py` — HTTP-Fixture: `vulnerable`
    (leakt bei allen drei Triggern) und `clean` (durchgängig generische,
    strukturierte Fehler).
  - Erweiterung von `tests/fixtures/stdio_server.py` um ein drittes
    `--toolset errors` (parallel zu `fetch`/`fuzz`, gleiches
    `--mode vulnerable|clean`-Muster) für die stdio-Transport-Abdeckung.
  - `tests/test_error_leakage.py`.

## Architektur-Entscheidungen (Entwurf)

1. **Rein `call()`-basiert, transport-blind** (wie 007) — `session.call(...)`
   für alle drei Probe-Klassen, kein Sonderfall pro Transport.
2. **Drei fest verdrahtete, adversarial-freie Probe-Klassen** — `UNKNOWN_TOOL`
   (US1), `UNKNOWN_METHOD` (US2), `NONEXISTENT_RESOURCE` (US3). Bewusst
   **keine** schema-verletzenden Payloads (das ist `SCHEMA_FUZZING`-Scope) —
   alle gesendeten Werte sind schema-**konform**, nur inhaltlich harmlos-
   erfunden (nicht existenter Name/ID).
3. **Genau ein Signal: Interna-Leak.** Kein Crash-Nachweis, kein
   Liveness-Recheck — im Unterschied zu `SCHEMA_FUZZING`s zwei Signalen
   (Crash+Leak). Ein Transportfehler während einer Probe macht NUR diese
   Probe nicht auswertbar (übersprungen, nicht als Finding gewertet); die
   übrigen Probe-Klassen werden trotzdem versucht (kein Fail-Fast-Stop wie
   bei 007 — hier gibt es keinen Prozess zu schonen, da nie mehr als drei
   Aufrufe insgesamt anfallen).
4. **Marker-Erkennung wiederverwendet das konservative Muster-Set aus
   `SCHEMA_FUZZING` US2** (Traceback/Exception-Klasse/absoluter Pfad/
   SQL-Fehlertext) — lokal in `error_leakage.py` dupliziert (Prinzip II:
   Plugin-Isolation, keine Cross-Check-Imports zwischen Checks).
5. **Read-only.** US3 nutzt dieselbe `_MUTATE_HINTS`-Namens-Heuristik wie
   `RBAC_CROSS_TENANT`/`SCHEMA_FUZZING` — nie ein mutierendes Tool als Ziel.
6. **Severity einheitlich MEDIUM** (CWE-209) für alle drei Probe-Klassen —
   anders als `SCHEMA_FUZZING`, das zwischen HIGH (Crash) und MEDIUM (Leak)
   unterscheidet: hier gibt es nur die eine Befund-Art.

## Entschiedene Design-Punkte (Best Practice)

1. **OWASP-Mapping-Unschärfe → CWE-209 + best-effort MCP08 (entschieden).**
   Die offizielle OWASP-MCP-Top-10-Kategorienliste (Stand 2026-07-02) hat
   keine dedizierte "Information Disclosure via Error Message"-Kategorie.
   Begründung Best Practice: `owasp_mcp_ref="MCP08"` (Lack of Audit and
   Telemetry — die inhaltlich nächstgelegene, wenn auch unscharfe Kategorie)
   setzen, mit `cwe_ref="CWE-209"` als der eigentlich präzisen Referenz, und
   das im Code klar kommentieren. Alternative (Feld leer lassen) wurde
   verworfen, da alle bisherigen Checks das Feld konsistent befüllen und
   Nutzer:innen ggf. danach filtern.
2. **Kein eigener Crash-Nachweis → entschieden gegen Redundanz mit
   `SCHEMA_FUZZING`.** Ein zweiter Liveness-Recheck-Mechanismus in diesem
   Check würde Verantwortung duplizieren (Prinzip II: klare Check-Grenzen)
   und die Unterscheidung "wer hat den Crash bewiesen" verwässern. Ein
   während einer Probe auftretender Transportfehler wird konsequent als
   "diese Probe nicht auswertbar" behandelt, nie als eigenständiges Finding
   dieses Checks.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Fixtures + Tests zuerst (rot), dann Check. |
| II. Plugin Isolation | ✅ | Reiner Plugin-Check, **keine** Transport-/Core-Änderung; Abgrenzung zu SCHEMA_FUZZING explizit im Design (keine Redundanz). |
| III. FP over FN | ✅ | Konservative Leak-Marker; unauswertbare Probe → übersprungen statt geraten. |
| IV. Zero Unnecessary Deps | ✅ | stdlib-only. |
| V. Evidence-Grounded | ✅ **zentral** | Finding nur bei konkret geleaktem Interna-Ausschnitt. |
| VI. Paired Fixture Testing (NON-NEGOTIABLE) | ✅ | `vulnerable` (leakt bei allen drei Triggern) UND `clean` (generisch) Fixture, HTTP + stdio. |
| VII. Security-Research Currency | ✅ | Frischer Research-Pass (mcpcat.io Error-Handling-Guide 2026, CVE-2026-20205, OWASP-MCP-Top-10-Kategorienliste) in spec.md. |

**Gate-Ergebnis: PASS** (keine Complexity-Tracking-Einträge nötig).

## Test Strategy (TDD, Prinzip I & VI)

`tests/fixtures/error_leakage_servers.py` (stdlib `http.server`, analog
`fuzzing_servers.py`):
- **vulnerable**: `tools/list` liefert ein `get_item(id: string)`-Tool;
  `tools/call` mit unbekanntem Namen wirft eine ungefangene Exception →
  Traceback im Body; eine unbekannte JSON-RPC-Methode ebenso; `get_item` mit
  nicht-existenter ID liefert einen simulierten ORM-Fehlertext statt
  `{"item": null}`.
- **clean**: alle drei Fälle liefern generische, strukturierte Fehler
  (`-32601`/`-32602`) bzw. `{"item": null}`, nie Interna.

`tests/fixtures/stdio_server.py`: `--toolset errors` ergänzen (gleiches
`get_item`-Tool, `--mode vulnerable|clean` steuert das Verhalten der drei
Trigger) — bestehendes `fetch`/`fuzz`-Verhalten bleibt unverändert
(Default `--toolset fetch`).

`tests/test_error_leakage.py`:
- US1: vulnerable→Finding (Leak bei unbekanntem Tool-Namen), clean→kein
  Finding. Beide Transporte.
- US2: vulnerable→Finding (Leak bei unbekannter Methode), clean→kein Finding.
- US3: vulnerable→Finding (Leak bei nicht-existenter ID), clean→kein
  Finding; kein ID-Tool vorhanden → US3 entfällt, US1/US2 liefern trotzdem
  ein reguläres Ergebnis.
- Sicherheit: kein mutierendes Tool wird für US3 verwendet (Aufruf-Zähler
  bleibt 0).
- Degradation: Server unreachable → INCONCLUSIVE.
- Regression: bestehende dynamische Tests (auth/ssrf/rbac/fuzzing/stdio)
  bleiben grün.

Reihenfolge: Fixtures+Tests (rot) → `ErrorProbe`/`ErrorProbeClass` in models
→ Check US1 → US2 → US3 → Registry → volle Suite grün → Doku.

## Risiken / Restunsicherheiten

- **OWASP-Mapping-Unschärfe**: MCP08 ist ein Best-Effort-Fit, kein exaktes
  Match — im Finding-Text transparent machen, nicht als Fakt verkaufen.
- **Sentinel-Kollision (US1)**: der erfundene Tool-Name muss praktisch
  garantiert nicht existieren (zufälliges, eindeutiges Suffix pro Lauf).
- **Scope-Disziplin**: keine schema-verletzenden Payloads (SCHEMA_FUZZING-
  Scope), kein Crash-Nachweis (ebenso SCHEMA_FUZZING-Scope), keine
  Injection-Payloads (CMD/SSRF-Scope).
