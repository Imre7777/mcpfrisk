# Tasks: SCHEMA_FUZZING (007-schema-fuzzing)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): pro Phase erst Tests/Fixtures (rot), dann Implementierung (grün).
**Status: IMPLEMENTIERT (2026-07-02). Alle Phasen grün: `pytest -q` 102/102
(90 bestehende + 12 neue), keine Regression. Rein verhaltensbasiert (kein
Schema-Deklarations-Advisory); Crash-Erkennung via Liveness-Recheck ohne
Transport-/Core-Umbau (Ziel-Design eingehalten).**

## Phase 0 — Design-Punkte (entschieden)

- [x] **T001** Schema-Deklarations-Advisory → **ausgeklammert**: v1 bleibt rein
  verhaltensbasiert (FP-arm, Prinzip V). Ein statisches Deklarations-Audit wäre
  ggf. ein separater künftiger Check.
- [x] **T002** Crash-Erkennung → **Liveness-Recheck** (kein Transport-Umbau,
  Plugin-Isolation unangetastet); additives `is_alive()` nur bei nachgewiesenem
  Bedarf.

## Phase 1 — Modelle

- [x] **T003** `core/models.py`: `FuzzProbeClass` (`TYPE_MISMATCH`, `OVERSIZED`,
  `MISSING_REQUIRED`, `MALFORMED_FORMAT`) + `FuzzProbe` (tool, parameter,
  probe_class, outcome, observed) — strukturkompatibel zu `RbacProbe`/`UrlFetchProbe`.

## Phase 2 — Fixtures & Tests zuerst (rot)

- [x] **T004** `tests/fixtures/fuzzing_servers.py`: HTTP-Fixture, Modi
  `vulnerable` (ungefangene Exception → 500 + Traceback; Crash-Variante) und
  `clean` (validiert → `-32602`, kein Leak, bleibt am Leben). Zählt Aufrufe
  mutierender Tools (muss 0 bleiben).
- [x] **T005** `tests/fixtures/stdio_server.py`: `fuzz`-Modus (Crash = Prozess-Tod
  bei Payload; clean = strukturierter Fehler) für stdio-Transport-Parität.
- [x] **T006** `tests/test_schema_fuzzing.py` (rot): US1 (Crash, HTTP+stdio),
  US2 (Traceback-Leak), US3 (kein Tool / roter Baseline / Hang → INCONCLUSIVE),
  Read-only-Nachweis, Regression.

## Phase 3 — Check US1 (Crash / Unhandled Exception)

- [x] **T007** `checks/schema_fuzzing.py`: `tools/list` lesen, lesende Tools
  filtern (Namens-Heuristik, `_MUTATE_HINTS` meiden), gesunden Baseline
  bestätigen, schema-abgeleitete Payloads senden, Crash per **Liveness-Recheck**
  belegen → NOT_ENFORCED (HIGH bei Prozess-Tod / MEDIUM bei 500). Fail-fast.
- [x] **T008** Registrierung in `checks/registry.py` (`DYNAMIC_CHECKS`).

## Phase 4 — Check US2 (Stacktrace-/Interna-Leak)

- [x] **T009** Fehlerantworten auf konservative Leak-Marker prüfen (Traceback/
  Exception/absolute Pfade/SQL) → NOT_ENFORCED (MEDIUM, CWE-209) mit gekürztem,
  secret-bereinigtem Beleg. Strukturierter `-32602` ohne Leak → ENFORCED.

## Phase 5 — US3 Degradation & Sicherheit

- [x] **T010** Sichere Degradation: kein lesendes/fuzzbares Tool, roter Baseline,
  opake Antworten → INCONCLUSIVE; Hang/Timeout → INCONCLUSIVE + Triage-Hinweis
  (kein Finding). Nie stilles „sicher", nie geworfen.
- [x] **T011** Read-only-Garantie: mutierende Tools werden nie gefuzzt
  (Test über den Aufruf-Zähler des Fixtures, bleibt 0).

## Phase 6 — Polish & Verifikation

- [x] **T012** Volle Suite grün (`pytest -q`); keine Regression in
  auth/ssrf/rbac/stdio; Basis-Install bleibt dependency-frei.
- [x] **T013** Doku: README Tier-2 (SCHEMA_FUZZING als implementiert),
  `CONTEXT.md` Roadmap/Architektur.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; **keine** Transport-/Core-Änderung (Ziel-Design); Finding nur bei
belegtem Crash (Liveness) oder konkret geleaktem Interna-Ausschnitt; jeder
Unklarheits-/Fehlerfall → INCONCLUSIVE (+ggf. Triage), nie „sicher", nie
geworfen; **keine mutierenden Operationen**; **keine** Injection-Payloads
(Scope von CMD/SSRF); paired vulnerable/clean Fixtures über HTTP **und** stdio.
