# Tasks: RATE_LIMITING (009-rate-limiting)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): pro Phase erst Tests/Fixtures (rot), dann Implementierung (grün).
**Status: NICHT IMPLEMENTIERT — Design entschieden (Best Practice): v1 als
schneller sequenzieller Burst (keine echte Multi-Thread-Parallelität, wegen
stdio-Kanal-Race-Condition-Risiko); kein `owasp_mcp_ref` (keine passende
OWASP-MCP-Top-10-Kategorie vorhanden). Bereit für Phase 1 auf Signal.**

## Phase 0 — Design-Punkte (entschieden)

- [x] **T001** Multi-Thread-Parallelität → **v1: schneller sequenzieller
  Burst** (kein Transport-Umbau; `StdioTransport`s gemeinsamer
  Subprozess-Kanal ist nicht thread-sicher für echte parallele `call()`s).
- [x] **T002** OWASP-Mapping → **bewusst kein `owasp_mcp_ref`** (keine der
  zehn Kategorien passt auch nur näherungsweise; CWE-400/CWE-770 bleiben die
  präzisen Referenzen).

## Phase 1 — Modelle

- [ ] **T003** `core/models.py`: `RateLimitProbeClass` (`BURST_CRASH`,
  `BURST_DEGRADATION`) + `RateLimitProbe` (tool, parameter, probe_class,
  outcome, observed) — strukturkompatibel zu `ErrorProbe`/`FuzzProbe`.

## Phase 2 — Fixtures & Tests zuerst (rot)

- [ ] **T004** `tests/fixtures/rate_limiting_servers.py`: HTTP-Fixture,
  deterministische Modi `throttled` (429 ab fester Schwelle), `degrading`
  (deterministisch steigende Antwortzeit, kein Cap), `crash` (stellt nach
  fester Aufrufzahl die Antwort ein, Server-Shutdown aus Handler-Thread wie
  `fuzzing_servers.py`, **kein** `os._exit`), `fast` (konstant schnell).
  Zählt Aufrufe mutierender Tools (muss 0 bleiben) und Gesamt-Burst-Umfang.
- [ ] **T005** `tests/fixtures/stdio_server.py`: `--toolset burst` ergänzen
  (`--mode throttled|degrading|crash|fast`) für stdio-Transport-Parität —
  bestehendes `fetch`/`fuzz`/`errors`-Verhalten unverändert.
- [ ] **T006** `tests/test_rate_limiting.py` (rot): US1 (Crash, HTTP+stdio),
  US2 (Degradation mit Latenzbeleg), US3 (kein Tool / roter Baseline /
  unreachable → INCONCLUSIVE), Read-only-Nachweis, Burst-Umfang-Grenze,
  Regression.

## Phase 3 — Check US1 (Crash unter Last)

- [ ] **T007** `checks/rate_limiting.py`: `tools/list` lesen, lesende Tools
  filtern (`_MUTATE_HINTS` meiden), gesunden Baseline-Call + Latenz messen,
  kurzen sequenziellen Burst senden, Crash per **Liveness-Recheck**
  belegen → NOT_ENFORCED (HIGH, CWE-400). Fail-fast bei eindeutigem Beleg.
- [ ] **T008** Registrierung in `checks/registry.py` (`DYNAMIC_CHECKS`).

## Phase 4 — Check US2 (Latenz-Degradation)

- [ ] **T009** Burst-Latenzen messen, gegen Baseline vergleichen; klar
  definierter Vielfachen-Schwellenwert überschritten (kein Crash, kein
  Drossel-Signal) → NOT_ENFORCED (MEDIUM, CWE-400/CWE-770) mit den
  konkreten Latenzwerten als Beleg.
- [ ] **T010** Drossel-Signal-Erkennung (HTTP 429 / erkennbarer
  Rate-Limit-Fehlertext) an JEDER Stelle im Burst → sofort ENFORCED,
  unabhängig vom restlichen Burst.

## Phase 5 — US3 Degradation & Sicherheit

- [ ] **T011** Sichere Degradation: kein lesendes Tool, roter Baseline,
  Server nicht erreichbar → INCONCLUSIVE. Nie stilles „sicher", nie
  geworfen.
- [ ] **T012** Read-only-Garantie + Burst-Umfang-Grenze: mutierende Tools
  werden nie belastet (Aufruf-Zähler bleibt 0); der Burst ist nachweislich
  auf einen festen, kleinen Umfang begrenzt (kein andauernder Last-Test).

## Phase 6 — Polish & Verifikation

- [ ] **T013** Volle Suite grün (`pytest -q`); keine Regression in
  auth/ssrf/rbac/fuzzing/errors/stdio; Basis-Install bleibt dependency-frei.
- [ ] **T014** Doku: README Tier-2 (RATE_LIMITING als implementiert),
  `CONTEXT.md` Roadmap/Architektur.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; **keine** Transport-/Core-Änderung (v1-Scope-Entscheidung);
Finding nur bei belegtem Crash (Liveness) oder konkret gemessener
Latenz-Degradation mit Zahlenbeleg; jeder Unklarheits-/Fehlerfall →
INCONCLUSIVE, nie „sicher", nie geworfen; **keine mutierenden Operationen**;
Burst-Umfang bewusst klein/CI-tauglich, kein andauernder Last-Test; **kein**
`owasp_mcp_ref` (siehe Design-Punkt T002); paired Fixtures über HTTP **und**
stdio.
