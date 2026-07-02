# Tasks: RBAC_CROSS_TENANT (006-rbac-cross-tenant)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): pro Phase erst Tests/Fixtures (rot), dann Implementierung (grün).
**Status: IMPLEMENTIERT — CLI `--identity NAME=CREDENTIAL` mit `env:`-Indirektion;
stdio-Identität via Env-Overlay je Prozess. Volle Suite grün (90 Tests).**

## Phase 0 — Transport-Identitäts-Erweiterung (Grundlage, additiv)

- [x] **T001** Transport-Port um optionale Identität erweitert: `call(..., identity=None)`;
  `HttpTransport` setzt daraus einen (konfigurierbaren) Header (Default
  `Authorization: Bearer <cred>`); `StdioTransport` hält **einen Subprozess pro
  Identität** mit Env-Overlay (`_channels`-dict, lazily; `close()` beendet alle).
  Rückwärtskompatibel — `identity=None` = altes Verhalten; auth/ssrf/stdio-Tests bleiben grün.
- [x] **T002** `RbacProbe`/`RbacProbeClass`-Modelle in `core/models.py` (Drei-Zustands-
  Verdikt, `identity_from`/`identity_to`) — analog zu `UrlFetchProbe`.

## Phase 1 — Fixtures & Tests zuerst (rot)

- [x] **T003** `tests/fixtures/rbac_servers.py`: multi-tenant HTTP-Fixture,
  Modi `vulnerable` (IDOR via `get_record(id)` + Tenant-Arg via `list_records(tenant)`)
  und `clean` (scoped per verifiziertem Token). A-Daten mit eindeutigem Fingerprint;
  zählt mutierende Calls (muss 0 bleiben).
- [x] **T004** `tests/test_rbac_cross_tenant.py`: US1 (IDOR), US2 (Tenant-Arg),
  US3 (1/0 Identitäten → INCONCLUSIVE), Read-only-Nachweis, Runner-Integration.

## Phase 2 — Check US1 (IDOR-Replay)

- [x] **T005** `checks/rbac_cross_tenant.py`: Discovery als A (lesende Tools, IDs +
  A-private Fingerprints via A−B-Baseline sammeln), Replay als B, Beweis =
  A-privater Marker in B's Antwort.
- [x] **T006** Registrierung in `checks/registry.py` (`DYNAMIC_CHECKS`).

## Phase 3 — Check US2 (Tenant-Argument-Injection)

- [x] **T007** Tenant-/Owner-artige Parameter erkannt; als B mit A's Tenant-Wert
  aufgerufen; Beweis wie US1.

## Phase 4 — US3 Degradation & Sicherheit

- [x] **T008** Sichere Degradation: < 2 Identitäten / keine A-private Ressource /
  Transportfehler → INCONCLUSIVE (+ erklärende `observed`-Notiz).
- [x] **T009** Read-only-Garantie: mutierende Tool-Namen (`_MUTATE_HINTS`) werden nie
  geprobt (Test über den Schreib-Zähler des Fixtures, bleibt 0).

## Phase 5 — CLI & Verdrahtung

- [x] **T010** `cli.py probe`: `--identity NAME=CREDENTIAL` (wiederholbar,
  `env:VAR`-Indirektion), optional `--auth-header NAME` (HTTP) und
  `--identity-env VAR` (stdio). Ohne/< 2 Identitäten → Check überspringt sich
  sauber (INCONCLUSIVE).

## Phase 6 — Polish & Verifikation

- [x] **T011** Volle Suite grün (`pytest -q`, 90 Tests); keine Regression in auth/ssrf/stdio.
- [x] **T012** Doku: README Tier-2 (RBAC_CROSS_TENANT als implementiert +
  Identitäts-Nutzung), `CONTEXT.md` Roadmap/Architektur.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; Finding nur bei beweisbarem A-Fingerprint in B's Antwort; jeder
Unklarheits-/Fehlerfall → INCONCLUSIVE (+ggf. Triage), nie „sicher", nie geworfen;
**keine mutierenden Operationen**; paired vulnerable/clean Fixtures.
