# Tasks: RBAC_CROSS_TENANT (006-rbac-cross-tenant)

**Spec**: [`spec.md`](./spec.md) | **Plan**: [`plan.md`](./plan.md)

TDD (Prinzip I): pro Phase erst Tests/Fixtures (rot), dann Implementierung (grün).
**Status: NICHT IMPLEMENTIERT — Design entschieden (CLI `--identity NAME=CREDENTIAL`
mit `env:`-Indirektion; stdio-Identität via Env-Overlay je Prozess). Bereit für
Phase 0 auf Signal.**

## Phase 0 — Transport-Identitäts-Erweiterung (Grundlage, additiv)

- [ ] **T001** Transport-Port um optionale Identität erweitern: `call(..., identity=None)`;
  `HttpTransport` setzt daraus einen (konfigurierbaren) Header (Default
  `Authorization: Bearer <cred>`); `StdioTransport` hält **einen Subprozess pro
  Identität** mit Env-Overlay (`dict`, lazily; `close()` beendet alle).
  Rückwärtskompatibel — `identity=None` = altes Verhalten; auth/ssrf/stdio-Tests bleiben grün.
- [ ] **T002** `CallerIdentity`/`RbacProbe`-Modelle in `core/models.py` (Drei-Zustands-
  Verdikt, Fingerprint-Feld) — analog zu `UrlFetchProbe`.

## Phase 1 — Fixtures & Tests zuerst (rot)

- [ ] **T003** `tests/fixtures/rbac_servers.py`: multi-tenant HTTP-Fixture,
  Modi `vulnerable` (IDOR via `get_record(id)` + Tenant-Arg via `list_records(tenant)`)
  und `clean` (scoped per verifiziertem Token). A-Daten mit eindeutigem Fingerprint;
  zählt mutierende Calls (muss 0 bleiben).
- [ ] **T004** `tests/test_rbac_cross_tenant.py` (rot): US1 (IDOR), US2 (Tenant-Arg),
  US3 (1 Identität / mehrdeutig → INCONCLUSIVE), Read-only-Nachweis, Regression.

## Phase 2 — Check US1 (IDOR-Replay)

- [ ] **T005** `checks/rbac_cross_tenant.py`: Discovery als A (lesende Tools, IDs +
  Fingerprint sammeln), Replay als B, Beweis = A-Fingerprint in B's Antwort.
- [ ] **T006** Registrierung in `checks/registry.py` (`DYNAMIC_CHECKS`).

## Phase 3 — Check US2 (Tenant-Argument-Injection)

- [ ] **T007** Tenant-/Owner-artige Parameter erkennen; als B mit A's Tenant-Wert
  aufrufen; Beweis wie US1.

## Phase 4 — US3 Degradation & Sicherheit

- [ ] **T008** Sichere Degradation: < 2 Identitäten / keine scoped Ressource /
  Transportfehler → INCONCLUSIVE; mehrdeutiges Overlap → INCONCLUSIVE + Triage-Hinweis.
- [ ] **T009** Read-only-Garantie: mutierende Tool-Namen werden nie geprobt
  (Test über den Schreib-Zähler des Fixtures).

## Phase 5 — CLI & Verdrahtung

- [ ] **T010** `cli.py probe`: `--identity NAME=CREDENTIAL` (wiederholbar,
  `env:VAR`-Indirektion), optional `--auth-header NAME` (HTTP) und
  `--identity-env VAR` (stdio). Ohne/< 2 Identitäten → Check überspringt sich
  sauber (INCONCLUSIVE).

## Phase 6 — Polish & Verifikation

- [ ] **T011** Volle Suite grün (`pytest -q`); keine Regression in auth/ssrf/stdio.
- [ ] **T012** Doku: README Tier-2 (RBAC_CROSS_TENANT als implementiert +
  Identitäts-Nutzung), `CONTEXT.md` Roadmap/Architektur.

## Constitution-Leitplanke (alle Tasks)

stdlib-only; Finding nur bei beweisbarem A-Fingerprint in B's Antwort; jeder
Unklarheits-/Fehlerfall → INCONCLUSIVE (+ggf. Triage), nie „sicher", nie geworfen;
**keine mutierenden Operationen**; paired vulnerable/clean Fixtures.
