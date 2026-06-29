---
description: "Task list for AUTH_BOUNDARY dynamic check"
---

# Tasks: AUTH_BOUNDARY check

**Input**: Design documents from `specs/001-auth-boundary/`

**Prerequisites**: plan.md, spec.md (user stories), research.md, data-model.md, contracts/interfaces.md, quickstart.md

**Tests**: MANDATORY for this project. Per the constitution (`.specify/memory/constitution.md`,
Principles I & VI) tests are written FIRST, approved by the maintainer, and confirmed
FAILING (red) before implementation. Every detection task ships with a paired
vulnerable-fixture and clean-fixture test.

**Organization**: Tasks grouped by user story (US1, US2, US3) so each is independently testable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no incomplete dependencies)
- **[Story]**: US1 / US2 / US3 (Setup, Foundational, Polish carry no story label)

## Path Conventions

Single project: package at `mcpfrisk/`, tests at `tests/` (repo root).

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Make the dynamic dependency available without touching the Tier 1 install.

- [ ] T001 Add an optional `dynamic` extra (the `mcp` SDK) to `[project.optional-dependencies]` in `pyproject.toml`; keep core `dependencies` empty (Constitution IV).
- [ ] T002 [P] Add `tests/fixtures/__init__.py` if missing and confirm `pytest` picks up `tests/test_auth_boundary.py` via existing `[tool.pytest.ini_options]`.
- [ ] T003 [P] Document the `dynamic` extra install in `README.md` (Tier 2 section) and reference `mcpfrisk probe` usage.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The dynamic execution scaffolding every user story depends on.

**⚠️ CRITICAL**: No user-story work begins until this phase is complete.

- [ ] T004 Extend `mcpfrisk/core/models.py`: add `CredentialCondition` (NONE/INVALID/VALID) and `BoundaryOutcome` (ENFORCED/NOT_ENFORCED/INCONCLUSIVE) enums per data-model.md. Do not modify existing `Finding`/`Severity` shape.
- [ ] T005 Extend `mcpfrisk/core/models.py`: add `AuthProbe` and `BoundaryResult` dataclasses with the aggregation rule (any NOT_ENFORCED ⇒ NOT_ENFORCED; all ENFORCED ⇒ ENFORCED; else INCONCLUSIVE).
- [ ] T006 Finalize `BaseDynamicCheck` in `mcpfrisk/core/base_check.py`: `check_id`, `name`, `severity`, and `run(session) -> BoundaryResult` per contracts/interfaces.md (must never raise on server misbehavior).
- [ ] T007 Create `mcpfrisk/core/dynamic_runner.py` with `DynamicRunner(checks, timeout_s=5.0)` and a `DynamicSession` abstraction providing a bounded-timeout probe method (skeleton; wiring completed in US phases).
- [ ] T008 Extend `mcpfrisk/checks/registry.py`: add a new `DYNAMIC_CHECKS` list (separate from `STATIC_CHECKS`); leave it empty until the check exists.
- [ ] T009 Extend `mcpfrisk/cli.py`: add a `probe --server <url> [--timeout] [--fail-on] [--json] [--skip]` verb that constructs a `DynamicRunner`; preserve the existing `scan` exit-code contract (0/1) and add the INCONCLUSIVE-never-fails behavior.

**Checkpoint**: Dynamic scaffolding present; `mcpfrisk probe` runs end-to-end with zero registered checks (no-op).

---

## Phase 3: User Story 1 - Detect a server that serves unauthenticated callers (P1) 🎯 MVP

**Goal**: A finding is produced for an HTTP MCP server that answers an unauthenticated request.

**Independent Test**: Probe the vulnerable fixture → exactly one `AUTH_BOUNDARY` HIGH finding.

### Tests for User Story 1 (write FIRST, confirm RED) ⚠️

- [ ] T010 [P] [US1] Create `tests/fixtures/auth_vulnerable_server.py`: a localhost HTTP server that returns 200 to every request regardless of credentials.
- [ ] T011 [US1] Add `tests/test_auth_boundary.py::TestAuthBoundary::test_vulnerable_server_is_flagged` — starts the vulnerable fixture on an ephemeral port, runs the check, asserts one `AUTH_BOUNDARY` finding (SC-001). Confirm it FAILS before implementation.

### Implementation for User Story 1

- [ ] T012 [US1] Create `mcpfrisk/checks/auth_boundary.py`: `AuthBoundaryCheck(BaseDynamicCheck)`, `check_id="AUTH_BOUNDARY"`, `severity=HIGH`; implement probe P1 (no credentials) → classify 200/success as NOT_ENFORCED, 401/403 as ENFORCED.
- [ ] T013 [US1] Register `AuthBoundaryCheck` in `mcpfrisk/checks/registry.py` `DYNAMIC_CHECKS` (single entry — Constitution II).
- [ ] T014 [US1] Complete `DynamicRunner.run(target)` in `mcpfrisk/core/dynamic_runner.py`: open session, run dynamic checks, convert each NOT_ENFORCED `BoundaryResult` into one `Finding`.
- [ ] T015 [US1] Extend `mcpfrisk/core/report.py` to render a dynamic NOT_ENFORCED finding (location = `<operation> @ <target>`, secret-redacted evidence). Make T011 GREEN.

**Checkpoint**: US1 fully functional — vulnerable fixture is flagged; MVP deliverable.

---

## Phase 4: User Story 2 - Confirm a properly protected server passes cleanly (P1)

**Goal**: Zero findings against a server that correctly refuses unauthenticated requests.

**Independent Test**: Probe the clean fixture → zero `AUTH_BOUNDARY` findings.

### Tests for User Story 2 (write FIRST, confirm RED) ⚠️

- [ ] T016 [P] [US2] Create `tests/fixtures/auth_clean_server.py`: a localhost HTTP server that returns 401 + `WWW-Authenticate` when no/invalid token is presented.
- [ ] T017 [US2] Add `test_clean_server_is_not_flagged` to `tests/test_auth_boundary.py` — asserts zero findings against the clean fixture (SC-002). Confirm RED (will pass only once ENFORCED classification is correct).

### Implementation for User Story 2

- [ ] T018 [US2] Harden the classification in `mcpfrisk/checks/auth_boundary.py`: 401/403 ⇒ ENFORCED ⇒ no finding; ensure aggregation in `BoundaryResult` yields ENFORCED for the clean fixture. Make T017 GREEN without breaking T011.

**Checkpoint**: US1 + US2 both pass — the paired-fixture bar (Constitution VI) is met.

---

## Phase 5: User Story 3 - Invalid credentials rejected as firmly as missing ones (P2)

**Goal**: A server that accepts a junk token is flagged.

**Independent Test**: Probe a fixture that accepts any non-empty token → `AUTH_BOUNDARY` finding.

### Tests for User Story 3 (write FIRST, confirm RED) ⚠️

- [ ] T019 [P] [US3] Add an "accepts-any-token" mode to `tests/fixtures/auth_vulnerable_server.py` (or a small sibling fixture) that returns 200 for any non-empty `Authorization` header.
- [ ] T020 [US3] Add `test_invalid_credentials_are_flagged` to `tests/test_auth_boundary.py` (SC-005). Confirm RED.

### Implementation for User Story 3

- [ ] T021 [US3] Add probe P2 (invalid credential `Bearer not-a-real-token`) to `mcpfrisk/checks/auth_boundary.py`; record both P1 and P2 in `BoundaryResult.probes` (evidence). Make T020 GREEN.

**Checkpoint**: All three stories independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Edge cases, output, and CI — hardening against false negatives.

- [ ] T022 [P] Add `test_unreachable_server_is_inconclusive` and `test_timeout_is_inconclusive` to `tests/test_auth_boundary.py`: probing a dead port / non-responding server yields INCONCLUSIVE, never a pass, never a crash, within the timeout bound (SC-003, SC-004; FR-008/FR-009).
- [ ] T023 [P] Add `test_stdio_target_is_not_applicable` — a stdio target reports INCONCLUSIVE/not-applicable (research R1).
- [ ] T024 Extend `mcpfrisk/core/report.py` + JSON export: INCONCLUSIVE prints a distinct informational line (not a pass) and the JSON includes `outcome` + `probes` (contracts/interfaces.md, Contract 3).
- [ ] T025 [P] Ensure secret redaction in evidence output (no full tokens echoed) — add an assertion test mirroring the existing `test_report_redacts_the_secret_value`.
- [ ] T026 Update `.github/workflows/ci.yml`: install the `dynamic` extra and run `tests/test_auth_boundary.py` in the matrix.
- [ ] T027 [P] Validate `quickstart.md` end-to-end and tick the spec `checklists/requirements.md` follow-ups; run full `pytest` (existing 17 + new) green.

---

## Dependencies & Execution Order

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: depends on Setup; BLOCKS all user stories.
- **US1 (Phase 3)**: depends on Foundational. MVP. No dependency on US2/US3.
- **US2 (Phase 4)**: depends on Foundational; refines classification added in US1 but is independently testable (its own fixture + test).
- **US3 (Phase 5)**: depends on Foundational; adds the P2 probe; independently testable.
- **Polish (Phase 6)**: depends on the stories it hardens.

### Within each story

- Tests are written and MUST FAIL before implementation (Constitution I).
- Models (Phase 2) before checks; check before runner wiring; runner before report.

### Parallel opportunities

- T002, T003 in Setup.
- Fixtures (T010, T016, T019) are independent files → [P].
- Polish tests T022, T023, T025, T027 touch independent areas → [P].

---

## Implementation Strategy

### MVP first (US1 only)

1. Phase 1 Setup → 2. Phase 2 Foundational → 3. Phase 3 US1 → **STOP & VALIDATE**: vulnerable fixture flagged, clean path not yet asserted. Demoable MVP.

### Incremental delivery

US1 (detect) → US2 (no false positives — the trust gate) → US3 (invalid-token gap) → Polish (inconclusive/edge + CI). Each increment keeps prior tests green.

---

## Notes

- [P] = different files, no incomplete dependencies.
- Verify every test fails before implementing it (Constitution I, NON-NEGOTIABLE).
- A crash/timeout is NEVER enforcement (Constitution III; FR-008).
- Commit after each task or logical group.
