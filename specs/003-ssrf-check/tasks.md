---
description: "Task list for SSRF_CHECK dynamic check"
---

# Tasks: SSRF_CHECK check

**Input**: Design documents from `specs/003-ssrf-check/`

**Prerequisites**: plan.md, spec.md (user stories), research.md, data-model.md, contracts/interfaces.md, quickstart.md

**Tests**: MANDATORY for this project. Per the constitution (`.specify/memory/constitution.md`,
Principles I & VI) tests are written FIRST, approved by the maintainer, and confirmed
FAILING (red) before implementation. Every detection task ships with a paired
vulnerable-fixture and clean-fixture test.

**Organization**: Tasks grouped by user story (US1 detect, US2 clean-pass, US3 redirect-bypass)
so each is independently testable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no incomplete dependencies)
- **[Story]**: US1 / US2 / US3 (Setup, Foundational, Polish carry no story label)

## Path Conventions

Single project: package at `mcpfrisk/`, tests + fixtures at `tests/` (repo root).
SSRF_CHECK reuses the Tier 2 dynamic path built for AUTH_BOUNDARY.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: No new dependency — confirm the existing `dynamic` extra and test collection cover SSRF.

- [ ] T001 Confirm the `dynamic` extra in `pyproject.toml` is sufficient for SSRF_CHECK (the check is stdlib-only; only target-server talk needs `dynamic`). No new dependency added (Constitution IV); note this explicitly in the SSRF section.
- [ ] T002 [P] Confirm `pytest` collects `tests/test_ssrf_check.py` and `tests/fixtures/ssrf_*` via existing `[tool.pytest.ini_options]`.
- [ ] T003 [P] Add an "SSRF_CHECK" subsection to `README.md` (Tier 2): what it does (out-of-band callback proof), `mcpfrisk probe` usage, and `--skip SSRF_CHECK`.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The model + session + listener scaffolding every user story depends on.

**⚠️ CRITICAL**: No user-story work begins until this phase is complete.

- [ ] T004 Extend `mcpfrisk/core/models.py`: add `ProbeClass` (CALLBACK/METADATA/LOOPBACK/REDIRECT) and `UrlFetchProbe` dataclass (tool, parameter, probe_class, outcome, observed, `to_dict()`) per data-model.md. Reuse `BoundaryOutcome`; widen `BoundaryResult.probes` typing to a `DynamicProbe` protocol so `AuthProbe` and `UrlFetchProbe` both qualify. Do NOT modify the aggregation rule or `Finding`/`Severity`.
- [ ] T005 Add a generic, additive `DynamicSession.call(method, params=None, timeout_s=None) -> dict` to `mcpfrisk/core/dynamic_runner.py` (JSON-RPC over HTTP; returns parsed `result`; one typed transport error). Must not alter the existing `probe(...)` used by AUTH_BOUNDARY.
- [ ] T006 Create `mcpfrisk/checks/_ssrf_callback.py`: `CallbackListener` (stdlib `ThreadingHTTPServer` on `127.0.0.1:0`) + `CallbackHit` per contracts §2 — `new_probe_url()`, `redirect_url(token)`, `received(token, timeout_s)`, deterministic `__exit__` shutdown. Bounded waits (FR-010); benign fixed response body.

**Checkpoint**: Model + session.call + callback listener exist and are unit-testable in isolation; no check registered yet.

---

## Phase 3: User Story 1 - Detect a tool that fetches an attacker-controlled URL (P1) 🎯 MVP

**Goal**: A finding is produced for a server whose tool fetches a McpFrisk-controlled callback URL.

**Independent Test**: Probe the vulnerable fixture → exactly one `SSRF_CHECK` HIGH finding + a recorded callback hit.

### Tests for User Story 1 (write FIRST, confirm RED) ⚠️

- [ ] T007 [P] [US1] Create `tests/fixtures/ssrf_vulnerable_server.py`: a localhost HTTP MCP-style server exposing a `fetch_url(url)` tool that performs an outbound GET to any URL it is given (no validation). `tools/list` advertises the URL param.
- [ ] T008 [US1] Add `tests/test_ssrf_check.py::test_vulnerable_server_is_flagged` — starts the vulnerable fixture + a `CallbackListener` on ephemeral ports, runs the check, asserts exactly one `SSRF_CHECK` finding AND a callback hit with the matching token (SC-001). Confirm it FAILS before implementation.

### Implementation for User Story 1

- [ ] T009 [US1] Create `mcpfrisk/checks/ssrf_check.py`: `SsrfCheck(BaseDynamicCheck)`, `check_id="SSRF_CHECK"`, `severity=HIGH`. Discover candidate `(tool, param)` via `session.call("tools/list")` (URL-bearing name / `format: "uri"`); for each, send a CALLBACK probe via `session.call("tools/call", …)` and classify NOT_ENFORCED iff `listener.received(token)` returns a hit. Never raises (→ INCONCLUSIVE probe).
- [ ] T010 [US1] Register `SsrfCheck` in `mcpfrisk/checks/registry.py` `DYNAMIC_CHECKS` (single entry — Constitution II).
- [ ] T011 [US1] Confirm `DynamicRunner.run(target)` converts the NOT_ENFORCED `BoundaryResult` into one `Finding` (existing path); `to_finding` sets location = exercised tool, evidence = probe class + redacted observation. Make T008 GREEN.

**Checkpoint**: US1 fully functional — vulnerable fixture is flagged via a real callback. MVP deliverable.

---

## Phase 4: User Story 2 - Confirm a properly guarded server passes cleanly (P1)

**Goal**: Zero findings against a server that refuses internal/metadata/non-public targets.

**Independent Test**: Probe the clean fixture → zero `SSRF_CHECK` findings, no callback hit.

### Tests for User Story 2 (write FIRST, confirm RED) ⚠️

- [ ] T012 [P] [US2] Create `tests/fixtures/ssrf_clean_server.py`: a `fetch_url` tool that parses the URL, resolves the host, and refuses loopback/RFC1918/link-local/non-http(s) before fetching (the documented correct fix).
- [ ] T013 [US2] Add `test_clean_server_is_not_flagged` to `tests/test_ssrf_check.py` — asserts zero findings AND that the listener recorded no hit for any probe (SC-002). Confirm RED where the US1 logic is still too eager.

### Implementation for User Story 2

- [ ] T014 [US2] Ensure `SsrfCheck` only flags on an observed callback hit (not on tool-call success/error), so the guarded fixture (which never calls back) aggregates to ENFORCED ⇒ no finding. Make T013 GREEN without breaking T008.

**Checkpoint**: US1 + US2 both pass — the paired-fixture bar (Constitution VI) is met for SSRF.

---

## Phase 5: User Story 3 - Redirect-based bypass is still caught (P2)

**Goal**: A server that blocks the direct target but follows redirects is flagged.

**Independent Test**: Probe the redirect-bypass fixture → `SSRF_CHECK` finding.

### Tests for User Story 3 (write FIRST, confirm RED) ⚠️

- [ ] T015 [P] [US3] Create `tests/fixtures/ssrf_redirect_server.py`: a `fetch_url` tool that validates only the initial host but follows redirects without re-validation (so a callback URL that 302s to the unique token still fetches).
- [ ] T016 [US3] Add `test_redirect_bypass_is_flagged` to `tests/test_ssrf_check.py` using `listener.redirect_url(token)` (SC-003). Confirm RED.

### Implementation for User Story 3

- [ ] T017 [US3] Add the REDIRECT probe to `mcpfrisk/checks/ssrf_check.py` (supply `listener.redirect_url(token)`); record CALLBACK + REDIRECT (+ METADATA/LOOPBACK attempt evidence) in `BoundaryResult.probes`. Make T016 GREEN.

**Checkpoint**: All three stories independently functional; the OOB-callback advantage is demonstrated.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Edge cases, safety, output, and CI — hardening against false negatives.

- [ ] T018 [P] Add `test_no_url_tool_is_inconclusive` and `test_unreachable_server_is_inconclusive` to `tests/test_ssrf_check.py`: a server with no URL-accepting tool, and a dead port, each yield INCONCLUSIVE — never a pass, never a crash (SC-005; FR-008/FR-009).
- [ ] T019 [P] Add `test_evaluation_is_time_bounded`: a server that accepts the call but never fetches completes within the timeout bound (SC-004; FR-010).
- [ ] T020 [P] Add `test_probes_target_only_local_and_metadata` (SC-006/FR-012): assert the only non-loopback target ever produced is the well-known metadata IP attempt; no third-party host is contacted by McpFrisk itself.
- [ ] T021 Ensure secret/PII redaction in `observed` evidence (only a short token suffix, never response bodies) — add an assertion mirroring the existing redaction test.
- [ ] T022 Update `.github/workflows/ci.yml`: run `tests/test_ssrf_check.py` under the `dynamic` extra in the matrix.
- [ ] T023 [P] Validate `quickstart.md` end-to-end; update `README.md` Tier 2 section and `CONTEXT.md` (SSRF_CHECK now shipped); run the full `pytest` suite green.

---

## Dependencies & Execution Order

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: depends on Setup; BLOCKS all user stories (models + session.call + listener).
- **US1 (Phase 3)**: depends on Foundational. MVP. No dependency on US2/US3.
- **US2 (Phase 4)**: depends on Foundational + the US1 logic it tightens; independently testable via its own clean fixture.
- **US3 (Phase 5)**: depends on the US1 callback path; adds the REDIRECT probe; independently testable.
- **Polish (Phase 6)**: depends on the stories it hardens.

### Within each story

- Tests are written and MUST FAIL before implementation (Constitution I, NON-NEGOTIABLE).
- Model + session.call + listener (Phase 2) before the check; check before relying on the runner/report (reused unchanged).
- Vulnerable fixture/test before that check's impl; clean fixture/test before the FP-hardening.

### Parallel opportunities

- Setup: T002, T003.
- Fixtures T007, T012, T015 are independent files → [P].
- Polish tests T018, T019, T020 touch independent areas → [P].

---

## Implementation Strategy

### MVP first (US1 only)

1. Phase 1 Setup → 2. Phase 2 Foundational → 3. Phase 3 US1 → **STOP & VALIDATE**: vulnerable fixture flagged via a real callback. Demoable: "McpFrisk proves a server performs SSRF."

### Incremental delivery

US1 (detect via callback) → US2 (no false positives — the trust gate) → US3 (redirect bypass) → Polish (inconclusive/edge, safety, CI). Each increment keeps prior tests green.

---

## Notes

- [P] = different files, no incomplete dependencies.
- Verify every test fails before implementing it (Constitution I, NON-NEGOTIABLE).
- The authoritative signal is an inbound callback to McpFrisk's single-use listener, never the tool's return value.
- A crash/timeout/undeliverable-environment is NEVER protection (Constitution III; FR-008/FR-009).
- Probes target only McpFrisk's own listener + well-known reserved addresses (FR-012); no third-party traffic.
- Commit after each task or logical group.
