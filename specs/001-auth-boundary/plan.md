# Implementation Plan: AUTH_BOUNDARY check

**Branch**: `001-auth-boundary` | **Date**: 2026-06-29 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-auth-boundary/spec.md`

## Summary

Add McpFrisk's first **dynamic (Tier 2)** check, `AUTH_BOUNDARY`, which connects to a
*running* MCP server over its HTTP transport, exercises it as an unauthenticated and
then as an invalid-credential caller, and reports a finding when the server answers
instead of refusing. This requires a new dynamic execution path (`DynamicRunner` +
`BaseDynamicCheck` realization) alongside the existing static `Runner`, a way to point
the CLI at a running server, and a three-state outcome model (enforced / not enforced /
inconclusive).

## Technical Context

**Language/Version**: Python 3.10+ (matches existing project floor)

**Primary Dependencies**: `mcp` (official Model Context Protocol Python SDK) as the
client to talk to a running server, which pulls in `httpx` for the Streamable HTTP
transport. This is the **explicitly permitted Tier 2 exception** to Constitution
Principle IV (zero-dependency rule applies to Tier 1 static checks only). Added under
a new optional extra `dynamic` in `pyproject.toml`; Tier 1 install stays dependency-free.

**Storage**: N/A (no persistence)

**Testing**: `pytest`. Dynamic checks are validated against two local fixture servers
started by the test harness — one that enforces auth (clean) and one that does not
(vulnerable) — bound to an ephemeral localhost port.

**Target Platform**: CLI tool, cross-platform (Windows/Linux/macOS), CI-first.

**Project Type**: Single-project Python CLI / library (existing layout under `mcpfrisk/`).

**Performance Goals**: Per-request wait is bounded (default ≈5s, configurable); a full
auth-boundary evaluation of one server completes in seconds and never hangs the scan.

**Constraints**: Must not regress the static Tier 1 path or its zero-dependency install.
A server crash/timeout/transport error MUST NOT be read as enforcement (false-negative
guard). Findings reuse the existing `Finding`/`Severity` model.

**Scale/Scope**: One new check + one new runner + minimal CLI surface. AUTH_BOUNDARY
targets HTTP-transport servers; stdio servers (no transport-level auth per MCP spec)
are reported as **inconclusive/not-applicable**, never as a pass or a finding.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Verify the plan against the McpFrisk Constitution (`.specify/memory/constitution.md`):

- [x] **I. Test-First (NON-NEGOTIABLE)**: Tasks order the failing tests (against both
      fixture servers) before any `AuthBoundaryCheck`/`DynamicRunner` implementation;
      maintainer approves the tests and confirms RED first.
- [x] **II. Plugin Isolation**: `AuthBoundaryCheck` is a self-contained
      `BaseDynamicCheck` subclass in its own file; it is wired in via a single
      `STATIC_CHECKS`-equivalent registry entry (a new `DYNAMIC_CHECKS` list). No
      existing check file is modified.
- [x] **III. False Positives over False Negatives**: Ambiguous/uncertain server
      behavior resolves to *inconclusive* or *finding*, never a silent pass; a crash
      or timeout is never counted as enforcement.
- [x] **IV. Zero Unnecessary Dependencies (Tier 1)**: Tier 1 stays stdlib-only; the
      `mcp` SDK is added only under the `dynamic` extra and is genuinely required to
      speak the protocol — the sanctioned Tier 2 exception.
- [x] **V. Evidence-Grounded Findings**: Each finding cites the operation exercised,
      the credential condition, and a summary of the server's response; severity per
      rubric (HIGH — exploit plausible under realistic conditions).
- [x] **VI. Paired Fixture Testing (NON-NEGOTIABLE)**: Ships with BOTH a vulnerable
      (no-auth) and a clean (enforcing) fixture server, each with a paired test.
- [x] **VII. Security-Research Currency**: Fresh research pass completed 2026-06-29 →
      [research.md](./research.md) (MCP authorization spec, 401/WWW-Authenticate,
      audience-validation gap from Jan-2026 scan).

No gate violations → Complexity Tracking left empty.

## Project Structure

### Documentation (this feature)

```text
specs/001-auth-boundary/
├── plan.md              # This file
├── spec.md              # Feature specification
├── research.md          # Phase 0 output (security research + tech decisions)
├── data-model.md        # Phase 1 output (entities)
├── quickstart.md        # Phase 1 output (run/validate guide)
├── contracts/           # Phase 1 output (check + CLI contracts)
│   └── interfaces.md
└── checklists/
    └── requirements.md  # Spec quality checklist (from /speckit-specify)
```

### Source Code (repository root)

```text
mcpfrisk/
├── core/
│   ├── models.py          # EXTEND: add BoundaryOutcome (enforced/not_enforced/inconclusive)
│   ├── base_check.py      # USE: BaseDynamicCheck (already stubbed) — finalize run() contract
│   ├── runner.py          # UNCHANGED (static path)
│   ├── dynamic_runner.py  # NEW: orchestrates dynamic checks against a live server session
│   └── report.py          # EXTEND: render dynamic results + inconclusive outcomes
├── checks/
│   ├── registry.py        # EXTEND: add DYNAMIC_CHECKS = [AuthBoundaryCheck] (new list)
│   └── auth_boundary.py    # NEW: AuthBoundaryCheck(BaseDynamicCheck), check_id AUTH_BOUNDARY
└── cli.py                 # EXTEND: way to target a running server (e.g. `probe --server <url>`)

tests/
├── fixtures/
│   ├── auth_clean_server.py        # NEW: HTTP MCP server that returns 401 unauthenticated
│   └── auth_vulnerable_server.py   # NEW: HTTP MCP server that answers without auth
└── test_auth_boundary.py           # NEW: paired true-positive + false-positive + edge tests
```

**Structure Decision**: Single-project layout (existing). The dynamic path mirrors the
static path 1:1 (`runner.py` ⇄ `dynamic_runner.py`, `STATIC_CHECKS` ⇄ `DYNAMIC_CHECKS`)
so the plugin-isolation principle holds identically for dynamic checks.

## Complexity Tracking

> No Constitution Check violations. Table intentionally empty.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| (none)    | —          | —                                    |
