# Implementation Plan: SSRF_CHECK check

**Branch**: `003-ssrf-check` | **Date**: 2026-06-29 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/003-ssrf-check/spec.md`

## Summary

Add a second **dynamic (Tier 2)** check, `SSRF_CHECK`, that connects to a *running* MCP
server, discovers tools that accept a URL-like parameter, and verifies the server refuses to
fetch McpFrisk-controlled and reserved/internal targets. Detection is **out-of-band**: the
check stands up a single-use local **callback listener**, hands each candidate tool a unique
callback URL, and treats an inbound hit (with the matching token) as proof the server
performed an outbound request → `SSRF_CHECK` finding. It additionally probes loopback /
RFC1918 / link-local cloud-metadata (`169.254.169.254`) targets and a redirect that lands on
the callback (the documented first-host-only bypass). The verdict maps onto the existing
three-state `BoundaryOutcome` (guarded / not-guarded / inconclusive), so the `DynamicRunner`
and report path are reused unchanged.

## Technical Context

**Language/Version**: Python 3.10+ (matches existing project floor).

**Primary Dependencies**: **stdlib only** — `http.server` in a background thread for the
callback listener, `urllib`/`json` for `tools/list` + `tools/call` JSON-RPC over the existing
HTTP transport. This matches reality in the codebase: AUTH_BOUNDARY is itself stdlib-`urllib`
(no `dynamic`/`mcp` extra was ever added; `pyproject.toml` declares only `jsts` + `dev`). So
SSRF_CHECK adds **no new dependency at all** and Tier 1 stays dependency-free.

**Storage**: N/A (no persistence; the callback listener holds in-memory hit records only).

**Testing**: `pytest`. Validated against local fixture servers started by the test harness on
ephemeral localhost ports: a **vulnerable** fetch-server (fetches any URL), a **clean** server
(denylist + post-resolution IP check refuses internal/metadata), and a **redirect-bypass**
server (blocks the direct target but follows a redirect to the callback). A controlled
callback listener observes hits. No test reaches the public internet (FR-013/SC-006).

**Target Platform**: CLI tool, cross-platform (Windows/Linux/macOS), CI-first.

**Project Type**: Single-project Python CLI / library (existing layout under `mcpfrisk/`).

**Performance Goals**: Per tool-call wait and per-callback wait are bounded (default ≈5s,
configurable); a full SSRF evaluation of one server completes in seconds and never hangs.

**Constraints**: Must not regress the static Tier 1 path or the AUTH_BOUNDARY dynamic path. A
server crash/timeout/transport error MUST NOT be read as protection (false-negative guard).
Probes target ONLY McpFrisk's own callback endpoint and well-known reserved/benign addresses —
never a third-party host (FR-012). Findings reuse the existing `Finding`/`Severity` model.

**Scale/Scope**: One new dynamic check + a small reusable callback-listener helper + a generic
`call(method, params)` addition to `DynamicSession` for tool discovery. SSRF_CHECK targets
HTTP-transport servers; stdio servers are handled via the same session abstraction or reported
**inconclusive/not-applicable**, never as a pass or a finding.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] **I. Test-First (NON-NEGOTIABLE)**: Tasks order failing tests (against all three fixture
      servers + callback listener) before any `SsrfCheck` implementation; maintainer confirms RED.
- [x] **II. Plugin Isolation**: `SsrfCheck` is a self-contained `BaseDynamicCheck` subclass in
      its own file, wired via one `DYNAMIC_CHECKS` registry entry. The callback listener is a
      small dedicated helper; no existing check file is modified. The only shared-code change is
      an additive, generic `call()` on `DynamicSession` (used by any future dynamic check).
- [x] **III. False Positives over False Negatives**: No observed callback → guarded only if at
      least one probe was actually delivered; an undeliverable environment, crash, or timeout
      resolves to *inconclusive*, never a silent pass.
- [x] **IV. Zero Unnecessary Dependencies (Tier 1)**: Tier 1 stays stdlib-only. The check adds
      NO new dependency (stdlib `http.server`); it lives under the existing `dynamic` Tier 2 path.
- [x] **V. Evidence-Grounded Findings**: Each finding cites the tool + parameter exercised, the
      probe class (callback/loopback/metadata/redirect), and a redacted observation summary.
- [x] **VI. Paired Fixture Testing (NON-NEGOTIABLE)**: Ships with a vulnerable fetch-server AND
      a clean guarded server (plus a redirect-bypass server for US3), each with a paired test.
- [x] **VII. Security-Research Currency**: Fresh research pass completed 2026-06-29 →
      [research.md](./research.md) (May–Jun 2026 disclosures: mcp-server-fetch / playwright-mcp /
      fetch-mcp SSRF, link-local metadata IAM-exfiltration, redirect & DNS-rebinding bypass).

No gate violations → Complexity Tracking left empty.

## Project Structure

### Documentation (this feature)

```text
specs/003-ssrf-check/
├── plan.md              # This file
├── spec.md              # Feature specification
├── research.md          # Phase 0 output (security research + tech decisions)
├── data-model.md        # Phase 1 output (entities)
├── quickstart.md        # Phase 1 output (run/validate guide)
├── contracts/           # Phase 1 output (check + listener contracts)
│   └── interfaces.md
└── checklists/
    └── requirements.md  # Spec quality checklist
```

### Source Code (repository root)

```text
mcpfrisk/
├── core/
│   ├── models.py          # EXTEND: UrlFetchProbe + ProbeClass; reuse BoundaryOutcome verdict
│   ├── base_check.py      # USE: BaseDynamicCheck (run_against_server / to_finding) unchanged
│   ├── dynamic_runner.py  # EXTEND: additive generic DynamicSession.call(method, params)
│   └── report.py          # UNCHANGED (SSRF result renders via existing dynamic path)
├── checks/
│   ├── registry.py        # EXTEND: add SsrfCheck to DYNAMIC_CHECKS
│   ├── ssrf_check.py       # NEW: SsrfCheck(BaseDynamicCheck), check_id SSRF_CHECK
│   └── _ssrf_callback.py    # NEW: single-use localhost callback listener helper (stdlib http.server)
└── cli.py                 # UNCHANGED (reuses `probe --server <url>` from AUTH_BOUNDARY)

tests/
├── fixtures/
│   ├── ssrf_vulnerable_server.py   # NEW: fetches any URL it is given
│   ├── ssrf_clean_server.py        # NEW: denylist + post-resolution IP check
│   └── ssrf_redirect_server.py     # NEW: blocks direct target, follows redirect to callback
└── test_ssrf_check.py              # NEW: paired TP + FP + redirect + inconclusive/edge tests
```

**Structure Decision**: Single-project layout (existing). SSRF_CHECK slots into the dynamic
path built for AUTH_BOUNDARY (`dynamic_runner.py`, `DYNAMIC_CHECKS`, `BaseDynamicCheck`,
`BoundaryOutcome`), proving the Tier 2 abstraction generalizes to a second, structurally
different check. The out-of-band callback listener is the one genuinely new mechanism and is
isolated in its own helper module.

## Complexity Tracking

> No Constitution Check violations. Table intentionally empty.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| (none)    | —          | —                                    |
