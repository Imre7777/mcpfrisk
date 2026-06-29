# Feature Specification: AUTH_BOUNDARY check

**Feature Branch**: `001-auth-boundary`

**Created**: 2026-06-29

**Status**: Draft

**Input**: User description: "Add AUTH_BOUNDARY dynamic check that verifies an MCP server rejects unauthenticated requests"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Detect a server that serves unauthenticated callers (Priority: P1)

An MCP server author whose server is meant to require authentication runs McpFrisk
against their server before release. McpFrisk exercises the server as an
unauthenticated caller and reports whether the server processed the request anyway
instead of refusing it.

**Why this priority**: This is the core value of the check and the single most
impactful gap in the MCP ecosystem (research indicates a large share of registered
servers ship with no effective authentication). Without this story there is no check.

**Independent Test**: Point McpFrisk at a server fixture that is supposed to require
auth but does not enforce it. The run MUST produce an `AUTH_BOUNDARY` finding. This
fully delivers value on its own.

**Acceptance Scenarios**:

1. **Given** a server that requires no credentials and answers every request,
   **When** McpFrisk runs the AUTH_BOUNDARY check against it,
   **Then** McpFrisk reports an `AUTH_BOUNDARY` finding identifying which operation
   was answered without authentication.
2. **Given** a server that returns a normal (success) response to a request carrying
   no credentials, **When** the check runs, **Then** the response is treated as a
   failure to enforce authentication and a finding is produced.

---

### User Story 2 - Confirm a properly protected server passes cleanly (Priority: P1)

An author who has correctly implemented authentication runs McpFrisk and needs the
check to stay silent, so the tool is trustworthy enough to wire into CI as a gate.

**Why this priority**: Equal to Story 1. Per the project constitution, detection
logic is unverified until it is proven NOT to fire on a correctly-protected server.
A check that cries wolf on good servers is unusable as a CI gate.

**Independent Test**: Point McpFrisk at a server fixture that correctly refuses
unauthenticated requests. The run MUST produce zero `AUTH_BOUNDARY` findings.

**Acceptance Scenarios**:

1. **Given** a server that refuses unauthenticated requests with an authorization
   error, **When** the check runs, **Then** no `AUTH_BOUNDARY` finding is produced.
2. **Given** a server that accepts the same request once valid credentials are
   supplied, **When** the check runs unauthenticated, **Then** the refusal (not the
   later success) is what the check observes, and no finding is produced.

---

### User Story 3 - Invalid credentials are rejected as firmly as missing ones (Priority: P2)

An author wants assurance that the server rejects not only requests with no
credentials, but also requests carrying clearly invalid credentials.

**Why this priority**: Closes a common partial-implementation gap (servers that
check for the *presence* of a token but never validate it). Valuable but secondary
to the missing-credentials case.

**Independent Test**: Run the check against a fixture that accepts any non-empty
token. McpFrisk MUST report an `AUTH_BOUNDARY` finding.

**Acceptance Scenarios**:

1. **Given** a server that accepts an obviously invalid credential, **When** the
   check runs with a junk credential, **Then** a finding is produced.

---

### Edge Cases

- **Server cannot be reached / fails to start**: The check MUST NOT emit a false
  "secure" result. It reports that the boundary could not be evaluated (an
  informational result, distinct from a pass), so an unreachable server is never
  silently treated as safe.
- **Server exposes no callable operations**: The check reports that there was
  nothing to evaluate rather than a pass or a finding.
- **Server hangs / never responds**: The check stops waiting after a bounded time
  and reports the operation as inconclusive, never blocking the run indefinitely.
- **Server crashes or returns a malformed error when called without auth**: A crash
  or unhandled error is not the same as a deliberate authorization refusal; the
  check MUST NOT count it as proper enforcement.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: McpFrisk MUST be able to exercise a target MCP server as a client and
  observe its responses (this introduces the project's first dynamic, running-server
  capability).
- **FR-002**: The check MUST send at least one representative request that carries
  **no** credentials and record whether the server refused it or processed it.
- **FR-003**: The check MUST send at least one representative request that carries
  **clearly invalid** credentials and record whether the server refused it.
- **FR-004**: The check MUST classify a response as "enforced" only when the server
  explicitly refuses on authorization grounds; a normal success response MUST be
  classified as "not enforced".
- **FR-005**: When the server fails to enforce the boundary, the check MUST emit a
  finding with check id `AUTH_BOUNDARY`, identifying the operation that was answered
  and whether it was the missing-credential or invalid-credential probe.
- **FR-006**: Every finding MUST include enough evidence for a human to judge it: the
  operation exercised, the credential condition used, and a summary of the server's
  response. (Constitution V.)
- **FR-007**: The check MUST distinguish three outcomes — enforced (no finding),
  not enforced (finding), and inconclusive (could not evaluate) — and MUST NOT report
  an inconclusive outcome as either pass or finding.
- **FR-008**: A server crash, timeout, or transport error MUST NOT be counted as
  authorization enforcement (FR-004 protection against false negatives).
- **FR-009**: The check MUST bound how long it waits for any single server response
  so a non-responsive server cannot hang the overall scan.
- **FR-010**: The `AUTH_BOUNDARY` severity MUST follow the project rubric; serving
  arbitrary callers without authentication is a direct exploit path and is therefore
  classified at the high end of the scale.
- **FR-011**: The check MUST be selectable/deselectable through the existing
  check-skip mechanism, consistent with the other checks.
- **FR-012**: Because this check requires a running server (unlike the static Tier 1
  checks), McpFrisk MUST make clear to the user how a target server is supplied, and
  MUST behave predictably (an explicit inconclusive/skip result, never a crash) when
  no running server is available.

### Key Entities *(include if feature involves data)*

- **Auth probe**: A single attempt against the server defined by (operation
  exercised, credential condition: none | invalid | valid) and its observed outcome
  (refused | answered | inconclusive).
- **Boundary result**: The aggregate verdict for the server — enforced, not
  enforced, or inconclusive — derived from the probes, plus the evidence backing it.
- **Finding**: Reuses the project's existing finding model (file/location, severity,
  description, evidence), with location pointing at the exercised operation rather
  than a source line.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Against a deliberately unprotected server fixture, the check reports an
  `AUTH_BOUNDARY` finding in 100% of runs (no false negatives on the known-bad case).
- **SC-002**: Against a correctly-protected server fixture, the check reports zero
  `AUTH_BOUNDARY` findings in 100% of runs (no false positives on the known-good case).
- **SC-003**: A single server evaluation completes within a small bounded time even
  when the server is unresponsive (the check never hangs the scan).
- **SC-004**: When no running server is available, the run finishes with a clear
  inconclusive/skip outcome and a non-crashing exit, every time.
- **SC-005**: Both the missing-credential and invalid-credential conditions are
  exercised and independently reflected in the result evidence.

## Assumptions

- The author can provide or point McpFrisk at a runnable instance of their server;
  evaluating authentication necessarily requires a running server (this is what makes
  it a Tier 2 / dynamic check rather than a static source scan).
- "Authentication" here means the server's own access boundary; McpFrisk judges only
  whether unauthenticated/invalid callers are refused, not the cryptographic strength
  of any particular scheme.
- Reusing the existing severity scale and finding model is preferred over inventing a
  parallel reporting path, to keep output consistent across checks.
- The precise transport(s) and client mechanism for talking to a running server are
  intentionally left to the implementation plan, not fixed by this specification.
