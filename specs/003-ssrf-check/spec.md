# Feature Specification: SSRF_CHECK check

**Feature Branch**: `003-ssrf-check`

**Created**: 2026-06-29

**Status**: Draft

**Input**: User description: "Add SSRF_CHECK dynamic check that verifies a running MCP server refuses tool calls fetching internal or cloud-metadata URLs"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Detect a tool that fetches an attacker-controlled URL (Priority: P1)

An MCP server author whose server exposes a URL-fetching tool (fetch, read-from-web,
screenshot, webhook, …) runs McpFrisk against the running server before release. McpFrisk
asks the server's tools to retrieve a benign, McpFrisk-controlled callback URL and observes
whether the server actually performed the outbound request.

**Why this priority**: This is the core of the check and a confirmed, actively-exploited gap
in the MCP ecosystem (multiple 2026 disclosures: reference fetch servers retrieve arbitrary
agent-supplied URLs with no validation → confused-deputy SSRF). Without this story there is
no check.

**Independent Test**: Point McpFrisk at a server fixture whose tool fetches any URL it is
given. The run MUST produce an `SSRF_CHECK` finding identifying the tool that fetched the
callback. This fully delivers value on its own.

**Acceptance Scenarios**:

1. **Given** a server with a tool that fetches any URL passed to it, **When** McpFrisk runs
   the SSRF check and supplies a unique callback URL it controls, **Then** McpFrisk observes
   the inbound callback and reports an `SSRF_CHECK` finding naming the tool and the parameter
   that carried the URL.
2. **Given** the same server, **When** the check supplies a URL targeting a link-local
   cloud-metadata address (e.g. the well-known `169.254.169.254`), **Then** the server's
   willingness to attempt that request is reported as evidence in the finding.

---

### User Story 2 - Confirm a properly guarded server passes cleanly (Priority: P1)

An author who has correctly implemented SSRF protections (scheme allow-list, private/
loopback/link-local denylist, post-DNS-resolution IP checks) runs McpFrisk and needs the
check to stay silent, so the tool is trustworthy enough to wire into CI as a gate.

**Why this priority**: Equal to Story 1. Per the project constitution, detection logic is
unverified until it is proven NOT to fire on a correctly-protected server. A check that
flags well-guarded servers is unusable as a CI gate.

**Independent Test**: Point McpFrisk at a server fixture that rejects internal/metadata/
non-public targets. The run MUST produce zero `SSRF_CHECK` findings, and the controlled
callback listener MUST receive no request from the reserved-target probes.

**Acceptance Scenarios**:

1. **Given** a server whose fetch tool refuses private/loopback/link-local targets, **When**
   the check supplies such targets, **Then** no callback is received and no finding is
   produced.
2. **Given** a server that only fetches from an explicit allow-list of public hosts, **When**
   the check supplies a non-allowed target, **Then** the request is refused and no finding is
   produced.

---

### User Story 3 - Redirect-based and DNS-rebinding bypass is still caught (Priority: P2)

An author wants assurance that a server which blocks the *initial* host but blindly follows
redirects (or re-resolves a hostname) does not silently regain the SSRF capability.

**Why this priority**: Closes a common partial-implementation gap documented in the 2026
disclosures (a public URL that 302-redirects to `169.254.169.254` bypasses a first-host-only
check). Valuable but secondary to the direct-fetch case.

**Independent Test**: Run the check against a fixture that validates the first host but
follows redirects, supplying a callback URL that redirects to a reserved target. McpFrisk
MUST report an `SSRF_CHECK` finding.

**Acceptance Scenarios**:

1. **Given** a server that blocks direct internal targets but follows redirects without
   re-validating, **When** the check supplies a URL that redirects to its controlled
   callback, **Then** the callback is received and a finding is produced.

---

### Edge Cases

- **Server cannot be reached / fails to start**: The check MUST NOT emit a false "secure"
  result. It reports that SSRF exposure could not be evaluated (inconclusive, distinct from a
  pass), so an unreachable server is never silently treated as safe.
- **Server exposes no URL-accepting tools**: The check reports that there was nothing to
  evaluate (inconclusive/skip) rather than a pass or a finding.
- **Server fetches the callback but very slowly**: The check waits a bounded time for the
  callback; absence within that window is treated as "no observed fetch" for that probe, and
  the overall run never hangs.
- **Server returns an error to the tool call but still performed the request**: The inbound
  callback (not the tool's return value) is the authoritative signal that a fetch occurred.
- **Outbound network egress is itself blocked in the test environment**: If no probe can
  possibly succeed because the environment forbids the server from reaching the callback,
  the result is inconclusive, never a pass.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: SSRF_CHECK MUST be a dynamic (Tier 2) check that exercises a **running** target
  MCP server as a client, reusing the project's existing dynamic-scan capability.
- **FR-002**: The check MUST identify candidate tools/parameters that accept a URL (or
  URL-like) input to exercise.
- **FR-003**: The check MUST stand up a unique, single-use, McpFrisk-controlled callback
  endpoint and supply its address as the URL input, so that an inbound hit unambiguously
  proves the server performed an outbound request on McpFrisk's behalf.
- **FR-004**: The check MUST also exercise at least one reserved/internal target class
  (loopback, RFC1918 private, and link-local cloud-metadata `169.254.169.254`) and record
  whether the server attempted it.
- **FR-005**: The check MUST classify a tool as **not guarded** (finding) when McpFrisk
  observes the server fetch a McpFrisk-controlled callback (directly or via redirect), and as
  **guarded** (no finding) when no controlled callback is observed for any probe.
- **FR-006**: When the boundary is not guarded, the check MUST emit a finding with check id
  `SSRF_CHECK`, identifying the tool and parameter exercised and which probe class triggered
  the fetch. (Severity per the project rubric; full read-SSRF / metadata reachability is a
  direct credential-exfiltration path and is therefore classified at the high end.)
- **FR-007**: Every finding MUST include enough evidence for a human to judge it: the tool
  and parameter exercised, the probe class (callback / loopback / metadata / redirect), and a
  short, secret-redacted summary of what was observed. (Constitution V.)
- **FR-008**: The check MUST distinguish three outcomes — guarded (no finding), not guarded
  (finding), and inconclusive (could not evaluate) — and MUST NOT report an inconclusive
  outcome as either pass or finding.
- **FR-009**: A server crash, timeout, or transport error MUST NOT be counted as SSRF
  protection (protection against false negatives).
- **FR-010**: The check MUST bound how long it waits for any single tool call and for any
  callback, so a non-responsive server or a never-arriving callback cannot hang the scan.
- **FR-011**: The check MUST be selectable/deselectable through the existing check-skip
  mechanism, consistent with the other checks.
- **FR-012**: The check MUST NOT cause harmful side effects: probes target only McpFrisk's
  own callback endpoint and well-known benign/reserved addresses, never third-party hosts.
- **FR-013**: The callback endpoint and all probe targets MUST be local to the run; the check
  MUST NOT depend on any external internet service being reachable to render a verdict.

### Key Entities *(include if feature involves data)*

- **URL-fetch probe**: A single attempt defined by (tool exercised, parameter carrying the
  URL, probe class: callback | loopback | metadata | redirect) and its observed outcome
  (fetched | not-fetched | inconclusive).
- **Callback observation**: The record that McpFrisk's controlled endpoint received a request
  attributable to a specific probe (unique token in the path), proving an outbound fetch.
- **SSRF result**: The aggregate verdict for the server/tool — guarded, not guarded, or
  inconclusive — derived from the probes, plus the evidence backing it.
- **Finding**: Reuses the project's existing finding model (severity, description, evidence),
  with location pointing at the exercised tool/parameter rather than a source line.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Against a deliberately unguarded fetch-server fixture, the check reports an
  `SSRF_CHECK` finding in 100% of runs (no false negatives on the known-bad case).
- **SC-002**: Against a correctly-guarded server fixture (denylist + post-resolution IP
  check), the check reports zero `SSRF_CHECK` findings in 100% of runs (no false positives).
- **SC-003**: The redirect-bypass fixture (blocks direct target, follows redirects) is
  reported as not guarded — proving the check is not fooled by first-host-only validation.
- **SC-004**: A single server evaluation completes within a small bounded time even when the
  server never performs the fetch (the check never hangs the scan).
- **SC-005**: When no running server is available, or the server exposes no URL-accepting
  tool, the run finishes with a clear inconclusive/skip outcome and a non-crashing exit.
- **SC-006**: The check produces no outbound requests to any host other than its own callback
  endpoint and the well-known reserved/benign probe addresses (no third-party traffic).

## Assumptions

- The author can provide or point McpFrisk at a runnable instance of their server; evaluating
  outbound-fetch behaviour necessarily requires a running server (Tier 2, like AUTH_BOUNDARY).
- "SSRF protection" here means the server's own egress access boundary; McpFrisk judges only
  whether the server can be coerced into fetching McpFrisk-controlled / reserved targets, not
  the completeness of any particular allow-list.
- Reusing the existing severity scale, finding model, and dynamic-scan plumbing is preferred
  over inventing a parallel reporting path, to keep output consistent across checks.
- The precise transport(s), callback-listener mechanism, and URL-parameter discovery strategy
  are intentionally left to the implementation plan, not fixed by this specification.
- An inbound callback to a unique single-use token is treated as proof of an outbound fetch;
  the benign callback content makes the probe safe to run against any server.
