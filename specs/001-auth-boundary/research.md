# Phase 0 Research: AUTH_BOUNDARY

**Date**: 2026-06-29 — fresh research pass per Constitution Principle VII.

## R1. How MCP defines an authentication boundary

**Decision**: AUTH_BOUNDARY targets **HTTP-transport** MCP servers and asserts that a
request lacking a valid token is refused with an authorization error (HTTP `401`,
or `403` for scope/permission failures), not answered.

**Rationale**: The MCP Authorization spec places auth at the **transport level**:

- HTTP-based transports SHOULD conform to OAuth 2.1. When authorization is required
  and not yet proven, the server **MUST** respond `401 Unauthorized`, and **MUST**
  send a `WWW-Authenticate` header pointing at Protected Resource Metadata
  (`/.well-known/oauth-protected-resource`, RFC 9728). Invalid/expired tokens MUST
  also receive `401`; insufficient scope is `403`.
- STDIO transports SHOULD NOT follow the OAuth spec; credentials come from the local
  environment. There is no transport-level auth handshake to probe.

**Alternatives considered**: Treating stdio servers as in-scope — rejected: there is
no protocol-level boundary to test, so a probe would be meaningless. stdio targets are
reported **inconclusive / not applicable**.

## R2. Why this check matters (threat data)

**Decision**: Severity = **HIGH** (serving arbitrary callers is an exploit plausible
under realistic conditions; reserve CRITICAL for confirmed data exfiltration paths).

**Rationale**: A January-2026 scan attributed a ~13% authentication-bypass rate
largely to missing or wrong **audience (`aud`) validation** — servers that accept
tokens not minted for them, or accept requests with no token at all. Prior research
(CONTEXT.md §5) put 38–41% of registered servers without effective auth. This is the
single highest-leverage dynamic check.

**Alternatives considered**: CRITICAL severity — rejected as the default; an open
boundary is severe but exploitation impact depends on what the tools expose, so HIGH
is the calibrated default, leaving room to raise per-finding later.

## R3. Client mechanism to talk to a running server

**Decision**: Use the official **`mcp` Python SDK** client over the **Streamable HTTP**
transport to open a session against the target URL. Added under a new optional
dependency extra `dynamic`; Tier 1 install remains dependency-free.

**Rationale**: Reimplementing the JSON-RPC/Streamable-HTTP handshake by hand would
duplicate a non-trivial, evolving protocol — exactly what Constitution Principle III
of the design notes (CONTEXT.md) warns against ("no reinventing good tools"). The SDK
is the genuinely-required Tier 2 dependency the constitution explicitly exempts.

**Alternatives considered**: Raw `httpx`/`urllib` requests against `/mcp` — viable for
a pure 401-status probe but brittle as the protocol evolves; kept as a possible
fallback only if the SDK proves too heavy. Decision: prefer SDK, allow a thin raw-HTTP
probe internally for the unauthenticated status check.

## R4. How to classify the three outcomes (no false negatives)

**Decision**: 
- **enforced** → server refuses the probe with `401`/`403` (authorization error). No finding.
- **not_enforced** → server returns a normal/success response to the unauthenticated or
  invalid-credential probe. Finding emitted.
- **inconclusive** → connection failed, timed out, server crashed, returned a malformed
  non-authorization error, exposed no operations, or used stdio transport. No pass, no finding.

**Rationale**: Directly encodes spec FR-004/FR-007/FR-008 and Principle III. A crash or
timeout is explicitly *not* enforcement, eliminating the most dangerous false negative
("it errored, so it must be secure").

**Alternatives considered**: Two-state pass/fail — rejected: it forces unreachable or
ambiguous servers into either a false "secure" or a noisy false finding.

## R5. Probe matrix

**Decision**: Run at least these probes against the same representative operation
(prefer `tools/list`; fall back to the first advertised `tools/call` if listing is open):

| Probe | Credential condition | Expected (enforced) |
|-------|----------------------|---------------------|
| P1    | none (no Authorization header) | 401 |
| P2    | invalid (`Authorization: Bearer not-a-real-token`) | 401 |

**Rationale**: P1 covers missing auth (largest gap); P2 covers presence-but-no-validation
servers (FR-003). Valid-credential probing is out of scope for v1 (the author would have
to supply a real token); the spec's Story 2 scenario 2 is satisfied by observing the
refusal, not a subsequent success.

## R6. Test fixtures without heavy infrastructure

**Decision**: Provide two minimal local HTTP servers as fixtures, started by the test
harness on an ephemeral `127.0.0.1` port:
- `auth_vulnerable_server.py` — answers every request with `200`, no auth check.
- `auth_clean_server.py` — returns `401` + `WWW-Authenticate` when no/invalid token.

**Rationale**: Satisfies Principle VI (paired vulnerable + clean) with deterministic,
fast, offline tests. Using stdlib `http.server` for fixtures keeps the *test* side light;
the check itself uses the SDK/raw-HTTP probe against these endpoints.

**Alternatives considered**: Spinning real `mcp`-SDK servers as fixtures — heavier and
slower; deferred. A localhost HTTP responder is sufficient to exercise the 401-vs-200
boundary the check actually judges.
