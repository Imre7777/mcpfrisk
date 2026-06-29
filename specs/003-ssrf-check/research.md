# Research: SSRF_CHECK

**Date**: 2026-06-29 | **Feature**: `003-ssrf-check` | Constitution Principle VII (currency).

## Threat landscape (fresh pass, June 2026)

SSRF is a confirmed, actively-exploited gap in the MCP ecosystem. Several reference and
community servers expose URL-fetching tools that retrieve **any** agent-supplied URL with no
scheme allow-list, host denylist, or post-DNS-resolution IP check:

- **`mcp-server-fetch`** (Anthropic reference, `modelcontextprotocol/servers`): passes
  arbitrary URLs to `httpx.get(...)`. Public issues #4116 / #4143 / #4205; full disclosure
  on seclists (2026-05-25), CVSS 7.5 HIGH. Independent re-verification (39 days post-disclosure)
  found even the latest PyPI release `2026.6.4` **still vulnerable** — the fix (#4226) had not
  shipped. A second code path (`get_prompt` → `fetch_url`) bypassed the autonomy guard entirely.
- **`playwright-mcp`** (Microsoft): same class — arbitrary navigation/fetch without internal
  network filtering.
- **`fetch-mcp`** (egoist): `fetch_url` performs outbound requests to any URL; confirmed via
  out-of-band callback (`http://127.0.0.1:PORT/ssrf/<token>` hit observed). CVSS 9.1 CRITICAL,
  CWE-918. Full read-SSRF (response body returned to the caller).

**Impact**: On cloud hosts (EC2/GCP/Azure/ECS), a prompt-injected agent can call
`fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/")`; IMDSv1 returns
IAM credentials with no authentication, which the agent then exfiltrates. On laptops/offices
the same primitive reaches localhost and internal services. `file://`, `gopher://`, `dict://`
schemes broaden it further (httpx honors `file://`).

## The correct fix (what a *guarded* server does)

The accepted fix shape across the disclosures (#4205/#4226):

1. **Scheme allow-list**: only `http`/`https`; reject `file://`, `gopher://`, `dict://`.
2. **Reserved-range denylist** on the **resolved** IP(s): loopback `127.0.0.0/8` + `::1`,
   link-local `169.254.0.0/16` (covers cloud metadata), RFC1918 `10/8` `172.16/12`
   `192.168/16`, unspecified `0.0.0.0`, plus other reserved ranges.
3. **Resolve-then-check**: `getaddrinfo` the hostname and validate **every** returned IP
   before connecting (defeats DNS rebinding).
4. **Per-redirect re-validation**: `follow_redirects=False`; re-run the same checks against
   each `Location` (a public URL that 302s to `169.254.169.254` otherwise bypasses a
   first-host-only check). Bound the redirect chain.
5. Operationally: IMDSv2 (session-token), VPC/security-group egress policy — out of McpFrisk's
   scope (we test the application boundary, not the network).

## Detection decision: out-of-band callback (the reliable signal)

A *static* read of source can flag unconstrained URL params (mcp-doctor's `_check_ssrf`,
mcp-safeguard), but the user chose the **dynamic** check: prove the running server actually
performs the fetch. The authoritative, low-false-positive signal used by the disclosures
themselves is an **out-of-band (OOB) callback**:

- McpFrisk stands up a single-use localhost HTTP listener on an ephemeral port.
- For each candidate tool/param, it supplies a unique URL `http://127.0.0.1:<port>/<token>`.
- If the listener records a hit with the matching `<token>`, the server *demonstrably* made
  an outbound request on McpFrisk's behalf → not guarded. No callback for any probe → guarded.

This is decisive (a real fetch, not a heuristic), safe (only McpFrisk's own endpoint is
targeted), and self-contained (no external internet dependency — FR-013/SC-006).

**Probe classes exercised** (each a distinct piece of evidence):

| Class      | Target supplied to the tool                         | What it proves |
|------------|------------------------------------------------------|----------------|
| `callback` | `http://127.0.0.1:<port>/<token>`                    | server fetches arbitrary attacker URLs (loopback) |
| `metadata` | `http://169.254.169.254/latest/meta-data/...`        | server attempts the cloud-metadata IP |
| `loopback` | `http://127.0.0.1:<reserved>/`                       | server attempts loopback service |
| `redirect` | a callback URL that 302s to the unique callback hit  | server follows redirects without re-validation (US3) |

The `callback` and `redirect` classes yield a confirmed inbound hit (strongest evidence); the
`metadata`/`loopback` classes are recorded as attempt evidence (the server's willingness to
target them) even when the address itself does not call back in the test environment.

## Tooling / architecture decisions

- **Reuse Tier 2 plumbing**: `DynamicRunner` + `BaseDynamicCheck` + three-state
  `BoundaryOutcome` (built for AUTH_BOUNDARY) carry SSRF unchanged — guarded ⇒ `ENFORCED`,
  not-guarded ⇒ `NOT_ENFORCED`, undeterminable ⇒ `INCONCLUSIVE`.
- **Tool discovery**: add a generic `DynamicSession.call("tools/list")` / `call("tools/call", …)`
  helper (additive, stdlib `urllib`+`json`), then select params whose name/schema looks
  URL-bearing (`url`, `uri`, `href`, `link`, `endpoint`, `webhook`, `src`, `target`, format
  `uri`). No new dependency.
- **Callback listener**: stdlib `http.server.ThreadingHTTPServer` on `127.0.0.1:0`, started/
  stopped per evaluation, recording `(token, path, method, time)` hits in memory. Isolated in
  `checks/_ssrf_callback.py`.
- **Bounded waits** (FR-010): both the tool call and the post-call callback-wait use the
  configurable dynamic timeout; absence within the window = "not fetched" for that probe.
- **Safety** (FR-012): the only non-local target ever sent is the well-known link-local
  metadata IP as *attempt* evidence; McpFrisk never connects out to a third party itself.

## Open questions / deferred

- Authenticated tool calls (a server that requires auth before exposing the fetch tool) —
  reuse the AUTH_BOUNDARY credential plumbing later if needed; v1 targets the common
  no-auth / post-auth fetch tool.
- Non-HTTP (stdio) transports: handled via the session abstraction or reported inconclusive;
  full stdio fetch-tool exercising can follow once stdio dynamic support matures.
