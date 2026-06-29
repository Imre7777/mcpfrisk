# Phase 1 Data Model: AUTH_BOUNDARY

All new types live in `mcpfrisk/core/models.py` (extend, do not break existing models).

## Enum: `CredentialCondition`

The credential state a probe is sent with.

| Value | Meaning |
|-------|---------|
| `NONE` | No `Authorization` header / no credentials |
| `INVALID` | Syntactically-present but bogus credential (e.g. `Bearer not-a-real-token`) |
| `VALID` | A genuine credential (reserved; not exercised in v1) |

## Enum: `BoundaryOutcome`

The verdict for one probe and, aggregated, for the server.

| Value | Meaning | Produces finding? |
|-------|---------|-------------------|
| `ENFORCED` | Server refused with `401`/`403` | No |
| `NOT_ENFORCED` | Server answered the probe (success response) | Yes |
| `INCONCLUSIVE` | Unreachable, timeout, crash, malformed error, no operations, or stdio transport | No (informational) |

## Entity: `AuthProbe`

One attempt against the server.

| Field | Type | Notes |
|-------|------|-------|
| `operation` | `str` | MCP operation exercised, e.g. `tools/list` |
| `condition` | `CredentialCondition` | Credential state used |
| `outcome` | `BoundaryOutcome` | Result of this single probe |
| `observed` | `str` | Short human-readable summary of the server response (status code / error / first bytes) — evidence, redacted of secrets |

**Rule**: `outcome` is derived only from an explicit authorization refusal → `ENFORCED`;
a success → `NOT_ENFORCED`; anything else (error/timeout/crash) → `INCONCLUSIVE`.

## Entity: `BoundaryResult`

Aggregate verdict for one target server.

| Field | Type | Notes |
|-------|------|-------|
| `target` | `str` | Server URL (or stdio descriptor) probed |
| `probes` | `list[AuthProbe]` | All probes run (≥ P1, P2) |
| `outcome` | `BoundaryOutcome` | Aggregate: `NOT_ENFORCED` if any probe is `NOT_ENFORCED`; else `ENFORCED` if all enforced; else `INCONCLUSIVE` |

**Aggregation rule** (worst-case wins, per Principle III): any `NOT_ENFORCED` probe
makes the server `NOT_ENFORCED`. Only if every probe is `ENFORCED` is the server
`ENFORCED`. Otherwise `INCONCLUSIVE`.

## Reuse: `Finding`

Existing `Finding` (in `core/models.py`) is reused unchanged in shape. For dynamic
findings:

| Field | Value for AUTH_BOUNDARY |
|-------|-------------------------|
| `check_id` | `"AUTH_BOUNDARY"` |
| `severity` | `Severity.HIGH` |
| `location` | the probed `operation` + target (instead of a source file/line) |
| `description` | which credential condition was accepted and a response summary |
| evidence | the `AuthProbe.observed` summary backing the verdict |

A `BoundaryResult` with `outcome == NOT_ENFORCED` maps to exactly one `Finding`.
`ENFORCED` and `INCONCLUSIVE` map to zero findings (the latter surfaced as an
informational note in the report, never as a pass).
