# Data Model: SSRF_CHECK

**Feature**: `003-ssrf-check` | **Phase 1**

The SSRF check reuses the existing Tier 2 verdict plumbing (`BoundaryOutcome`,
`BoundaryResult`, `DynamicScanResult`, `Finding`/`Severity`) and adds two small,
SSRF-specific value objects plus a callback-listener record. No existing entity is rewritten;
`UrlFetchProbe` is shaped to satisfy `BoundaryResult` structurally (it exposes `.outcome` and
`.to_dict()`, the only members `BoundaryResult._aggregate` / `failing_probe` / `to_dict`
touch), so `BoundaryResult.probes` simply carries `UrlFetchProbe` items.

## Reused (unchanged) entities — `mcpfrisk/core/models.py`

- **`BoundaryOutcome`** (enum): `ENFORCED` / `NOT_ENFORCED` / `INCONCLUSIVE`. SSRF mapping:
  - `ENFORCED`  ⇒ **guarded** (no observed fetch of any controlled/reserved probe) → no finding
  - `NOT_ENFORCED` ⇒ **not guarded** (a controlled callback was observed) → finding
  - `INCONCLUSIVE` ⇒ could not evaluate (no URL-tool, unreachable, undeliverable env, crash)
- **`BoundaryResult`**: aggregates probes (worst-case wins — a single NOT_ENFORCED probe makes
  the server not-guarded; all-ENFORCED makes it guarded; otherwise inconclusive). The type hint
  on `.probes` is widened to a small `DynamicProbe` protocol (`outcome: BoundaryOutcome`,
  `to_dict() -> dict`) so both `AuthProbe` and `UrlFetchProbe` qualify.
- **`DynamicScanResult`**, **`Finding`**, **`Severity`**: unchanged.

## New entities — `mcpfrisk/core/models.py`

### `ProbeClass` (enum)

The kind of target supplied to a tool, i.e. *what each probe proves*.

| Value      | Target supplied                                   | Evidence meaning |
|------------|---------------------------------------------------|------------------|
| `CALLBACK` | `http://127.0.0.1:<listener-port>/<token>`        | server fetched an arbitrary loopback URL (confirmed hit) |
| `METADATA` | `http://169.254.169.254/latest/meta-data/...`     | server attempted the cloud-metadata IP |
| `LOOPBACK` | `http://127.0.0.1:<reserved-port>/`               | server attempted a loopback service |
| `REDIRECT` | a callback URL that 302-redirects to `<token>`    | server follows redirects without re-validation (US3) |

### `UrlFetchProbe` (dataclass)

One attempt against one tool/parameter with one probe class.

| Field        | Type             | Notes |
|--------------|------------------|-------|
| `tool`       | `str`            | tool name exercised (e.g. `fetch_url`) |
| `parameter`  | `str`            | parameter that carried the URL (e.g. `url`) |
| `probe_class`| `ProbeClass`     | which target class was sent |
| `outcome`    | `BoundaryOutcome`| NOT_ENFORCED if a matching callback hit was observed; ENFORCED if the server refused/did not fetch; INCONCLUSIVE if undeliverable/crash/timeout |
| `observed`   | `str`            | short, **secret-redacted** summary (status / hit token suffix / error) — Principle V |

`to_dict()` → `{tool, parameter, probe_class, outcome, observed}`.

## Helper-local entities — `mcpfrisk/checks/_ssrf_callback.py`

### `CallbackHit` (dataclass)

A single inbound request recorded by the listener.

| Field    | Type    | Notes |
|----------|---------|-------|
| `token`  | `str`   | unique per-probe token taken from the request path |
| `path`   | `str`   | request path as received |
| `method` | `str`   | HTTP method |
| `at`     | `float` | monotonic timestamp of receipt |

### `CallbackListener` (context manager / handle)

- `__enter__` binds a `ThreadingHTTPServer` on `127.0.0.1:0`, returns a handle exposing
  `base_url` and `new_probe_url() -> (token, url)`.
- `received(token, timeout_s) -> CallbackHit | None` blocks up to `timeout_s` for a hit with
  that token (bounded wait — FR-010).
- `__exit__` shuts the server down deterministically (no leaked thread/port).

## Discovery (transient, not persisted)

- **Candidate tool/param**: derived from `tools/list` — a `(tool_name, param_name)` pair whose
  param name or JSON-schema `format: "uri"` looks URL-bearing (`url`, `uri`, `href`, `link`,
  `endpoint`, `webhook`, `src`, `target`, …). Each candidate yields one or more `UrlFetchProbe`s.

## Aggregation rule (recap)

A server/tool is reported **not guarded** (finding) when **any** `UrlFetchProbe` is
`NOT_ENFORCED` (a controlled callback was observed). It is **guarded** only when at least one
probe was actually delivered and **none** produced a callback. If no probe could be delivered
(no URL tool, unreachable, environment blocks egress), the result is **inconclusive** — never
a silent pass (Constitution III).
