# Contracts: SSRF_CHECK

**Feature**: `003-ssrf-check` | **Phase 1**

Defines the interfaces the implementation must satisfy. SSRF_CHECK plugs into the dynamic path
built for AUTH_BOUNDARY; the only shared-surface change is an additive, generic
`DynamicSession.call(...)`.

## 1. Check contract — `mcpfrisk/checks/ssrf_check.py`

`SsrfCheck` subclasses `BaseDynamicCheck` and honours the existing dynamic contract:

```python
class SsrfCheck(BaseDynamicCheck):
    check_id = "SSRF_CHECK"
    severity = Severity.HIGH          # full read-SSRF / metadata reachability → credential exfil

    def run_against_server(self, session: DynamicSession) -> BoundaryResult: ...
    def to_finding(self, result: BoundaryResult) -> Finding | None: ...
```

- **`run_against_server(session)`**:
  1. Discover candidate `(tool, param)` pairs via `session.call("tools/list")`
     (URL-bearing param name / `format: "uri"`). No candidates ⇒ `BoundaryResult` with an
     INCONCLUSIVE probe ("no URL-accepting tool") — never a pass.
  2. Open a `CallbackListener`. For each candidate, build `CALLBACK`, `METADATA`, `LOOPBACK`,
     and `REDIRECT` probes and invoke the tool via `session.call("tools/call", …)`.
  3. After each call, `listener.received(token, timeout_s)` decides the probe outcome:
     a matching hit ⇒ `NOT_ENFORCED`; bounded-wait expiry with a delivered call ⇒ `ENFORCED`;
     transport error/crash/timeout on the call itself ⇒ `INCONCLUSIVE`.
  4. Return `BoundaryResult(target, probes=[UrlFetchProbe, …])`; its `_aggregate()` yields the
     server verdict (worst-case wins).
- **`to_finding(result)`**: returns `None` unless `result.outcome == NOT_ENFORCED`. The finding
  reuses the `Finding` model with location = the exercised `tool` (param in the description),
  severity HIGH, and evidence naming the triggering probe class + redacted observation (V).
- **Never raises**: any internal error degrades to an INCONCLUSIVE probe (III).

## 2. Callback-listener contract — `mcpfrisk/checks/_ssrf_callback.py`

```python
class CallbackListener:
    def __enter__(self) -> "CallbackListener": ...   # binds 127.0.0.1:0, starts thread
    def __exit__(self, *exc) -> None: ...            # deterministic shutdown, no leaked port
    base_url: str                                    # e.g. "http://127.0.0.1:54321"
    def new_probe_url(self) -> tuple[str, str]: ...  # (token, "http://127.0.0.1:PORT/<token>")
    def redirect_url(self, token: str) -> str: ...   # a URL on the listener that 302s to /<token>
    def received(self, token: str, timeout_s: float) -> CallbackHit | None: ...
```

- Binds only to loopback; an ephemeral port (`:0`) avoids collisions and parallel-test races.
- `received` blocks at most `timeout_s` (FR-010) and matches strictly on the unique `token`
  (no cross-probe contamination, no false hit from unrelated traffic).
- Records hits in memory only; the response body is a fixed benign string (safe to fetch).

## 3. Session contract — additive — `mcpfrisk/core/dynamic_runner.py`

```python
class DynamicSession:
    def call(self, method: str, params: dict | None = None,
             timeout_s: float | None = None) -> dict: ...
```

- Sends a JSON-RPC request (`method`, `params`) over the HTTP transport, returns the parsed
  `result` (or raises a single typed transport error the check converts to INCONCLUSIVE).
- Generic and reusable by any future dynamic check; does not alter the existing `probe(...)`
  used by AUTH_BOUNDARY.

## 4. Registration — `mcpfrisk/checks/registry.py`

- Append `SsrfCheck` to `DYNAMIC_CHECKS`. `get_all_dynamic_checks()` then returns it, and the
  existing `--skip SSRF_CHECK` path works unchanged (FR-011).

## 5. Report — `mcpfrisk/core/report.py`

- **Unchanged.** The SSRF `BoundaryResult` / `DynamicScanResult` renders through the existing
  dynamic report path; INCONCLUSIVE is shown distinctly from guarded/finding (FR-008).

## 6. Test contract — `tests/test_ssrf_check.py` + fixtures

- **Fixtures**: `ssrf_vulnerable_server.py` (fetches any URL), `ssrf_clean_server.py`
  (denylist + post-resolution IP check), `ssrf_redirect_server.py` (blocks direct target,
  follows redirect). Each is a local HTTP MCP-style server on an ephemeral port.
- **Paired tests** (Constitution VI): vulnerable ⇒ exactly one `SSRF_CHECK` finding (SC-001);
  clean ⇒ zero findings and no callback hit (SC-002); redirect ⇒ finding (SC-003);
  no-URL-tool / unreachable ⇒ INCONCLUSIVE, non-crashing (SC-005); bounded-time even when the
  server never fetches (SC-004); and an assertion that no probe targets any non-local host
  besides the metadata IP attempt (SC-006/FR-012).
