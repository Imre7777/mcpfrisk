# Quickstart / Validation: SSRF_CHECK

This guide proves the feature works end-to-end. It assumes the feature has been implemented
per [plan.md](./plan.md). For interface details see
[contracts/interfaces.md](./contracts/interfaces.md).

## Prerequisites

```powershell
# From the repo root, in the project venv
uv pip install -e ".[dev]"
```

SSRF_CHECK is **stdlib-only** — the callback listener uses `http.server` and the server talk
uses `urllib`, exactly like AUTH_BOUNDARY. There is **no extra dependency** to install
(Constitution IV holds even for this Tier 2 check).

## Run the automated validation (the source of truth)

```powershell
uv run pytest tests/test_ssrf_check.py -v
```

Expected: all tests green, including (Constitution VI — paired fixtures):

- **True positive**: probing `ssrf_vulnerable_server` yields exactly one `SSRF_CHECK` finding;
  McpFrisk's callback listener recorded a hit with the matching token (SC-001).
- **False-positive guard**: probing `ssrf_clean_server` (denylist + post-resolution IP check)
  yields zero findings and **no** callback hit (SC-002).
- **Redirect bypass**: probing `ssrf_redirect_server` (blocks the direct target but follows a
  redirect to the callback) yields a finding (SC-003).
- **Edge — no URL tool / unreachable**: `INCONCLUSIVE`, never a pass and never a crash (SC-005).
- **Edge — never fetches**: the evaluation completes within the bounded wait (SC-004).
- **Safety**: assert no probe targets any non-local host other than the metadata-IP attempt
  (SC-006 / FR-012).

## Manual run against a real server

```powershell
# A fetch server that does NOT validate URLs → expect a HIGH SSRF_CHECK finding, exit code 1
uv run mcpfrisk probe --server http://localhost:8000/mcp

# A server with a proper SSRF denylist → expect no findings, exit code 0
uv run mcpfrisk probe --server https://my-guarded-server.example/mcp

# Inconclusive (no server reachable / no URL-accepting tool) → informational line, exit code 0
uv run mcpfrisk probe --server http://localhost:9 --timeout 2
```

`SSRF_CHECK` runs alongside `AUTH_BOUNDARY` in the dynamic scan; deselect with
`--skip SSRF_CHECK`.

## What "pass" means here

- A finding on the vulnerable fixture AND silence on the clean fixture — both — is the bar.
  Either one alone is, per the constitution, an unverified check.
- The authoritative signal is an **inbound callback** to McpFrisk's single-use listener, not
  the tool's return value: a server can error to the caller yet still have performed the fetch.
- A no-URL-tool / unreachable / egress-blocked target must surface as `INCONCLUSIVE`, distinct
  from a clean pass — an undeliverable probe is never counted as protection.
