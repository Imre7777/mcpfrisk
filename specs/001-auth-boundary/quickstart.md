# Quickstart / Validation: AUTH_BOUNDARY

This guide proves the feature works end-to-end. It assumes the feature has been
implemented per [plan.md](./plan.md). For interface details see
[contracts/interfaces.md](./contracts/interfaces.md).

## Prerequisites

```powershell
# From the repo root, in the project venv
uv pip install -e ".[dev,dynamic]"   # 'dynamic' extra pulls in the mcp SDK
```

## Run the automated validation (the source of truth)

```powershell
uv run pytest tests/test_auth_boundary.py -v
```

Expected: all tests green, including (Constitution VI — paired fixtures):

- **True positive**: probing `auth_vulnerable_server` yields an `AUTH_BOUNDARY`
  finding (SC-001).
- **False positive guard**: probing `auth_clean_server` yields zero findings (SC-002).
- **Invalid-credential probe**: a server that accepts a junk token is flagged (SC-005).
- **Edge — unreachable**: probing a dead port returns `INCONCLUSIVE`, never a pass
  and never a crash (SC-004).
- **Edge — timeout**: a non-responding server is abandoned within the bound (SC-003).

## Manual run against a real server

```powershell
# A server that does NOT enforce auth → expect a HIGH AUTH_BOUNDARY finding, exit code 1
uv run mcpfrisk probe --server http://localhost:8000/mcp

# A properly protected server → expect no findings, exit code 0
uv run mcpfrisk probe --server https://my-secured-server.example/mcp

# Inconclusive (no server reachable) → informational line, exit code 0 (not a pass, not a fail)
uv run mcpfrisk probe --server http://localhost:9 --timeout 2
```

## What "pass" means here

- A finding on the vulnerable fixture AND silence on the clean fixture — both — is the
  bar. Either one alone is, per the constitution, an unverified check.
- An unreachable/timeout/stdio target must surface as `INCONCLUSIVE`, distinct from a
  clean pass.
