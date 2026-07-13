# External Validation

The [`corpus/`](./corpus) benchmark is McpFrisk-authored, so it proves FP-discipline
and guards against regressions — but not independent validation. This file records
runs against **externally-authored** corpora: a real vulnerable MCP server (recall)
and legitimate production MCP servers (precision in the wild). External repos are
**not vendored** into this repo; instead their exact commits are pinned here so any
run is reproducible.

## How to reproduce

```bash
# Recall: an externally-authored deliberately-vulnerable MCP server
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server dvmcp
git -C dvmcp checkout 79734c1
mcpfrisk scan dvmcp --json dvmcp.json

# Precision in the wild: the official reference servers
git clone https://github.com/modelcontextprotocol/servers official
git -C official checkout d31124c
mcpfrisk scan official --json official.json
```

> McpFrisk only ever reads these files statically — it never installs or runs the
> cloned servers. Scanning untrusted source is exactly its job and is safe.

## Run: 2026-07-13

| Corpus | Pinned commit | Files (py/ts) |
|---|---|---|
| `damn-vulnerable-MCP-server` | `79734c1` | 31 |
| `modelcontextprotocol/servers` | `d31124c` | 79 |

### Recall — DVMCP (externally-authored vulnerabilities)

McpFrisk lit up the deliberately-vulnerable server with **32 findings**:

| Severity | Count | Checks |
|---|---:|---|
| CRITICAL | 15 | `CMD_INJECTION` ×8, `HARDCODED_SECRETS` ×5, `TOOL_POISONING` ×2 |
| HIGH | 11 | `PATH_TRAVERSAL` |
| MEDIUM | 5 | `TOOL_NAME_COLLISION` |
| LOW | 1 | `TOOL_NAME_COLLISION` |

Independent evidence that the core checks catch real, externally-planted
vulnerabilities (command injection, hardcoded secrets, tool poisoning, path
traversal) — not just McpFrisk's own fixtures.

### Precision in the wild — official reference servers

The credibility test that matters most for release: does McpFrisk stay quiet on
real, legitimate code? On 79 source files it produced **9 findings** (0 critical):

| Finding | Verdict |
|---|---|
| 7× `PATH_TRAVERSAL` (HIGH) in `src/filesystem/lib.ts` | **False positives** — internal IO helpers that receive already-validated paths; the server validates via `validatePath()` at the handler boundary (inter-procedural, which McpFrisk deliberately does not follow). All carry McpFrisk's **triage hint** naming the module's validation function. See "Open item" below. |
| 1× `PATH_TRAVERSAL` (HIGH) in `src/everything/resources/files.ts` | Borderline — a `readFileSafe(path)` helper in a demo server with no local validation; a reviewer would dismiss it. |
| 1× `MCP_CONFIG_AUDIT` (LOW) in `.mcp.json` | Defensible LOW — a remote server URL configured without an auth header (a public docs endpoint; low risk, correctly LOW). |

### A precision bug this run found (fixed)

An earlier run reported **11** findings, including 2× `TOOL_NAME_COLLISION` on the
`fetch` server's `list_tools` / `call_tool` functions. Those are low-level MCP SDK
request handlers (`@server.list_tools()`, `@server.call_tool()`), **not** tool
definitions — the Python tool detector matched the substring "tool". Fixed so the
decorator callee must be `tool` or end in `.tool` (commit that added
`test_list_call_tool_handlers_do_not_collide`), consistent with the JS adapter.
This removed the 2 false positives across the whole tool-check family
(collision / poisoning / schema-mismatch / drift).

## Resolved — filesystem PATH_TRAVERSAL confidence calibration

The 7 `filesystem/lib.ts` findings are the known limit of intra-procedural (+
one-hop) taint analysis: the helpers assume pre-validated paths. **Decision
(2026-07):** a triage-hinted finding — where the module defines a separate
path-validation function that the flagged function doesn't call — is now emitted at
**MEDIUM** instead of HIGH. Rationale: a high HIGH-severity false-positive rate on
known-good code erodes user trust (and so the tool's mission); MEDIUM **suppresses
nothing** (the finding still prints, still blocks at `--fail-on medium`, still
carries the triage hint) — it just honestly signals lower confidence, the way
mature scanners (Semgrep "confidence", CodeQL "precision") do. Proven cross-function
taint flows stay HIGH. After this change the official-server run reports **1 HIGH +
7 MEDIUM** path-traversal findings instead of 8 HIGH — the same detections, honestly
ranked. See `CHANGELOG.md` and `test_finding_precision.py`.
