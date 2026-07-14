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

## Cross-tool comparison — 2026-07-14

Run of the labeled `corpus/` benchmark with two real competitors installed
(`python -m benchmark.run` with them on `PATH`). **Detection** = did the tool
report *any* finding on a vulnerable sample; **clean passed** = did it stay silent
on a clean sample.

| Tool | Version | Vuln detected | Clean passed | Config used |
|---|---|---:|---:|---|
| **McpFrisk** | 0.1.0 | **10 / 10** | **4 / 4** | (built-in) |
| agent-audit | 0.19.2 | 4 / 10 | 3 / 4 | `agent-audit scan <path> --format json` |
| Semgrep | 1.169.0 | 1 / 10 | 4 / 4 | `semgrep scan --config p/python --config p/javascript` |

Per-sample detection (vulnerable samples):

| Sample (planted issue) | McpFrisk | agent-audit | Semgrep |
|---|:---:|:---:|:---:|
| `01` command injection (py) | ✅ | ✅ | ✅ |
| `02` path traversal (py) | ✅ | ✅ | ❌ |
| `03` hardcoded secret (py) | ✅ | ❌ | ❌ |
| `04` tool poisoning (py) | ✅ | ❌ | ❌ |
| `05` tool-name collision (py) | ✅ | ❌ | ❌ |
| `06` risky MCP config | ✅ | ✅ | ❌ |
| `07` schema/description mismatch | ✅ | ❌ | ❌ |
| `08` consent/escalation text | ✅ | ❌ | ❌ |
| `09` dependency typosquat | ✅ | ❌ | ❌ |
| `10` command injection (ts) | ✅ | ✅ | ❌ |

- **False alarm:** agent-audit flagged the clean `22-clean-subprocess-py`
  (allow-listed `subprocess` with an argument list) — 3/4 clean. Semgrep and
  McpFrisk stayed silent on all clean samples.
- **What the competitors miss here:** the MCP-*specific* classes — tool poisoning,
  schema/description mismatch, typosquatting, consent-escalation, tool-name
  collision, and (for Semgrep) hardcoded secrets under the chosen config. That is
  the differentiation, not a claim that these are bad tools.

### Honest reading (important)

- **This corpus is McpFrisk-authored and deliberately emphasizes MCP-specific
  vulnerability classes** — the classes McpFrisk is built for. So this measures
  *coverage of MCP-specific issues*, where McpFrisk is designed to lead. It is
  **not** a claim that McpFrisk is a better general-purpose SAST than Semgrep, nor
  a fully neutral head-to-head.
- **Competitor scores depend on configuration.** Semgrep with a broader ruleset
  (`p/secrets`, `p/security-audit`, …) would catch more of the generic classes;
  agent-audit may have tuning we didn't apply. We used a single reasonable config
  each and counted detections **generously** (any finding, including agent-audit's
  suppressed-tier ones).
- Both competitors are legitimate, mature tools. agent-audit in particular is a
  strong direct peer; the takeaway is McpFrisk's MCP-specific coverage + zero
  false alarms on this corpus, not that the others are weak.
- **Reproduce:** `pip install semgrep agent-audit`, ensure both are on `PATH`,
  then `python -m benchmark.run` (needs network for Semgrep's registry rulesets).
  Semgrep does not run on native Windows without WSL.

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
