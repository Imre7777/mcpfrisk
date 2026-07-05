# McpFrisk

> **Security linting for MCP servers — before they ship.**

[![CI](https://github.com/Imre7777/mcpfrisk/actions/workflows/ci.yml/badge.svg)](https://github.com/Imre7777/mcpfrisk/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Core deps](https://img.shields.io/badge/core%20deps-stdlib--only-success)](./pyproject.toml)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP%20Top%2010-informational)](https://owasp.org/www-project-mcp-top-10/)

McpFrisk is a pre-deploy / CI security scanner for **MCP server source code**.
It runs **before** release — unlike tools such as `mcp-scan`, which inspect
*installed* servers on the end user's machine, McpFrisk targets the
**server authors** and catches vulnerabilities before they ship.

- **Static (Tier 1):** AST-based checks for command injection, path traversal,
  hardcoded secrets and tool poisoning — for Python *and* JS/TS.
- **Dynamic (Tier 2):** six checks probe a **running** server — auth boundary,
  SSRF, cross-tenant/RBAC leakage, schema fuzzing (crash/leak under malformed
  input), error-response internals leakage, and rate limiting/resource
  exhaustion — all evidence-grounded, never a guess.
- **Stdlib-only core:** the base install ships no external dependencies —
  small attack surface, trivial installation. JS/TS parsing is an optional extra.
- **Hardened against the servers it's testing:** bounded response sizes, a
  crash in one check never takes down the rest of the scan, and every
  transport failure degrades to *inconclusive* — never a false pass or a
  crashed run, even against a hostile or badly broken target.
- **CI-ready:** one exit code, one optional JSON report — usable directly as a build gate.

> **New to the project?** Start with [`CONTEXT.md`](./CONTEXT.md) — full
> architectural rationale, lessons learned, the security research behind the
> checks, and the [GitHub Spec-Kit](https://github.com/github/spec-kit) setup
> used for further development. Competitive landscape and differentiation:
> [`MARKET-RESEARCH.md`](./MARKET-RESEARCH.md).

## Contents

- [Quickstart](#quickstart)
- [JavaScript/TypeScript support](#javascripttypescript-support-optional-extra)
- [Usage](#usage)
- [Baseline / diff scanning](#baseline--diff-scanning)
- [SARIF output](#sarif-output)
- [GitHub Action](#github-action)
- [Checks (Tier 1, static)](#currently-implemented-checks-tier-1-static)
- [Tier 2 (dynamic)](#tier-2-dynamic-needs-a-running-server)
- [Roadmap (Tier 3)](#roadmap-tier-3-supply-chain--spec-compliance)
- [Design principles](#design-principles)
- [Known limitations](#known-limitations-intentional-not-a-bug)
- [Development](#development)

## Quickstart

```bash
# From the repo root (pyproject.toml lives here)
pip install -e .

mcpfrisk scan ./path/to/server
```

Runnable without installation:

```bash
python3 -m mcpfrisk.cli scan ./path/to/server
```

### JavaScript/TypeScript support (optional extra)

The base install stays dependency-free on purpose (Python standard library only).
For **full, parser-based JS/TS analysis** (same depth as for Python), install
the `jsts` extra:

```bash
pip install -e ".[jsts]"
```

With it, every check analyzes `.js/.mjs/.cjs/.jsx` and `.ts/.mts/.cts/.tsx`
through a real AST (tree-sitter) instead of line-based regex — multi-line safe
and immune to matches inside comments/strings. **Without** the extra, JS/TS
files are skipped cleanly (never falsely reported as "clean"); `CMD_INJECTION`
falls back to a simple regex heuristic.

Architecture note: the parser sits behind a language-agnostic `SourceModel`
port (`core/sourcetree`). Checks query at the domain level
(`call_sites()`, `tool_definitions()`, …) and never see `ast`/`tree-sitter` —
a new language would be a new adapter, not a check rewrite.

## Usage

```bash
# Simple scan, terminal report
mcpfrisk scan ./my-mcp-server

# JSON report for CI artifacts / further processing
mcpfrisk scan ./my-mcp-server --json report.json

# Only fail the build from CRITICAL upwards (instead of the default HIGH)
mcpfrisk scan ./my-mcp-server --fail-on critical

# Disable individual checks
mcpfrisk scan ./my-mcp-server --skip TOOL_POISONING

# SARIF report for the GitHub Security tab (Code Scanning)
mcpfrisk scan ./my-mcp-server --sarif results.sarif

# Baseline / diff scanning: only NEW findings block the build
mcpfrisk scan ./my-mcp-server --write-baseline baseline.json   # accept the current state
mcpfrisk scan ./my-mcp-server --baseline baseline.json          # only new findings fail
```

Exit code `0` = passed, `1` = findings above the `--fail-on` threshold were
found. Usable directly as a GitHub Action / CI gate.

### Baseline / diff scanning

For repos with existing code, re-reporting every historical finding on every
run makes a scanner unusable as a hard CI gate — teams can't triage a
repo's entire backlog on every PR. `--write-baseline PATH` snapshots the
current findings' fingerprints (stable across machines: check ID + path
*relative to the scan target* + line + title — not the exact snippet text,
so cosmetic formatting changes don't invalidate it). Check that file into the
repo; subsequent `--baseline PATH` runs only let genuinely **new** findings
block the build. Known findings never silently disappear — they still print
in the report, just without failing the build. A missing or corrupt baseline
file is treated as empty (no error). Works for both `scan` and `probe`
(`Finding` is the shared type across Tier 1 and Tier 2).

### SARIF output

`--sarif PATH` (scan only — SARIF/GitHub Code Scanning is built around file
+ line in a repo, which Tier-2 dynamic findings don't have) writes a
SARIF 2.1.0 report: one `result` per finding, severity mapped to SARIF's
`level` (CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`),
uploadable via `github/codeql-action/upload-sarif@v3` for inline annotations
in the GitHub Security tab.

### GitHub Action

A reusable composite action ([`action.yml`](./action.yml)) wraps the above —
installs McpFrisk (from the action's own checkout, no PyPI release required
yet), scans, uploads SARIF, and fails the job on blocking findings:

```yaml
- uses: Imre7777/mcpfrisk@main
  with:
    path: .
    fail-on: high
    baseline: baseline.json   # optional
    skip: ''                  # optional, space-separated check IDs
    upload-sarif: true        # optional (default true)
```

The SARIF upload runs even if the scan step fails the build, so a failing
scan never leaves the Security tab empty. Grant the job
`permissions: { security-events: write }` for the upload to work.

> **Private repos:** SARIF upload to Code Scanning requires **GitHub Advanced
> Security** to be enabled. Without it the upload API returns *"Resource not
> accessible by integration"*. Set `upload-sarif: false` — the scan still runs
> and gates the build, and the SARIF file is still produced (exposed via the
> action's `sarif-path` output) for you to archive or handle yourself.

See [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) (`test-action`
job) for the action dogfooding itself against this repo's own fixtures (with
`upload-sarif: false`, since this repo is private without GHAS).

## Currently implemented checks (Tier 1, static)

| Check ID | What is checked | OWASP MCP Top 10 | Share of real-world CVEs |
|---|---|---|---|
| `CMD_INJECTION` | Shell calls with unsanitized input | MCP05 | ~43% |
| `PATH_TRAVERSAL` | File path construction without sandboxing | MCP05 | ~82% of implementations vulnerable |
| `HARDCODED_SECRETS` | API keys/tokens in source code | MCP01 | — |
| `TOOL_POISONING` | Hidden instructions in tool descriptions | MCP04 | 84% success rate under auto-approval |
| `TOOL_NAME_COLLISION` | Duplicate / confusingly-similar tool names (shadowing risk) | MCP03 | — |

`TOOL_NAME_COLLISION` flags two tool registrations sharing an **exact** name
(undefined which one the client resolves — one silently shadows the other →
MEDIUM) or **near-duplicate** names (case/separator/one-char/plural apart →
LOW, an agent-confusion risk). Both cite *both* source locations. Scope is
honest: McpFrisk scans one server, so it catches *intra-repo* collisions —
cross-server shadowing (a different malicious server registering a colliding
name) is out of scope. CWE-706. A check no generic SAST tool performs.

Each check is a self-contained class under `mcpfrisk/checks/`, registered in
`checks/registry.py`. Adding a new check means: a new file plus one entry in
the registry — no existing code is touched.

## Tier 2 (dynamic, needs a running server)

These need a real connection to the MCP server rather than just reading the
source. Run via the `probe` command against a **running** server — either over
HTTP (`--server <url>`) or over **stdio** (`--stdio "<command>"`), the transport
the majority of MCP servers use:

```bash
# HTTP: checks, among other things, that the server rejects unauthenticated requests (401/403)
mcpfrisk probe --server http://localhost:8000/mcp

# stdio: McpFrisk starts the server as a subprocess and speaks newline-delimited JSON-RPC
mcpfrisk probe --stdio "python -m my_server"
mcpfrisk probe --stdio "npx -y @scope/mcp-server" --timeout 5 --fail-on high

# Cross-tenant / RBAC: pass two caller identities (the first two are A/B).
# Prefer env: indirection so credentials never land in argv / shell history.
export TOKEN_A=... TOKEN_B=...
mcpfrisk probe --server http://localhost:8000/mcp \
  --identity "A=env:TOKEN_A" --identity "B=env:TOKEN_B"
```

> ⚠️ **Security note:** `--stdio` **runs the given command** (code execution).
> Only point it at servers you trust or are actively testing. McpFrisk
> automatically negotiates the protocol era (modern stateless `server/discover`
> with a fallback to the legacy `initialize` handshake), speaks pure
> stdlib JSON-RPC (no `mcp` SDK) and terminates the subprocess reliably.

An unreachable / timing-out / non-startable server is reported as
*inconclusive* — neither a pass nor a finding, and never silently treated as
"secure". **AUTH_BOUNDARY** is HTTP-specific by nature (stdio has no
transport-level auth boundary) and reports *inconclusive* over stdio; the
`call()`-based checks such as **SSRF_CHECK** run over both transports.

**Implemented:**

- **AUTH_BOUNDARY** ✅ — sends requests with no / an invalid token and checks
  whether the server really returns 401/403 instead of letting them through
  (stdlib-only, no external dependency).
- **SSRF_CHECK** ✅ — discovers URL-accepting tools and proves *out-of-band*
  whether the server can be coerced into requests against controlled/internal
  targets: McpFrisk starts a single-use loopback callback listener and treats
  an incoming hit as proof (not a heuristic). Covers direct fetches and
  redirect bypass, and probes the cloud metadata endpoint `169.254.169.254`.
  A properly hardened server (denylist + post-DNS IP check) stays finding-free.
  Stdlib-only (CWE-918).
- **RBAC_CROSS_TENANT** ✅ — acts as **two caller identities** (A/B) and proves
  cross-tenant data leakage *by evidence*: it first collects A-private
  fingerprints (content only A sees, not B in its own legitimate view), then
  tries to reach A's data as B — via IDOR replay (fetching a resource id
  discovered under A) and tenant-argument injection (feeding A's tenant/owner
  value into a client-supplied argument). A finding is raised **only** when an
  A-private marker surfaces in B's response. Read-only (never triggers a
  mutating tool); anything ambiguous → *inconclusive*. Identities are supplied
  via `--identity NAME=CREDENTIAL` (repeatable; `env:VAR` indirection
  recommended). Over HTTP the credential becomes a header (default
  `Authorization: Bearer <cred>`, overridable via `--auth-header`); over stdio
  it becomes a per-identity env overlay (`--identity-env`, default
  `MCP_AUTH_TOKEN`). Stdlib-only (CWE-639 / OWASP MCP07).

- **SCHEMA_FUZZING** ✅ — reads a running server's declared tool schemas
  (`tools/list`), derives fuzz payloads per parameter (type mismatch,
  oversized, missing required, format-violating) and sends them to **reading**
  tools only. A finding requires hard evidence: either the server **crashes**
  (a post-payload liveness recheck against `tools/list` fails — proven
  process/connection death, not a guess) or its error response **leaks a
  stacktrace/internal detail** (Traceback/exception-class/absolute-path/SQL
  markers). A structured validation rejection that keeps the server alive is
  finding-free; a timeout/hang where the liveness recheck still succeeds is
  *inconclusive* + a triage note (never its own finding — a hang isn't a
  proven crash). Stops at the first proof (fail-fast, no orphaned stdio
  processes). Read-only; injection-style payloads are out of scope (that's
  `CMD_INJECTION`/`SSRF_CHECK`). CWE-20/248/400/209, OWASP MCP05.
  Stdlib-only. Spec: `007-schema-fuzzing`.

- **ERROR_LEAKAGE** ✅ — sends three "natural", schema-**conformant** error
  triggers (no adversarial payloads) at a running server and inspects the
  responses for leaked internals: an unknown tool name, an unknown top-level
  JSON-RPC method, and (if a reading tool has an id-like required parameter)
  a well-formed but nonexistent resource id. A finding requires a concrete
  leaked traceback/exception-class/absolute-path/SQL-error marker in the
  response (MEDIUM, CWE-209); a generic, structured rejection is finding-free.
  Complements `SCHEMA_FUZZING`: that check probes schema-**violating**
  payloads for crash evidence (leak only a side signal); this check probes
  only schema-valid, everyday inputs and owns no crash proof of its own — to
  avoid overlapping responsibility between the two checks. Read-only;
  stdlib-only. Spec: `008-error-leakage`.

- **RATE_LIMITING** ✅ — measures a baseline latency, then sends a short,
  bounded, fast **sequential** burst (v1: no true multi-thread parallelism —
  stdio's shared per-identity subprocess channel isn't thread-safe for real
  concurrent calls, so this stays transport-blind with no transport change)
  at a reading tool and evaluates only hard signals: an explicit throttle
  hint (429 / recognizable "rate limit" text) anywhere in the burst passes
  immediately; a post-burst liveness-recheck failure proves a crash (HIGH,
  CWE-400); a measured latency degradation past a defined multiple of the
  baseline with no throttle proves unbounded resource consumption (MEDIUM,
  CWE-400/CWE-770). No finding carries an OWASP MCP Top 10 reference — none
  of the ten official categories has any real bearing on resource
  exhaustion/DoS. Read-only; stdlib-only. Spec: `009-rate-limiting`.

**Roadmap fully delivered** — all six originally planned Tier-2 checks
(`AUTH_BOUNDARY`, `SSRF_CHECK`, `RBAC_CROSS_TENANT`, `SCHEMA_FUZZING`,
`ERROR_LEAKAGE`, `RATE_LIMITING`) are implemented. See Tier 3 below for
what's next.

## Roadmap: Tier 3 (supply chain & spec compliance)

- **DEPENDENCY_SCAN** — a wrapper around `osv-scanner`/`pip-audit` rather than
  reinventing the wheel.
- **TYPOSQUAT_CHECK** — Levenshtein distance of the package name against
  known popular MCP servers.
- **PACKAGE_PROVENANCE** — npm provenance / signature check.
- **PROTOCOL_COMPLIANCE** — correct JSON-RPC error codes, preparation for
  the MCP spec RC (July 2026).

## Design principles

1. **Prefer false positives over false negatives.** A missed finding is worse
   than an overly cautious one.
2. **Every check is testable in isolation.** See `tests/fixtures/` for an
   intentionally vulnerable and an intentionally clean example server — both
   serve as regression tests.
3. **Don't reinvent existing good tools.** For dependency scanning there is
   `osv-scanner`/Snyk, for generic secrets `gitleaks`. McpFrisk wraps these
   rather than duplicating them — the value lies in the MCP-*specific* checks
   (tool poisoning, RBAC cross-tenant) that no generic tool knows about.
4. **Reports never show the full secret.** Even our own output is redacted —
   a scanner must not create a new leak.
5. **The scanner defends itself against the server it's testing.** Tier 2
   targets are not yet trusted by definition — a check that raises
   unexpectedly is caught and degraded to *inconclusive* rather than
   crashing the whole scan, and both transports cap response size against a
   hostile/broken server trying to exhaust McpFrisk's own memory.

## Known limitations (intentional, not a bug)

- Static analysis is a heuristic. AST matching cannot trace full data flow
  through arbitrarily complex code. Taint tracking follows intermediate
  assignments (including through nested `if`/`for`/`try` blocks) within a
  single function, and resolves import aliases (`import x as y`,
  `from x import y`) when matching dangerous calls. `PATH_TRAVERSAL`
  additionally follows taint **one function boundary deep**: a path-like
  parameter passed to a same-module helper (positionally or by keyword) that
  then opens it unvalidated is caught — the common thin-wrapper pattern that
  a purely intra-procedural analysis (including `agent-audit`'s) misses. The
  documented limits: only **one** hop (a two-level `F → G → H` chain is not
  followed), only **same-module** helpers (no cross-file/import resolution),
  and named helpers only (an arrow-function-const helper's name isn't
  resolved). If a server validates in a *separate* function the check can't
  see, `PATH_TRAVERSAL` still reports it (principle: prefer FP over FN) but
  attaches a **triage hint** pointing at the existing validation function.
- Severity follows the rubric: a constant argument list with a redundant
  `subprocess.run(..., shell=True)` is a best-practice violation (MEDIUM), not
  a direct RCE path (CRITICAL is reserved for the interpolated command).
- Tool-poisoning detection is pattern-based, not an LLM classifier like
  `mcp-scan`. For higher precision, an optional LLM-judge call would be a
  sensible Tier-2 extension.
- With the `jsts` extra, JS/TS is covered by all code checks (`CMD_INJECTION`,
  `PATH_TRAVERSAL`, `TOOL_POISONING`, `HARDCODED_SECRETS`) via AST. Minified/
  bundled files (`node_modules`, `dist`, `build`) are excluded on purpose.

## Development

```bash
# Dev setup (incl. tests + tree-sitter for JS/TS)
pip install -e ".[dev]"

# Full test suite
pytest -q

# With coverage (as in CI)
pytest --cov=mcpfrisk --cov-report=term-missing
```

CI (see [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)) runs against
Python 3.10/3.11/3.12 and additionally checks, in a dedicated job, the
degradation path **without** the `jsts` extra (the base install must never crash).

### Project layout

```text
mcpfrisk/
├── core/
│   ├── models.py          # Finding, Severity, ScanResult + Tier-2 models
│   ├── base_check.py      # BaseCheck (static) / BaseDynamicCheck (Tier 2)
│   ├── runner.py          # Static orchestration
│   ├── dynamic_runner.py  # Tier-2 orchestration + transport port (HTTP adapter, identities)
│   ├── stdio_transport.py # stdio adapter: subprocess + newline JSON-RPC (per-identity channels)
│   ├── sourcetree/        # SourceModel port + Python / tree-sitter adapters
│   ├── report.py          # Terminal output + JSON export
│   ├── baseline.py        # Fingerprint + baseline load/write/diff (scan + probe)
│   └── sarif.py           # SARIF 2.1.0 export (scan only)
├── checks/
│   ├── registry.py        # STATIC_CHECKS + DYNAMIC_CHECKS  ← new checks here
│   └── *.py               # one check per file (testable in isolation)
└── cli.py                 # argparse entry point (scan + probe)

action.yml                 # reusable composite GitHub Action (see below)
```

A new check is a new file in `checks/` plus an entry in `checks/registry.py` —
existing code is left untouched. Every check needs a vulnerable **and** a clean
fixture under `tests/fixtures/` as a regression test.

## License

[Apache-2.0](./LICENSE) © Imre Obermueller
