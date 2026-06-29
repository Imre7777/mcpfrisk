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
- **Dynamic (Tier 2):** probes a **running** server (auth boundary, SSRF) with
  real proof instead of heuristics.
- **Stdlib-only core:** the base install ships no external dependencies —
  small attack surface, trivial installation. JS/TS parsing is an optional extra.
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
```

Exit code `0` = passed, `1` = findings above the `--fail-on` threshold were
found. Usable directly as a GitHub Action / CI gate.

## Currently implemented checks (Tier 1, static)

| Check ID | What is checked | OWASP MCP Top 10 | Share of real-world CVEs |
|---|---|---|---|
| `CMD_INJECTION` | Shell calls with unsanitized input | MCP05 | ~43% |
| `PATH_TRAVERSAL` | File path construction without sandboxing | MCP05 | ~82% of implementations vulnerable |
| `HARDCODED_SECRETS` | API keys/tokens in source code | MCP01 | — |
| `TOOL_POISONING` | Hidden instructions in tool descriptions | MCP04 | 84% success rate under auto-approval |

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

**Planned** (architecture via `BaseDynamicCheck`/`DynamicRunner` already in place):

- **RBAC_CROSS_TENANT** — simulates multiple roles, checks for namespace
  leakage between tools (e.g. student/teacher separation).
- **SCHEMA_FUZZING** — malformed/oversized parameters, checks for crashes
  or stacktrace leaks.
- **ERROR_LEAKAGE** — inspects error responses for paths, stacktraces,
  DB schema information.
- **RATE_LIMITING** — generates parallel load, checks for missing constraints.

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

## Known limitations (intentional, not a bug)

- Static analysis is a heuristic. AST matching cannot trace full data flow
  through arbitrarily complex code (the taint tracking here is deliberately
  simple: one level of intermediate variables, not a full dataflow graph).
  If a server validates in a *separate* function (e.g. `validatePath()`),
  `PATH_TRAVERSAL` still reports it (principle: prefer FP over FN) but attaches
  a **triage hint** pointing at the existing validation function, so a likely
  false positive is quick to classify.
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
│   ├── dynamic_runner.py  # Tier-2 orchestration + transport port (HTTP adapter)
│   ├── stdio_transport.py # stdio adapter: subprocess + newline JSON-RPC
│   ├── sourcetree/        # SourceModel port + Python / tree-sitter adapters
│   └── report.py          # Terminal output + JSON export
├── checks/
│   ├── registry.py        # STATIC_CHECKS + DYNAMIC_CHECKS  ← new checks here
│   └── *.py               # one check per file (testable in isolation)
└── cli.py                 # argparse entry point (scan + probe)
```

A new check is a new file in `checks/` plus an entry in `checks/registry.py` —
existing code is left untouched. Every check needs a vulnerable **and** a clean
fixture under `tests/fixtures/` as a regression test.

## License

[Apache-2.0](./LICENSE) © Imre Obermueller
