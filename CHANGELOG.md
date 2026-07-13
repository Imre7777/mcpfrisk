# Changelog

All notable changes to McpFrisk are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0.0
onward.

## [Unreleased]

### Added
- 12 static (Tier 1) checks: command injection, path traversal, hardcoded
  secrets, tool-description poisoning, tool-name collision, MCP config audit,
  rug-pull drift, schema/description mismatch, dependency typosquatting,
  vulnerable-dependency scan (osv-scanner wrapper), consent/escalation
  manipulation, and npm package signatures.
- 7 dynamic (Tier 2) checks against a running server: auth boundary, SSRF,
  cross-tenant/RBAC leakage, schema fuzzing, error-internals leakage, rate
  limiting, and JSON-RPC protocol compliance.
- Python **and** JS/TS analysis via a language-agnostic `SourceModel` port
  (tree-sitter behind the optional `jsts` extra).
- CI integration: JSON and SARIF output, baseline/diff scanning, a reusable
  GitHub Action, and a `--version` flag.
- A reproducible, labeled **benchmark** (`benchmark/`) with provenance-stamped
  results and external-corpus validation (`benchmark/EXTERNAL.md`).

### Changed
- Tightened Python tool detection so low-level MCP SDK handlers
  (`@server.list_tools()` / `@server.call_tool()`) are no longer mistaken for
  tool definitions (removes a false-positive class found via external
  benchmarking).
- Hardened `find_leak` so URL routes in error responses are no longer flagged as
  internal-path leaks.
- **`PATH_TRAVERSAL` confidence calibration**: a finding whose module defines a
  separate path-validation function that the flagged function doesn't call is now
  emitted at **MEDIUM** (not HIGH) with a triage hint — it is never suppressed and
  still blocks at `--fail-on medium`, but the lower severity honestly reflects the
  higher false-positive likelihood (inter-procedural validation the analysis can't
  see). Prompted by external benchmarking against the official reference servers.
  Proven cross-function taint flows stay HIGH.

_This is the pre-1.0 development history; the first tagged release will start the
formal versioned changelog._
