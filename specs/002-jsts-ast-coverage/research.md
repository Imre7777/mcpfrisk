# Phase 0 Research: First-class JavaScript/TypeScript analysis

**Date**: 2026-06-29 — fresh research pass per Constitution Principle VII.

## R1. Is the JS/TS MCP threat surface real and the same classes as Python?

**Decision**: Target **the four existing check classes** in JS/TS — `CMD_INJECTION`,
`PATH_TRAVERSAL`, `TOOL_POISONING`, `HARDCODED_SECRETS` — not new JS/TS-only classes.

**Rationale**: Current (2025–2026) CVE data shows the dominant Python MCP weaknesses recur
identically in TypeScript servers:

- **Command injection via `exec`/`execSync`** is the headline JS/TS MCP bug, repeatedly,
  in exactly the `server.tool(...)` registration shape McpFrisk should inspect:
  - `@akoskm/create-mcp-server-stdio` (GHSA-3ch2-jxxc-v4xf): a tool runs
    `` exec(`lsof -t -i tcp:${port}`) `` — untrusted tool arg interpolated into a shell string.
  - `node-code-sandbox-mcp` (GHSA-5w57-2ccq-8w95): `` execSync(`docker rm -f ${container_id}`) ``
    → RCE / sandbox escape.
  - Codehooks MCP server: `` exec(`coho ${command} --admintoken ${token}`) `` — input never
    sanitized.
  - The "43% of analyzed MCP servers contain command-injection flaws" figure (Ultra
    Security, carried in CONTEXT.md) is a Node/TS-inclusive ecosystem number; the safe
    fix everywhere is `execFile`/`spawn` with an argument array.

**Alternatives considered**: Inventing JS/TS-specific checks first (e.g. prototype
pollution) — deferred; parity for the proven, highest-frequency classes delivers more value
and is the documented competitor gap.

## R2. JS/TS parser choice (the central technical decision)

**Decision**: Use **`tree-sitter`** (official Python bindings) with the **JS/TS/TSX
grammars**, added under a new optional dependency extra **`jsts`**. The base install stays
standard-library-only; `pip install mcpfrisk[jsts]` enables semantic JS/TS analysis.

**Rationale**:

- **Error tolerance** — tree-sitter never raises on malformed input; it returns a best-effort
  tree with `ERROR`/`MISSING` nodes and keeps going. That is exactly the behaviour FR-007
  (skip-but-don't-crash on invalid files) wants, and it mirrors how the Python path already
  swallows `SyntaxError`.
- **No transitive library dependencies** — `py-tree-sitter` ships pre-compiled wheels for all
  major platforms with no native build step for the user; the grammar packages
  (`tree-sitter-typescript`, providing both `typescript` and `tsx` dialects, plus
  `tree-sitter-javascript`) likewise ship wheels. This keeps the *opt-in* footprint small and
  auditable — important for a security tool's own supply chain (Principle IV).
- **TS + TSX + flow** — the `tsx` grammar parses TypeScript-with-JSX and JS-with-flow
  annotations, covering the realistic file matrix (FR-004) with one dialect choice per file.
- **Battle-tested** — the same grammars power editor tooling (Neovim, Helix, GitHub code
  navigation), so correctness on real-world TS is well-exercised.
- **Queries** — tree-sitter's S-expression query language lets each check declare *what* it
  looks for (e.g. a `call_expression` whose callee is `exec`) without hand-walking nodes,
  keeping the per-check JS/TS branch small.

**Alternatives considered**:
- **Keep line-regex** (status quo for `CMD_INJECTION`) — rejected: structurally cannot meet
  SC-003 (multi-line constructs) or SC-004 (ignore comments/strings), which is the entire
  reason for the feature.
- **`esprima-python` / pure-Python JS parsers** — rejected: JS-only, no first-class
  TypeScript, and less maintained; TS is the majority case.
- **Shell out to the TypeScript compiler / a Node script** — rejected: forces a full Node
  toolchain on every user, the worst install friction of all options, and couples a Python
  CLI to an external runtime.
- **`tree-sitter-language-pack`** (one wheel bundling many grammars) — viable and may be used
  as the grammar source, but pulling only the JS/TS grammars keeps the extra minimal; treat
  the bundle as a fallback if per-grammar wheels prove fragile on a platform.

## R3. Graceful degradation when the `jsts` extra is absent (Principle III & IV)

**Decision**: The shared analyzer detects whether the parser is importable. If not:
- JS/TS files are **skipped with a single clear notice** ("JS/TS analysis needs
  `pip install mcpfrisk[jsts]`"), never silently treated as clean.
- `CMD_INJECTION` MAY fall back to its current line-regex so the base install does not lose
  the coverage it has today (no regression).

**Rationale**: Keeps the dependency-free base honest (Principle IV) without ever emitting a
false "clean" for unscanned files (Principle III). A skip is informational, never a pass.

**Alternatives considered**: Hard-require the parser → rejected, breaks the zero-dependency
base promise that is itself a market differentiator. Silently ignore JS/TS when the parser is
missing → rejected, that is the false-"clean" failure mode the constitution forbids.

## R4. How each check maps onto the parse tree

**Decision** — per-check JS/TS detection strategy (detail in
[contracts/interfaces.md](./contracts/interfaces.md)):

| Check | JS/TS node target | Flag when … | Safe (no finding) |
|-------|-------------------|-------------|-------------------|
| `CMD_INJECTION` | `call_expression` to `exec`/`execSync`/`child_process.exec*`/`spawn` with a shell | callee is a shell-spawning API **and** an argument is a template literal with substitution or a string concatenation involving a parameter | `execFile`/`spawn` with a string-array of args; fully static string literal |
| `PATH_TRAVERSAL` | function/tool whose param name looks path-like, reaching an `fs.*`/`open`/`path.join` sink | a path-like parameter flows into a filesystem sink with no visible normalization (`path.resolve`+containment, `realpath`) | call uses `path.resolve` + a containment check, or a validated allowlist |
| `TOOL_POISONING` | the description/metadata string of a `server.tool(...)` / `tool(...)` registration | description contains the existing poisoning patterns (instruction tags, imperative directives, sensitive-path refs, cross-tool redirects) | description only describes the tool's function |
| `HARDCODED_SECRETS` | string-literal nodes (to scope regex away from comments) | a known key format / high-entropy secret assigned to a secret-named identifier and not from `process.env` | value read from `process.env` / a secret manager |

**Rationale**: Reuses the *exact* heuristics already calibrated for Python, applied to the
JS/TS tree, so parity means "same idea, JS/TS syntax" (spec Assumptions) and severity stays
consistent (Principle V). The `server.tool(...)` shape comes straight from the R1 CVEs.

**Alternatives considered**: Full inter-procedural taint for JS/TS now — deferred to a
later feature (cross-function taint is its own roadmap item); v1 matches the Python path's
current intra-function depth so parity is true and scoped.

## R5. Test fixtures (Principle VI)

**Decision**: A `tests/fixtures/jsts/` tree with a **vulnerable + clean pair per check**,
expressed in idiomatic TypeScript, plus two **cross-cutting accuracy fixtures**:
- `accuracy_multiline.ts` — a shell call whose interpolated command spans multiple lines
  (must be flagged; line-regex would miss it) → SC-003.
- `accuracy_comment_string.ts` — `exec(...)` appearing only inside a `//` comment and inside
  a normal string literal (must NOT be flagged) → SC-004.

**Rationale**: Directly encodes the two guarantees that distinguish AST analysis from the
old regex, and satisfies the paired-fixture mandate for every newly covered check.

**Alternatives considered**: Reusing Python fixtures transliterated by hand only — kept, but
the two accuracy fixtures are JS/TS-specific because they test parser behaviour the Python
path never needed.
