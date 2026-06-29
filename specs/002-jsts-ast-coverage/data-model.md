# Phase 1 Data Model: First-class JavaScript/TypeScript analysis

This feature adds **no new finding types** and changes no existing model in
`mcpfrisk/core/models.py`. The new types are analysis-layer helpers in
`mcpfrisk/core/sourcetree/`. `Finding` and `Severity` are reused unchanged.

## Enum: `SourceLanguage`

Identifies which adapter parses a file. Derived from the file extension.

| Value | Extensions |
|-------|-----------|
| `PYTHON` | `.py` |
| `JAVASCRIPT` | `.js`, `.mjs`, `.cjs`, `.jsx` |
| `TYPESCRIPT` | `.ts`, `.mts`, `.cts` |
| `TSX` | `.tsx` |

> JS/JSX → the `javascript`/`tsx` grammar; TS → the `typescript` grammar; TSX → the `tsx`
> grammar. Flow-annotated `.js` is parsed with `tsx` (see research R2).

## Entity: `ParsedSource`

The result of analyzing one file — the JS/TS counterpart to a Python `ast.Module`.

| Field | Type | Notes |
|-------|------|-------|
| `path` | `Path` | The scanned file |
| `language` | `SourceLanguage` | Resolved from extension |
| `text` | `bytes` | Raw source (parser works on bytes; needed for snippet extraction) |
| `tree` | parser tree handle | The error-tolerant syntax tree (opaque to checks) |
| `ok` | `bool` | `False` if the parser/extra was unavailable; `True` even for partially-broken input (tree-sitter recovers) |

**Rule**: A file that cannot be parsed at all (parser/extra missing) yields
`ParsedSource(ok=False, ...)`; checks treat it as "not analyzable" and skip it — never as
clean (Principle III). A file with `ERROR` nodes but a usable tree is still `ok=True`; checks
inspect what parsed.

## Entity: `NodeMatch`

A single hit a check cares about, with the evidence needed for a `Finding`.

| Field | Type | Notes |
|-------|------|-------|
| `line` | `int` | 1-based start line of the node (for `Finding.line_number`) |
| `snippet` | `str` | The source slice for the node, trimmed/redacted as the check requires |
| `text` | `str` | The decoded node text (e.g. the callee name, the description string) |
| `kind` | `str` | Which query matched (e.g. `shell_call`, `tool_description`) — lets a check pick the right message/severity |

**Rule**: `line`/`snippet` come directly from real parser node positions (Principle V —
evidence-grounded). `snippet` for `HARDCODED_SECRETS` is redacted by the existing
`_redact` logic before it leaves the check.

## Entity: `LanguageAdapter` (capability, not data)

The behaviour each language provides to the analyzer. Python is served by the stdlib `ast`
(existing code path); JS/TS by the tree-sitter adapter. Conceptually:

| Capability | Python (`ast`) | JS/TS (tree-sitter) |
|-----------|----------------|---------------------|
| parse file → tree | `ast.parse` (raises → skip) | `Parser.parse` (error-tolerant) |
| find calls by callee name | walk `ast.Call` | query `call_expression` |
| string / template literals | `ast.Constant`/`JoinedStr` | `string` / `template_string` nodes |
| comments excluded from matches | comments aren't in the AST | comment nodes are distinct → skip them |
| tool definitions | `@mcp.tool` decorated `FunctionDef` | `server.tool(name, …)` / `tool(…)` call args |
| node → (line, snippet) | `node.lineno` + source slice | node start point + byte slice |

## Reuse: `Finding`

Unchanged. JS/TS findings differ only in which file/construct they point at:

| Field | Value for a JS/TS finding |
|-------|---------------------------|
| `check_id` | the same id as the Python path (`CMD_INJECTION`, `PATH_TRAVERSAL`, `TOOL_POISONING`, `HARDCODED_SECRETS`) |
| `severity` | per the existing rubric (e.g. `exec` + template-literal interpolation → `HIGH`/`CRITICAL` as today) |
| `file_path` / `line_number` / `snippet` | from the matched `NodeMatch` |
| `owasp_mcp_ref` / `cwe_ref` / `remediation` / `references` | same as the Python branch of that check, with JS/TS-appropriate remediation wording (`execFile`/`spawn` array, `process.env`, …) |

## Check ↔ language coverage (goal state)

| Check | Python | JS/TS (this feature) |
|-------|--------|----------------------|
| `CMD_INJECTION` | AST (already) | AST (upgrades the old line-regex) |
| `PATH_TRAVERSAL` | AST (already) | AST (**new**) |
| `TOOL_POISONING` | AST (already) | AST (**new**) |
| `HARDCODED_SECRETS` | regex (already cross-language) | regex + AST string-literal scoping (FP reduction) |
