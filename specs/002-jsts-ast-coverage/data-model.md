# Phase 1 Data Model: First-class JavaScript/TypeScript analysis

**Architecture decision (full Clean Architecture)**: introduce one **language-agnostic
`SourceModel` port** with two adapters — `PythonAstAdapter` (stdlib `ast`) and
`TreeSitterAdapter` (JS/TS via tree-sitter). The four checks are (re)written **once** against
the port's domain vocabulary and never see `ast` or `tree_sitter` directly. This file defines
that vocabulary. No new finding types; `Finding`/`Severity` in `core/models.py` are reused.

> The value objects below are the *domain language of static analysis* as the checks need it
> — driven by the four existing checks' actual requirements (call inspection, taint over
> parameters, tool descriptions, string/secret literals). Each adapter maps its native tree
> onto these.

## Enum: `SourceLanguage`

| Value | Extensions | Adapter | Grammar/dialect |
|-------|-----------|---------|-----------------|
| `PYTHON` | `.py` | `PythonAstAdapter` | stdlib `ast` |
| `JAVASCRIPT` | `.js`, `.mjs`, `.cjs`, `.jsx` | `TreeSitterAdapter` | `javascript` (`.jsx`→`tsx`) |
| `TYPESCRIPT` | `.ts`, `.mts`, `.cts` | `TreeSitterAdapter` | `typescript` |
| `TSX` | `.tsx` | `TreeSitterAdapter` | `tsx` |

## Port: `SourceModel`

One parsed file, queried through language-neutral methods. Returned by `analyze(path)`.

| Member | Type | Notes |
|--------|------|-------|
| `path` | `Path` | The file |
| `language` | `SourceLanguage` | Resolved from extension |
| `ok` | `bool` | `False` only when the file could not be parsed at all (e.g. JS/TS but the `jsts` extra is absent). A recoverable/partial tree is still `ok=True`. Never means "clean". |
| `call_sites()` | `list[CallSite]` | Every call expression in the file |
| `functions()` | `list[FunctionDef]` | Every function/method definition |
| `tool_definitions()` | `list[ToolDefinition]` | MCP tool registrations + their description text |
| `string_literals()` | `list[StringLiteral]` | All string/template literals (scopes secret scanning away from comments) |
| `assignments()` | `list[Assignment]` | Name = value bindings (for secret/heuristic checks) |

## Value object: `CallSite`

The unit `CMD_INJECTION` (and the path sink detection) reasons over.

| Field | Type | Notes |
|-------|------|-------|
| `callee` | `str` | Dotted/qualified name: `subprocess.run`, `os.system`, `exec`, `child_process.exec`, `spawn` |
| `args` | `list[Argument]` | Positional arguments |
| `keywords` | `dict[str, Argument]` | Named args (e.g. Python `shell=True`) |
| `line` | `int` | 1-based start line |
| `snippet` | `str` | Evidence slice (Principle V) |

## Value object: `Argument`

A normalized view of one argument, so checks ask *intent* not syntax.

| Field | Type | Meaning (Python ⇄ JS/TS) |
|-------|------|--------------------------|
| `is_array` | `bool` | `list`/`tuple` literal ⇄ array literal (the "safe arg-list" form) |
| `is_constant_string` | `bool` | plain string literal, no interpolation |
| `has_interpolation` | `bool` | f-string/`.format()`/concat ⇄ template literal with `${…}`/concat — the dangerous form |
| `is_truthy_constant` | `bool` | resolves the `shell=True` style flag |
| `referenced_names` | `set[str]` | identifiers used inside the argument (for taint) |
| `text` | `str` | source text of the argument |

## Value object: `FunctionDef`

What `PATH_TRAVERSAL` (param → sink taint) reasons over.

| Field | Type | Notes |
|-------|------|-------|
| `name` | `str` | Function/method name |
| `params` | `list[str]` | Parameter names (for path-like detection) |
| `decorators` | `list[str]` | Dotted decorator names (Python `@mcp.tool`) |
| `body_calls` | `list[CallSite]` | Calls inside this function's body |
| `body_text` | `str` | Source of the body (validation-hint scan, comment-stripped by the check) |
| `line` | `int` | 1-based start line |

## Value object: `ToolDefinition`

What `TOOL_POISONING` reasons over — unifies Python decorator-tools and JS/TS
`server.tool(...)` registrations.

| Field | Type | Notes |
|-------|------|-------|
| `name` | `str` | Tool name |
| `description` | `str` | The text the model sees (Python: docstring; JS/TS: the description argument) |
| `line` | `int` | 1-based start line |

## Value object: `StringLiteral` / `Assignment`

What `HARDCODED_SECRETS` reasons over (AST-scoped, so comments are excluded).

| `StringLiteral` field | Type | Notes |
|-----------------------|------|-------|
| `value` | `str` | The literal's decoded value |
| `line` | `int` | 1-based line |
| `snippet` | `str` | Evidence (the check redacts before output) |

| `Assignment` field | Type | Notes |
|--------------------|------|-------|
| `target_name` | `str` | Assigned identifier (e.g. `API_KEY`) |
| `value` | `StringLiteral \| None` | The literal value, if the RHS is a string literal |
| `value_is_env_lookup` | `bool` | RHS reads `os.environ`/`os.getenv`/`process.env`/dotenv → safe |
| `line` | `int` | 1-based line |

## Reuse: `Finding`

Unchanged. A finding produced from a `SourceModel` query carries the same `check_id` /
`severity` / `owasp_mcp_ref` / `cwe_ref` regardless of language; only `file_path`,
`line_number`, and `snippet` differ per file. Remediation wording may branch on
`model.language` (e.g. `execFile`/`process.env` vs `subprocess`/`os.environ`).

## Check ↔ port mapping (the rewrite target — built AFTER the foundation review)

| Check | Port queries it will use |
|-------|--------------------------|
| `CMD_INJECTION` | `call_sites()` → match callee in danger set → inspect `Argument` (`is_array` safe; `has_interpolation`/`is_truthy_constant` shell flag → finding) |
| `PATH_TRAVERSAL` | `functions()` → path-like `params` → taint via `Argument.referenced_names` over `body_calls` → file sink without validation hint in `body_text` |
| `TOOL_POISONING` | `tool_definitions()` → run poisoning pattern families on `.description` |
| `HARDCODED_SECRETS` | `assignments()` + `string_literals()` → known-key/entropy on literals, `value_is_env_lookup` is safe |
