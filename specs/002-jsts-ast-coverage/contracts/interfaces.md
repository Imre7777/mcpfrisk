# Phase 1 Contracts: First-class JavaScript/TypeScript analysis

Two contracts: the **shared source-analysis API** (library, consumed by checks) and the
**per-check JS/TS behaviour** (what each check must now do). The CLI contract is unchanged —
`mcpfrisk scan <path>` already accepts JS/TS paths; this feature only changes what is found.

## Contract 1: Shared source-tree analysis (`core/sourcetree`)

Stable surface the checks call. Checks MUST go through this; they MUST NOT import
`tree_sitter` directly (keeps the parser dependency in one place, Principle II/IV).

```python
# core/sourcetree/__init__.py
def analyze(path: Path) -> ParsedSource | None:
    """Parse a JS/TS file into a ParsedSource.
    Returns None for non-JS/TS files (caller handles those via the Python path).
    Returns ParsedSource(ok=False) when the `jsts` extra/parser is unavailable —
    never raises, never returns a 'clean' signal for an unparsed file."""

def jsts_available() -> bool:
    """True if the `jsts` extra (tree-sitter + grammars) is importable.
    Lets a check decide between its AST branch and a regex fallback / skip-notice."""
```

```python
# core/sourcetree/analyzer.py — query helpers used by checks
class ParsedSource:
    path: Path
    language: SourceLanguage
    text: bytes
    ok: bool

    def calls_to(self, callee_names: set[str]) -> list[NodeMatch]:
        """All call expressions whose callee resolves to one of `callee_names`
        (handles `exec`, `child_process.exec`, `cp.exec` aliases pragmatically)."""

    def string_arguments(self, match: NodeMatch) -> list[NodeMatch]:
        """The string/template-literal arguments of a matched call, flagging which
        contain substitution/concatenation (the dangerous form)."""

    def tool_descriptions(self) -> list[NodeMatch]:
        """Description/metadata strings of `server.tool(...)` / `tool(...)` registrations."""

    def functions_with_params(self, name_hints: tuple[str, ...]) -> list[NodeMatch]:
        """Functions/tool callbacks that declare a parameter whose name matches a hint
        (e.g. path-like names), for the taint-style reachability check."""

    def string_literals(self) -> list[NodeMatch]:
        """All string/template literals (used to scope secret-scanning away from comments)."""
```

- **Error handling contract**: every method returns matches from the best-effort tree and
  never raises on malformed input. A file the parser can't load at all surfaces as
  `ParsedSource(ok=False)`.
- **Evidence contract**: every `NodeMatch` carries a real 1-based `line` and a source
  `snippet` (Principle V).

## Contract 2: Per-check JS/TS behaviour

Each check keeps its single `check_id` and gains a JS/TS branch that delegates to Contract 1.
`applies_to` is widened where needed so the check actually runs on JS/TS-only trees.

| Check | New JS/TS obligation | Severity (must match Python rubric) |
|-------|----------------------|-------------------------------------|
| `CMD_INJECTION` | Flag `exec`/`execSync`/`child_process.exec`/`spawn(.../sh)` whose argument is a template literal with substitution or a concatenation of a parameter. **Replaces** the line-regex; gains multi-line detection (SC-003) and comment/string immunity (SC-004). | `HIGH` (template-literal interpolation); `CRITICAL` reserved as in Python |
| `PATH_TRAVERSAL` | Flag a path-like tool/function parameter reaching `fs.*` / `open` / `path.join` with no visible `path.resolve`+containment / `realpath`. **New** for JS/TS. | `HIGH` |
| `TOOL_POISONING` | Run the existing poisoning pattern families against `server.tool(...)` description/metadata strings. **New** for JS/TS. | `CRITICAL`/`HIGH` per pattern, as in Python |
| `HARDCODED_SECRETS` | Keep regex, but only consider matches inside string-literal nodes (drops comment FPs); `process.env`/dotenv reads stay safe. | `CRITICAL`/`HIGH` as today |

**Skip / fallback contract** (when `jsts_available()` is `False`):
- The scan prints **one** notice that JS/TS analysis needs `pip install mcpfrisk[jsts]`.
- JS/TS files are not reported as clean — they are reported as skipped.
- `CMD_INJECTION` MAY use its existing line-regex so the base install keeps today's coverage
  (no regression). Other checks skip JS/TS in that mode.

## Contract 3: Exclusions & determinism (unchanged conventions)

- Excluded dirs/files stay the existing set (`node_modules`, `.venv`, `dist`, `build`,
  `__pycache__`, …). Minified/vendored bundles are out of scope via these excludes (FR-008).
- Same input → same findings, stable ordering (FR-009): iterate files in sorted order and
  emit matches in source position order.

## Contract 4: Packaging

- `pyproject.toml` gains an optional extra:
  `jsts = ["tree-sitter>=0.21", "tree-sitter-typescript", "tree-sitter-javascript"]`
  (exact grammar packaging finalized in tasks; `tree-sitter-language-pack` is the fallback).
- Base/`dev` installs are unaffected; `dev` includes `jsts` so CI exercises the AST path.
- CI runs the JS/TS tests with the `jsts` extra installed, and runs at least one job
  asserting the **parser-absent** skip/fallback path (no crash, no false "clean").
