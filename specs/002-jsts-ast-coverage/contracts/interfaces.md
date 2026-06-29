# Phase 1 Contracts: First-class JavaScript/TypeScript analysis

**Architecture**: full Clean Architecture. One language-agnostic **`SourceModel` port**
(domain layer) with two **adapters** (infrastructure layer): `PythonAstAdapter` and
`TreeSitterAdapter`. The four checks (use-case layer) depend only on the port and never
import `ast` or `tree_sitter`. The CLI contract is unchanged — `mcpfrisk scan <path>` already
accepts JS/TS paths.

```
checks/*  ──depends-on──▶  core/sourcetree (SourceModel port)  ◀──implemented-by──  ast / tree-sitter
   (use-cases)                       (domain port)                       (infra adapters)
```

## Contract 1: The `SourceModel` port (`core/sourcetree`)

Stable surface every check calls. Checks MUST go through it; they MUST NOT import a parser
directly (keeps both parsers in one place — Principles II/IV).

```python
# core/sourcetree/__init__.py
def analyze(path: Path) -> SourceModel | None:
    """Parse `path` into a language-neutral SourceModel.
    Returns None for unsupported file types.
    Returns a SourceModel with ok=False when the file's language is supported but its
    parser is unavailable (e.g. JS/TS without the `jsts` extra) — never raises, never
    signals 'clean'."""

def jsts_available() -> bool:
    """True if the `jsts` extra (tree-sitter + grammars) is importable. Lets the scan
    flow emit a one-time skip notice and lets CMD_INJECTION choose its regex fallback."""
```

```python
# core/sourcetree/model.py  — the port + value objects (see data-model.md)
class SourceModel(Protocol):
    path: Path
    language: SourceLanguage
    ok: bool
    def call_sites(self) -> list[CallSite]: ...
    def functions(self) -> list[FunctionDef]: ...
    def tool_definitions(self) -> list[ToolDefinition]: ...
    def string_literals(self) -> list[StringLiteral]: ...
    def assignments(self) -> list[Assignment]: ...
```

- **Adapter contract**: each adapter (`python_ast.py`, `treesitter.py`) implements every
  `SourceModel` query for its language, mapping its native tree onto the shared value objects.
  Adding a third language later = a new adapter only; no check and no other adapter changes.
- **Error tolerance**: queries never raise on malformed input. Python: a `SyntaxError` file
  yields `ok=False` (mirrors today's behaviour). JS/TS: tree-sitter recovers, yields `ok=True`
  with whatever parsed.
- **Evidence**: every value object carries a real 1-based `line` and a `snippet` (Principle V).

## Contract 2: Per-check obligations (after the foundation review)

Each check keeps its single `check_id` and is rewritten **once** against the port — no
per-language branches inside the check. Severity stays per the existing rubric.

| Check | Port queries | New coverage |
|-------|--------------|--------------|
| `CMD_INJECTION` | `call_sites()` + `Argument` flags | JS/TS via the same code path (replaces the old line-regex; gains multi-line + comment/string immunity) |
| `PATH_TRAVERSAL` | `functions()` + `body_calls` + `Argument.referenced_names` | JS/TS (**new**) |
| `TOOL_POISONING` | `tool_definitions()` (`.description`) | JS/TS `server.tool(...)` (**new**) |
| `HARDCODED_SECRETS` | `assignments()` + `string_literals()` | AST-scoped (drops comment FPs) across languages |

**Skip / fallback contract** (`jsts_available()` is `False`): the scan prints **one** notice
that JS/TS needs `pip install mcpfrisk[jsts]`; JS/TS files are reported *skipped*, never
clean; `CMD_INJECTION` MAY fall back to its current regex so the base install keeps today's
coverage.

## Contract 3: Exclusions & determinism (unchanged conventions)

- Excluded dirs/files stay the existing set (`node_modules`, `.venv`, `dist`, `build`,
  `__pycache__`, …); minified/vendored bundles are out of scope via these excludes (FR-008).
- Same input → same findings, stable ordering (FR-009): files in sorted order, matches in
  source-position order.

## Contract 4: Packaging

- `pyproject.toml` gains an optional extra:
  `jsts = ["tree-sitter>=0.21", "tree-sitter-typescript", "tree-sitter-javascript"]`
  (`tree-sitter-language-pack` is the fallback grammar source).
- Base/`dev` installs are unaffected; `dev` includes `jsts` so CI exercises the AST path.
- CI runs the JS/TS tests with the extra installed **and** one job without it asserting the
  skip/fallback path (no crash, no false "clean").

## Foundation scope (this iteration, stop-for-review)

Only the **port + both adapters + their tests** are built now (Phase 2 below). The four
checks are **not** touched until the architecture is reviewed — the port is validated in
isolation first, exactly so the later check rewrite is a mechanical mapping, not a redesign.
