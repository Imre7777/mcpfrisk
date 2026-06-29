# Quickstart / Validation: First-class JavaScript/TypeScript analysis

This guide proves the feature works end-to-end. It assumes implementation per
[plan.md](./plan.md); interface details in [contracts/interfaces.md](./contracts/interfaces.md).

## Prerequisites

```powershell
# From the repo root, in the project venv. The 'jsts' extra pulls in the JS/TS parser.
uv pip install -e ".[dev,jsts]"
```

## Run the automated validation (the source of truth)

```powershell
uv run pytest tests/test_jsts_command_injection.py tests/test_jsts_path_traversal.py `
              tests/test_jsts_tool_poisoning.py tests/test_jsts_accuracy.py -v
```

Expected — all green, including (Constitution VI — paired fixtures per check):

- **Parity true positives** (SC-001): the vulnerable `.ts` fixture for each check yields the
  expected finding (`CMD_INJECTION`, `PATH_TRAVERSAL`, `TOOL_POISONING`, `HARDCODED_SECRETS`).
- **False-positive guards** (SC-002): the clean `.ts` fixture for each check yields zero
  findings of that check (`execFile` arrays, `path.resolve`+containment, descriptive-only
  tool text, `process.env` secrets).
- **Multi-line accuracy** (SC-003): a shell call whose interpolated command spans lines is
  flagged — the pre-feature line-regex missed it.
- **Comment/string accuracy** (SC-004): `exec(...)` appearing only in a `//` comment or a
  string literal is NOT flagged.
- **Mixed tree** (SC-005): scanning a folder with both `.py` and `.ts` returns the union,
  no crash, no cross-language interference.
- **Malformed file** (SC-006): a syntactically broken `.ts` never aborts the scan; the rest
  of the tree still scans.
- **Parser-absent path**: with the `jsts` extra uninstalled, the run prints the
  `pip install mcpfrisk[jsts]` notice, skips JS/TS (never reports it clean), and does not crash.

## Manual run against a real TS server

```powershell
# A TypeScript MCP server that builds a shell command from a tool argument
# (e.g. the exec(`lsof ... ${port}`) pattern) → expect a CMD_INJECTION finding, exit code 1
uv run mcpfrisk scan ./path/to/ts-mcp-server

# A clean TS server (execFile + arg arrays, process.env secrets) → no findings, exit code 0
uv run mcpfrisk scan ./path/to/clean-ts-server

# Single TS file scans too (regression: single-file targets, bug-fixed in 001 era)
uv run mcpfrisk scan ./server.ts
```

## What "pass" means here

- For **every** newly covered check: a finding on its vulnerable JS/TS fixture AND silence on
  its clean JS/TS fixture — both. Either alone is, per the constitution, an unverified check.
- The two accuracy fixtures (multi-line TP, comment/string FP) are what prove this is real
  AST analysis and not regex in disguise.
- With the parser missing, the only acceptable outcomes are skip-with-notice or the
  documented `CMD_INJECTION` regex fallback — never a silent "clean" and never a crash.
