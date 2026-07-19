# Contributing to McpFrisk

Thanks for your interest! McpFrisk is a pre-deploy security scanner for MCP
servers, built with a strict, test-first discipline. This guide keeps
contributions consistent with that.

## Development setup

```bash
git clone https://github.com/Imre7777/mcpfrisk
cd mcpfrisk
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"                            # tests + tree-sitter (JS/TS)

pytest -q                                          # run the suite
ruff check .                                       # lint
```

Optionally install the git hooks so lint + basic hygiene run automatically on
every commit:

```bash
pip install pre-commit && pre-commit install       # runs ruff etc. on commit
```

By participating you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md).

## The non-negotiables (project constitution)

Every change is held to these principles (see [`CONTEXT.md`](./CONTEXT.md) for the
full rationale):

1. **Test-first.** Write the failing test before the code. Fixed bugs become
   regression tests.
2. **Prefer false positives over false negatives.** A missed vulnerability is
   worse than an over-cautious warning — but keep false positives disciplined
   (dual signals, evidence-grounded).
3. **Plugin isolation.** A check is a self-contained class in `mcpfrisk/checks/`
   plus one line in `checks/registry.py`. Checks never import each other; shared
   logic lives in a non-check helper (`_dynamic_helpers.py`, `_name_similarity.py`).
4. **Zero-dependency core.** The base install is Python-stdlib only. Anything
   external (tree-sitter, osv-scanner, npm) is an *optional* extra, and the tool
   must degrade cleanly when it's absent — never crash, never a silent "clean".
5. **Evidence-grounded findings.** A finding names the concrete location/snippet.
   Dynamic checks prove issues (callback hit, liveness recheck), never guess.
6. **Paired fixtures.** Every check ships a *vulnerable* and a *clean* fixture,
   for Python **and** JS/TS where applicable.
7. **Self-redaction.** Reports never print a full secret.

## Adding a check

1. Fresh security research first (cite it in the spec).
2. `specs/NNN-name/{spec,plan,tasks}.md` (GitHub Spec-Kit style).
3. Red tests + paired fixtures.
4. Implement the check; register it in `checks/registry.py`.
5. Green suite, update `README.md` + `CONTEXT.md`, run the benchmark
   (`python -m benchmark.run`) to check for regressions/false positives.

## Pull requests

- Keep one logical change per PR; write a clear description of *why*.
- The CI (lint + tests on Python 3.10–3.12, with and without the `jsts` extra)
  must be green.
- New behavior needs a test. Bug fixes need a regression test.
- Be kind and precise in reviews.

## Reporting security issues

See [`SECURITY.md`](./SECURITY.md) — please report privately, not via public issues.
