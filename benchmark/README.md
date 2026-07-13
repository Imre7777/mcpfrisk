# McpFrisk Benchmark

A **reproducible, labeled benchmark** that measures McpFrisk's detection rate
(recall) and false-alarm rate (precision) on a corpus of MCP-server samples, and
provides a fair, tool-agnostic way to compare against other scanners.

```bash
python -m benchmark.run        # from the repo root
# writes benchmark/RESULTS.md + benchmark/results.json, prints the report
```

Latest committed results: [`RESULTS.md`](./RESULTS.md).

## What it measures

Two metrics, deliberately kept separate:

1. **McpFrisk per-check precision/recall/F1** — using McpFrisk's own `check_id`
   taxonomy. Each corpus sample carries a ground-truth label of which check(s)
   *should* fire. TP/FP/FN are counted per `(sample, check_id)`.
2. **Cross-tool sample detection** (tool-agnostic) — did a tool flag **any**
   issue on a *vulnerable* sample (detection), and stay **silent** on a *clean*
   sample (no false alarm)? Different tools use different rule IDs, so this
   binary-per-sample view is the only *fair* cross-tool comparison; it needs no
   mapping between rule taxonomies.

## The corpus

`corpus/<NN-name>/` — each sample is a tiny MCP server (or config/manifest) with:
- the source file(s), and
- `expected.json` = the ground truth (`{"description", "expected": [{check_id, min_severity}], "requires_jsts"?}`).

Vulnerable samples plant **one** issue each (`01`–`10`); clean samples (`20`+)
contain realistic-but-safe patterns designed to catch false positives (validated
paths, allow-listed subprocess, env-var secrets, documented parameters, pinned
packages, "permission denied" error text). One sample (`06`) legitimately trips
**two** checks (a plaintext `sk-live-…` token is both a config issue *and* a
hardcoded secret) — the ground truth lists both, on purpose.

## Honesty & limitations (read this)

This benchmark is **authored by the McpFrisk project**, so a high score here
measures **internal consistency and FP-discipline**, *not* independent
third-party validation. Specifically:

- **A mature tool scoring ~100% on its own corpus is expected**, not
  impressive on its own. The value of this harness is threefold: (a) it proves
  the checks stay **silent on realistic clean code** (precision), (b) it is a
  **regression guard** (a check that breaks or a new FP shows up immediately),
  and (c) it is **reproducible and extensible** — anyone can point it at an
  independent corpus or add a competitor adapter and re-run.
- **For independent validation**, run the harness against a public,
  externally-authored corpus such as the appsecco *Vulnerable-MCP-Lab* or
  *MCPTox* (add them under `corpus/` with ground-truth labels). That is the
  credible comparison and is deliberately left as a follow-up rather than
  fabricated here.
- **Competitor columns are only populated if the tool is installed.** Semgrep
  and agent-audit adapters shell out *if present*; otherwise the report shows
  "not installed (skipped)" — never invented numbers. To compare, install them
  (`pip install semgrep agent-audit`) and re-run.
- **Static checks only.** McpFrisk's 7 dynamic (Tier-2) checks need a *running*
  server and are out of scope for this file-based harness; a dynamic benchmark
  (spinning up vulnerable/clean fixture servers) is a possible extension.
- **JS/TS samples require the `jsts` extra.** Without it they are skipped for
  McpFrisk (and the report says so).

## Adding a competitor

Implement a `Scanner` in `scanners.py` (`available()` + `scan(dir) -> ScanOutput`
whose `findings` is any non-empty list when the tool reports an issue) and add it
to `ALL_SCANNERS`. The cross-tool table picks it up automatically.

## Files

```text
benchmark/
├── corpus/            # labeled samples (source + expected.json)
├── metrics.py         # precision/recall/F1 (pure, unit-tested)
├── scanners.py        # Scanner adapters: McpFrisk + Semgrep + agent-audit
├── run.py             # orchestrator -> RESULTS.md + results.json
├── RESULTS.md         # generated report (committed)
└── results.json       # generated machine-readable results (committed)
```
