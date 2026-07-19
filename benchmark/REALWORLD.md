# Real-World-Korpus -- Finding-Rauschen auf echten MCP-Servern

> Reproduzierbar via `python -m benchmark.realworld_corpus`. Jeder Server
> ist auf einen Commit-SHA gepinnt. Gescannt wird der ausgelieferte
> Servercode; ausgeschlossen: `tests, test, __tests__, e2e, examples, example, docs, docs_src, sample, samples, fixtures`.

**Abgrenzung (ehrlich):** Dies misst *Präzision/Rauschen auf echtem Code*,
NICHT gelabelten Recall -- die wahren Schwachstellen dieser Repos sind nicht
annotiert. Der gelabelte Recall/Precision-Test steht in `RESULTS.md`.

## Provenance
- generated_at: `2026-07-19T12:01:25.299690+00:00`
- mcpfrisk: `67ec43f` (version `0.1.0`)
- working tree clean (relevant): `True`
- python `3.13.3` -- Windows-11-10.0.26200-SP0

## Ergebnisse pro Server

| Server | Lang | Commit | Status | Findings gesamt | Top-Checks |
|---|---|---|---|---:|---|
| context7 | ts | `23843e9ce6` | ok | 13 | PATH_TRAVERSAL:8, MCP_CONFIG_AUDIT:5 |
| mcp-atlassian | py | `b60c564ce4` | ok | 5 | TOOL_NAME_COLLISION:3, PATH_TRAVERSAL:2 |
| firecrawl-mcp | ts | `3eb1115b1f` | ok | 0 | - |
| tavily-mcp | ts | `259bfd205d` | ok | 0 | - |
| qdrant-mcp | py | `f1a4d04e4f` | ok | 0 | - |
| chroma-mcp | py | `98ff67589b` | ok | 0 | - |
| playwright-mcp | ts | `55679f5f3d` | ok | 0 | - |
| mcp-playwright | ts | `2349c2891e` | ok | 1 | MCP_CONFIG_AUDIT:1 |
| figma-mcp | ts | `c083d65c7e` | ok | 3 | PATH_TRAVERSAL:2, CMD_INJECTION:1 |
| elastic-mcp | ts | `9e64b842f2` | ok | 0 | - |
| llamacloud-mcp | py | `ebc66ba1c0` | ok | 2 | MCP_CONFIG_AUDIT:2 |
| python-sdk | py | `3a6f2996cd` | ok | 2 | CMD_INJECTION:2 |
| typescript-sdk | ts | `f60dff0674` | ok | 16 | PATH_TRAVERSAL:15, CMD_INJECTION:1 |
| servers | mixed | `d31124c982` | ok | 9 | PATH_TRAVERSAL:8, MCP_CONFIG_AUDIT:1 |

## Aggregat über 14 erfolgreich gescannte Server

| Check | Findings |
|---|---:|
| PATH_TRAVERSAL | 35 |
| MCP_CONFIG_AUDIT | 9 |
| CMD_INJECTION | 4 |
| TOOL_NAME_COLLISION | 3 |
