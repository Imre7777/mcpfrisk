# Security Policy

McpFrisk is a security tool, so we hold its own security to a high bar. Thank you
for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via one of:

- **GitHub Private Vulnerability Reporting** — the "Report a vulnerability"
  button under the repository's **Security** tab (preferred).
- **Email** — imre.obermueller@gmail.com with subject `mcpfrisk security`.

Please include:

- affected version (`mcpfrisk --version`) and commit,
- a description and, ideally, a minimal reproduction,
- the impact you foresee.

### What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity estimate within 10 business days.
- Coordinated disclosure: we agree on a timeline before any public detail; we
  credit reporters who wish to be credited.

## Scope

In scope — the McpFrisk tool itself:

- code execution, path escape, or memory exhaustion **in McpFrisk** while it
  scans hostile input (a core design goal: McpFrisk must defend itself against
  the untrusted servers it analyzes),
- a scanner output that **leaks a full secret** it was meant to redact,
- a check that reports a hostile target as **safe** in a way that misleads a
  user into shipping a real vulnerability (a false *negative* with security
  impact, not ordinary heuristic limits).

Out of scope:

- ordinary false positives / false negatives inherent to static heuristics
  (McpFrisk favors false positives by design — see the README) — please file
  those as normal issues,
- vulnerabilities in the **scanned** MCP servers (that is McpFrisk's *output*,
  not a McpFrisk vulnerability),
- issues in third-party tools McpFrisk optionally wraps (`osv-scanner`, `npm`) —
  report those upstream.

## Supported versions

McpFrisk is pre-1.0; security fixes land on the latest release / `main`. Once
1.0 ships, this section will pin supported minor versions.

## Handling of secrets

By design, McpFrisk **never prints a full secret** — its own reports redact
detected credentials. If you ever see an unredacted secret in McpFrisk output,
treat it as an in-scope vulnerability and report it privately.
