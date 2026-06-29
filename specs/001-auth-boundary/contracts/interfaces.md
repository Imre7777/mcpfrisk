# Phase 1 Contracts: AUTH_BOUNDARY

This tool exposes two contracts: the **dynamic check interface** (library) and the
**CLI command** (user-facing). Both must stay stable once shipped.

## Contract 1: Dynamic check interface

`BaseDynamicCheck` (finalize the existing stub in `core/base_check.py`):

```python
class BaseDynamicCheck:
    check_id: str          # UPPER_SNAKE_CASE, e.g. "AUTH_BOUNDARY"
    name: str
    severity: Severity

    def run(self, session: "DynamicSession") -> "BoundaryResult":
        """Exercise the live server via `session` and return a BoundaryResult.
        MUST NOT raise on server misbehavior — a crash/timeout/transport error
        is caught and reported as BoundaryOutcome.INCONCLUSIVE."""
```

- `DynamicSession` is a thin handle the `DynamicRunner` provides, wrapping the target
  (URL/transport) and a bounded-timeout request method. Checks never open their own
  raw connection lifecycle; they ask the session to probe.
- Registration contract: `checks/registry.py` gains `DYNAMIC_CHECKS = [AuthBoundaryCheck]`.
  Adding a dynamic check = new file + one entry here. (Constitution II.)

`DynamicRunner` (new, `core/dynamic_runner.py`), mirrors static `Runner`:

```python
class DynamicRunner:
    def __init__(self, checks: list[BaseDynamicCheck] | None = None,
                 timeout_s: float = 5.0): ...
    def run(self, target: str) -> list[Finding]:
        """Open a session to `target`, run each dynamic check, convert each
        NOT_ENFORCED BoundaryResult into a Finding. ENFORCED/INCONCLUSIVE → no Finding
        (INCONCLUSIVE captured for reporting)."""
```

## Contract 2: CLI

A dynamic run needs a *running server endpoint*, not a source path. Add a sibling
verb to the existing `scan`:

```
mcpfrisk probe --server <url> [--timeout 5] [--fail-on high] [--json report.json] [--skip AUTH_BOUNDARY]
```

| Element | Behavior |
|---------|----------|
| `--server <url>` | Target MCP HTTP endpoint to probe. Required for `probe`. |
| `--timeout <s>` | Per-request bound (default 5s). Guards FR-009 (no hang). |
| `--fail-on <sev>` | Same gate semantics as `scan` (default HIGH). |
| `--json <path>` | Same JSON report format/extension as `scan`. |
| `--skip <ID>` | Same skip mechanism (FR-011); `AUTH_BOUNDARY` is skippable. |

**Exit codes** (unchanged contract): `0` = no findings ≥ threshold; `1` = findings
≥ threshold. **INCONCLUSIVE never sets exit code 1** and never counts as a pass — it
prints an informational line (FR-007, FR-012). If `--server` is omitted/unreachable,
the run ends cleanly as inconclusive (non-crashing), not exit 1.

**Stdio target** (if a future flag points at a stdio server): reported
`INCONCLUSIVE — not applicable (stdio transport has no transport-level auth)`.

## Contract 3: Report output

`report.py` extends to render dynamic results:
- A `NOT_ENFORCED` result prints like other HIGH findings (id, severity, location =
  `<operation> @ <target>`, description, evidence — secret-redacted per Principle/Standards).
- An `INCONCLUSIVE` result prints a distinct informational line, clearly NOT a pass.
- JSON report includes `outcome` and the `probes` array for machine consumption.
