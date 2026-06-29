<!--
SYNC IMPACT REPORT
==================
Version change: (template / unversioned) → 1.0.0
Rationale: Initial ratification of the McpFrisk constitution. MAJOR baseline.

Principles defined (7):
  I.   Strict Test-First Development (NON-NEGOTIABLE)
  II.  Plugin Isolation (Library-First)
  III. False Positives Over False Negatives
  IV.  Zero Unnecessary Dependencies (Tier 1)
  V.   Evidence-Grounded Findings
  VI.  Paired Fixture Testing (NON-NEGOTIABLE)
  VII. Security-Research Currency

Added sections:
  - Core Principles (I–VII)
  - Security & Output Standards
  - Development Workflow & Quality Gates
  - Governance

Removed sections: none (initial version)

Templates requiring updates:
  ✅ .specify/templates/plan-template.md      (Constitution Check gates filled in)
  ✅ .specify/templates/tasks-template.md     (test mandate aligned with Principle I & VI)
  ✅ .specify/templates/spec-template.md       (reviewed — generic, no change needed)
  ✅ .specify/templates/constitution-template.md (source template — unchanged by design)

Follow-up TODOs: none. RATIFICATION_DATE set to first adoption (2026-06-29).
-->

# McpFrisk Constitution

McpFrisk is a CLI security scanner for MCP (Model Context Protocol) server source
code that runs pre-deploy / in CI — not against running servers. These principles
are binding for all contributors and AI agents working on this project.

## Core Principles

### I. Strict Test-First Development (NON-NEGOTIABLE)

For every new check or feature, tests MUST be written first, reviewed and approved
by the maintainer, and confirmed to FAIL (red) before any implementation code is
written. The Red-Green-Refactor cycle is mandatory and applies without exception —
including for "obvious" fixes and small changes.

**Rationale**: This is a security tool. A silent "it looks fine" is far more
expensive here than elsewhere, because the cost is a missed vulnerability shipping
to production. Writing the failing test first proves the test actually exercises the
behavior and prevents implementation-shaped tests that pass vacuously.

### II. Plugin Isolation (Library-First)

Every security check MUST be a fully self-contained, independently testable unit (a
class implementing `BaseCheck`) with zero dependencies on other checks. Adding a new
check MUST require only a new file plus a single registry entry in
`mcpfrisk/checks/registry.py` — it MUST NOT require modifying any existing check
file. This isolation MUST hold even as the project grows past 15+ checks.

**Rationale**: The roadmap targets a large, growing catalogue of checks. Open/Closed
isolation keeps each check reviewable in isolation, prevents one check's regression
from affecting others, and keeps the blast radius of any change minimal.

### III. False Positives Over False Negatives

When a detection heuristic is ambiguous, the check MUST flag the finding rather than
stay silent. Every finding MUST carry a description clear enough that a human can
judge for themselves whether it is a false positive.

**Rationale**: A missed real finding is worse than an over-cautious alert. The human
reviewer can dismiss noise cheaply; they cannot recover a vulnerability the scanner
never surfaced.

### IV. Zero Unnecessary Dependencies (Tier 1)

Tier 1 (static) checks MUST work using only the Python standard library (`ast`, `re`,
`pathlib`) wherever feasible. A dependency MUST NOT be added to solve a problem the
standard library already solves. Tier 2 (dynamic) checks that require a real MCP
client/server connection are exempt only where the `mcp` SDK (or equivalent) is
genuinely required.

**Rationale**: A security tool's own dependency tree is its own attack surface.
Minimal dependencies keep installation trivial, auditing realistic, and supply-chain
risk low — credibility a security scanner cannot afford to undermine.

### V. Evidence-Grounded Findings

No check may emit a finding based on guesswork. Every finding MUST cite the offending
file, the line number, and a code snippet. Severity MUST follow the established
rubric: CRITICAL = direct exploit path with no further conditions (e.g. RCE, secret
leak); HIGH = exploit plausible under realistic conditions; MEDIUM = best-practice
violation without an immediate exploit path.

**Rationale**: Findings without evidence cannot be triaged or trusted, and erode the
tool's authority. Concrete file/line/snippet evidence makes every finding actionable
and verifiable.

### VI. Paired Fixture Testing (NON-NEGOTIABLE)

No security-relevant detection logic ships without BOTH a paired vulnerable-fixture
test AND a paired clean-fixture test. A check that has only been tested against
vulnerable code is considered unverified, regardless of how obviously correct the
logic appears.

**Rationale**: Three real bugs during initial development (comment-as-validation,
over-aggressive directory excludes, incomplete secret regex) would all have been
missed by vulnerable-only testing. The clean fixture is what catches false positives;
without it, Principle III turns the tool into noise.

### VII. Security-Research Currency

Before implementing a new check class (e.g. SSRF, auth boundary, RBAC), a fresh
research pass against current CVE data and the OWASP MCP Top 10 categories is
REQUIRED. Training-data and prior-research knowledge about the MCP threat landscape
MUST be treated as stale by default.

**Rationale**: The MCP ecosystem and its threat landscape change fast. A check built
on outdated threat assumptions provides false confidence — the most dangerous failure
mode for a security tool.

## Security & Output Standards

- **Self-redaction**: Reports MUST NEVER print a full secret value, including the
  tool's own output. A scanner must not create a new leak.
- **Severity rubric**: All severity assignments MUST follow the CRITICAL / HIGH /
  MEDIUM / LOW / INFO scale defined in `mcpfrisk/core/models.py` and the rubric in
  Principle V. New findings calibrate against existing checks.
- **CI contract**: Exit code `0` = passed; exit code `1` = findings at or above the
  `--fail-on` threshold (default: HIGH). This contract MUST remain stable so the tool
  is safe to wire as a CI gate.
- **Conservative excludes**: Directory/file exclusions MUST be limited to genuine
  build/dependency directories (`node_modules`, `.venv`, `__pycache__`). Excludes
  MUST NOT silently swallow user source code (Lesson Learned: never exclude paths
  merely because they contain "test").

## Development Workflow & Quality Gates

- **Adding a check**: (1) new file in `mcpfrisk/checks/` with a class extending
  `BaseCheck`; (2) assign a `check_id` in UPPER_SNAKE_CASE; (3) implement
  `run(target_path) -> list[Finding]`; (4) register in `checks/registry.py`; (5) add
  vulnerable + clean fixtures; (6) add true-positive AND false-positive tests.
- **Test gate**: The full `pytest` suite MUST be green before any commit that
  changes detection logic. CI runs the suite across Python 3.10–3.12.
- **Regression protection**: The three documented historical bugs (see `CONTEXT.md`
  §4) are encoded as regression tests and MUST NOT be reintroduced.
- **Spec-driven flow**: Material new work proceeds through the Spec Kit workflow —
  `/speckit-specify` (what/why) → `/speckit-plan` (how) → `/speckit-tasks` →
  `/speckit-implement`. The plan's Constitution Check gate MUST pass before
  implementation.

## Governance

This constitution supersedes ad-hoc development practices for McpFrisk. All changes,
reviews, and AI-agent actions MUST verify compliance with these principles; any
deviation MUST be justified in writing (e.g. the plan's Complexity Tracking table)
or the change MUST be revised.

Amendments require: (1) a documented rationale, (2) a version bump per the policy
below, and (3) propagation to dependent templates (`plan-template.md`,
`tasks-template.md`, `spec-template.md`) in the same change.

Versioning policy (semantic):
- **MAJOR**: backward-incompatible governance/principle removals or redefinitions.
- **MINOR**: a new principle/section is added or guidance is materially expanded.
- **PATCH**: clarifications, wording, and non-semantic refinements.

Compliance is reviewed at every spec/plan gate and at code review. `CONTEXT.md` is
the authoritative runtime guidance document for project background and rationale.

**Version**: 1.0.0 | **Ratified**: 2026-06-29 | **Last Amended**: 2026-06-29
