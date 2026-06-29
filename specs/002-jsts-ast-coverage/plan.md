# Implementation Plan: First-class JavaScript/TypeScript analysis

**Branch**: `002-jsts-ast-coverage` | **Date**: 2026-06-29 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/002-jsts-ast-coverage/spec.md`

## Summary

Bring JS/TS scanning to parity with Python by introducing one shared, parser-backed
**source-tree analysis layer** that the existing static checks consume — the JS/TS
counterpart to Python's stdlib `ast`. Today only `CMD_INJECTION` looks at JS/TS (and only
via line-regex), `PATH_TRAVERSAL` and `TOOL_POISONING` skip JS/TS entirely, and
`HARDCODED_SECRETS` is already language-agnostic regex. The plan adds an error-tolerant
JS/TS parser (`tree-sitter` + the JS/TS grammars) behind a new **opt-in `jsts` extra**, so
the base install stays dependency-free and degrades gracefully when the extra is absent.
Each of the four checks gains a thin JS/TS branch that delegates to the shared analyzer; no
check depends on another, preserving plugin isolation.

## Technical Context

**Language/Version**: Python 3.10+ (existing project floor).

**Primary Dependencies**: NEW optional extra `jsts` → `tree-sitter` (Python bindings, ships
pre-compiled wheels, no transitive library deps) plus the JS/TS/TSX grammar package(s).
The **base / Tier-1 install stays standard-library-only** (Python scanning unaffected). This
is a deliberate, justified Tier-1 dependency (see Constitution Check IV + Complexity
Tracking): the stdlib has no JS/TS parser, and the alternatives are worse. Mirrors the
established `dynamic` extra pattern from feature 001.

**Storage**: N/A (no persistence).

**Testing**: `pytest`. Per Principle VI, **every** check that gains JS/TS support ships with
BOTH a vulnerable and a clean JS/TS fixture, plus two cross-cutting regression fixtures
(multi-line construct = true positive; comment/string look-alike = no finding).

**Target Platform**: cross-platform CLI / CI (Windows, Linux, macOS).

**Project Type**: single-project Python CLI / library (existing layout under `mcpfrisk/`).

**Performance Goals**: one parse per file, linear in file size; JS/TS scan time is in the
same order as the existing Python AST path. A single pathological file is bounded and never
hangs the scan (FR edge case).

**Constraints**: MUST NOT regress the Python path or the base dependency-free install. When
the `jsts` extra is not installed, JS/TS files are skipped with a clear one-time notice
(and `CMD_INJECTION` may fall back to its existing regex), never a crash and never a silent
"clean". Findings reuse the existing `Finding`/`Severity` model and exclusion conventions.

**Scale/Scope**: One new shared analysis module + per-language adapter, and a JS/TS branch
in each of the four existing static checks. No new check ids, no new severities, no CLI
surface change (`scan` already accepts JS/TS paths).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Verify the plan against the McpFrisk Constitution (`.specify/memory/constitution.md`):

- [x] **I. Test-First (NON-NEGOTIABLE)**: Tasks add the failing JS/TS fixtures + paired
      tests for each check first, maintainer approves, RED confirmed, before any analyzer or
      check code is written.
- [x] **II. Plugin Isolation**: Checks remain mutually independent — no check imports or
      depends on another. The JS/TS parsing/query logic is centralized in a shared
      `core/sourcetree` module so each check only gains a thin local branch. *Note:* this
      feature edits existing check files by design (it is language coverage, not a new
      check); Principle II's "new check = new file only" clause governs *adding checks* and
      is not violated. Recorded in Complexity Tracking for transparency.
- [x] **III. False Positives over False Negatives**: AST-level analysis removes a class of
      false negatives (multi-line constructs) and false positives (matches in
      comments/strings); ambiguous constructs still flag rather than stay silent.
- [x] **IV. Zero Unnecessary Dependencies (Tier 1)**: Base install stays stdlib-only; the
      parser is an **opt-in `jsts` extra**, genuinely required (stdlib has no JS/TS parser)
      and chosen for pre-compiled, dependency-free wheels. Justified in Complexity Tracking.
- [x] **V. Evidence-Grounded Findings**: JS/TS findings cite file + line + snippet derived
      from real parser node positions; severity follows the existing rubric (unchanged ids).
- [x] **VI. Paired Fixture Testing (NON-NEGOTIABLE)**: Each JS/TS-enabled check ships with a
      vulnerable AND a clean JS/TS fixture; the two cross-cutting accuracy guarantees (SC-003,
      SC-004) get their own paired regression fixtures.
- [x] **VII. Security-Research Currency**: Fresh research pass completed 2026-06-29 →
      [research.md](./research.md) (real 2025–2026 TS MCP command-injection CVEs, the
      `server.tool(...)` registration surface, and the parser technology landscape).

One transparency note (Principle II edits to existing files) is logged below; no gate fails.

## Project Structure

### Documentation (this feature)

```text
specs/002-jsts-ast-coverage/
├── plan.md              # This file
├── spec.md              # Feature specification
├── research.md          # Phase 0 output (JS/TS threat surface + parser tech decision)
├── data-model.md        # Phase 1 output (entities: ParsedSource, language adapter, coverage)
├── quickstart.md        # Phase 1 output (run/validate guide)
└── contracts/           # Phase 1 output (analyzer + per-check JS/TS contracts)
    └── interfaces.md
```

### Source Code (repository root)

```text
mcpfrisk/
├── core/
│   ├── sourcetree/            # NEW: shared, language-agnostic parsed-source layer
│   │   ├── __init__.py        #   public surface: analyze(path) -> ParsedSource | None
│   │   ├── analyzer.py        #   loads the parser, parses bytes, exposes query helpers
│   │   └── jsts.py            #   tree-sitter JS/TS/TSX adapter + tree-query primitives
│   ├── fs.py                  # UNCHANGED (rglob_or_file already handles file/dir targets)
│   └── models.py              # UNCHANGED (Finding/Severity reused as-is)
├── checks/
│   ├── command_injection.py   # EXTEND: replace JS line-regex with AST branch (multi-line + comment-safe)
│   ├── path_traversal.py      # EXTEND: add JS/TS branch (currently Python-only)
│   ├── tool_poisoning.py      # EXTEND: add JS/TS branch — scan server.tool(...) descriptions/metadata
│   ├── hardcoded_secrets.py   # OPTIONAL: use AST string-literal context to drop comment FPs (regex stays)
│   └── registry.py            # UNCHANGED (no new check ids)
└── cli.py                     # UNCHANGED (scan already accepts JS/TS paths)

tests/
├── fixtures/jsts/
│   ├── cmd_injection_vuln.ts / cmd_injection_clean.ts
│   ├── path_traversal_vuln.ts / path_traversal_clean.ts
│   ├── tool_poisoning_vuln.ts / tool_poisoning_clean.ts
│   ├── secrets_vuln.ts / secrets_clean.ts
│   └── accuracy_multiline.ts / accuracy_comment_string.ts   # SC-003 / SC-004 guards
├── test_jsts_command_injection.py
├── test_jsts_path_traversal.py
├── test_jsts_tool_poisoning.py
└── test_jsts_accuracy.py        # multi-line TP + comment/string FP guards, parser-absent skip
```

**Structure Decision**: Single-project layout (existing). All JS/TS parsing lives in one
new `core/sourcetree` package; the four checks call into it through a small stable surface,
so adding JS/TS support to a future check is "ask the analyzer", not "re-implement parsing".
This keeps the Open/Closed isolation of Principle II intact even though existing check files
are edited for their new language branch.

## Complexity Tracking

> Two items justified below: a new Tier-1 dependency, and edits to existing check files.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| New Tier-1 dependency (`tree-sitter` + JS/TS grammars) under an opt-in `jsts` extra | The Python stdlib has no JS/TS/TSX parser; semantic parity (FR-001/005/006) is impossible with stdlib alone | (a) Keep line-regex → rejected: cannot satisfy SC-003/SC-004 (multi-line / comment-string), the whole point of the feature. (b) Shell out to a Node/TypeScript toolchain → rejected: forces every user to install Node, far worse friction than a pip extra. (c) Hand-write a JS/TS parser → rejected: enormous, brittle, and itself a bug/attack surface a security tool can't justify. tree-sitter ships pre-compiled wheels with no library deps and is error-tolerant (ideal for FR-007). |
| Editing the four existing check files (touches `command_injection.py`, `path_traversal.py`, `tool_poisoning.py`, `hardcoded_secrets.py`) | This feature is *language coverage* for existing checks, not a new check; each must learn to read its JS/TS branch | Adding a parallel "JS/TS-only" duplicate of each check → rejected: would split one vulnerability class across two files, doubling maintenance and breaking the "one check id = one place" model. Shared analyzer + thin per-check branch keeps checks mutually isolated (Principle II's real intent). |
