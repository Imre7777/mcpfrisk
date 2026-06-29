# Feature Specification: First-class JavaScript/TypeScript analysis

**Feature Branch**: `002-jsts-ast-coverage`

**Created**: 2026-06-29

**Status**: Draft

**Input**: User description: "First-class JavaScript and TypeScript AST analysis across all static checks so MCP servers written in JS/TS are scanned with the same depth as Python"

## Why this feature *(context)*

A large share of MCP servers are written in TypeScript/JavaScript, yet today McpFrisk
treats them as second-class: only `CMD_INJECTION` looks at JS/TS at all, and it does so
with line-by-line regular expressions, while `TOOL_POISONING`, `PATH_TRAVERSAL`, and
`HARDCODED_SECRETS` silently scan Python only. The two direct competitors share exactly
this weakness (one is documented as "limited" on JS/TS, the other scores effectively
zero on it). Closing this gap with **semantic, parser-level** analysis — not more regex —
is the single highest-leverage differentiator available to the project.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A TypeScript server author gets the same findings a Python author would (Priority: P1)

An author of a TypeScript MCP server runs McpFrisk on their source tree. Every
vulnerability class McpFrisk can already detect in Python (command/shell injection,
tool-description poisoning, path traversal, hardcoded secrets) is detected in their
JS/TS code with comparable fidelity, reported through the same finding model.

**Why this priority**: This is the core value and the headline differentiator. Without
it, JS/TS authors — the majority of the MCP ecosystem — get a scan that quietly misses
most of what the tool is supposed to find. There is no feature without this story.

**Independent Test**: For each existing check that has a Python "known-bad" fixture,
provide a behaviourally equivalent JS/TS fixture (same vulnerability, expressed
idiomatically in TS). Running McpFrisk against the JS/TS fixture MUST produce the
corresponding finding. This delivers value on its own even before later stories.

**Acceptance Scenarios**:

1. **Given** a TypeScript file that builds a shell command from interpolated user input
   and runs it, **When** McpFrisk scans the file, **Then** a `CMD_INJECTION` finding is
   produced pointing at the offending call.
2. **Given** a TypeScript tool definition whose description contains a hidden-instruction
   pattern (e.g. an `<IMPORTANT>` directive), **When** McpFrisk scans it, **Then** a
   `TOOL_POISONING` finding is produced — the same way it would for a Python docstring.
3. **Given** a JS/TS file that reads a filesystem path assembled from untrusted input,
   **When** McpFrisk scans it, **Then** a `PATH_TRAVERSAL` finding is produced.
4. **Given** a JS/TS file containing a hardcoded credential, **When** McpFrisk scans it,
   **Then** a `HARDCODED_SECRETS` finding is produced.

---

### User Story 2 - A correctly written JS/TS server passes cleanly (Priority: P1)

An author who wrote safe TypeScript (argument arrays instead of shell strings,
parameterized path handling, secrets pulled from the environment, purely descriptive
tool descriptions) runs McpFrisk and the JS/TS analysis stays silent, so the tool is
trustworthy enough to gate CI.

**Why this priority**: Equal to Story 1. Per the project constitution, detection logic
is unverified until it is proven NOT to fire on correct code. JS/TS analysis that floods
clean idiomatic TypeScript with false positives is unusable and would be worse than the
current regex.

**Independent Test**: Provide a "known-good" JS/TS fixture for each check that exercises
the safe idiom. A scan MUST produce zero findings of that check.

**Acceptance Scenarios**:

1. **Given** a TS file that uses `execFile(cmd, [args])` (no shell string), **When**
   scanned, **Then** no `CMD_INJECTION` finding is produced.
2. **Given** a TS tool whose description only describes what the tool does, **When**
   scanned, **Then** no `TOOL_POISONING` finding is produced.
3. **Given** a TS file that loads a secret from an environment variable, **When**
   scanned, **Then** no `HARDCODED_SECRETS` finding is produced.

---

### User Story 3 - Semantic accuracy that line-regex cannot reach (Priority: P2)

The analysis understands the structure of the code rather than matching text lines, so
it catches constructs the current regex misses and ignores look-alikes that are not real
code.

**Why this priority**: This is what makes the work "first-class" rather than "more
regex". It directly removes both a class of false negatives (multi-line constructs) and a
class of false positives (matches inside comments/strings) that the existing line-based
JS scanner suffers from.

**Independent Test**: Provide a fixture where a dangerous call spans multiple lines (e.g.
a template literal broken across lines) and a fixture where the dangerous-looking text
appears only inside a comment or string literal. The multi-line case MUST be flagged; the
comment/string case MUST NOT be flagged.

**Acceptance Scenarios**:

1. **Given** a shell call whose interpolated command is split across several lines,
   **When** scanned, **Then** it is still detected (the current line-regex would miss it).
2. **Given** a commented-out `exec(...)` line or the word in a string literal, **When**
   scanned, **Then** no finding is produced for it.

---

### Edge Cases

- **Syntactically invalid / partial source file**: The analysis MUST NOT crash the scan.
  It skips the unparseable file (optionally noting it) and continues, exactly as the
  Python path already does for `SyntaxError`.
- **Vendored / generated code** (`node_modules`, `dist`, `build`, minified bundles): MUST
  be excluded from scanning, consistent with the existing exclusion behaviour, so authors
  are not drowned in findings from dependencies they did not write.
- **TypeScript-only syntax** (type annotations, interfaces, decorators, enums): MUST be
  accepted by the analysis and not mistaken for errors; type-only constructs carry no
  runtime risk and MUST NOT by themselves produce findings.
- **File variants**: `.js`, `.ts`, and the realistic ecosystem variants (`.mjs`/`.cjs`,
  `.jsx`/`.tsx`, `.mts`/`.cts`) are recognized as JS/TS source.
- **Non-UTF-8 / binary masquerading as source**: handled gracefully (skipped), never a
  crash, matching the existing `errors="ignore"` posture.
- **Very large files**: a single pathological file MUST NOT hang the scan unboundedly.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: McpFrisk MUST analyse JavaScript and TypeScript source by understanding its
  syntactic structure (parser/AST level), not by matching raw text lines.
- **FR-002**: Every static check that currently detects a vulnerability class in Python
  MUST detect the equivalent class in JS/TS: `CMD_INJECTION`, `TOOL_POISONING`,
  `PATH_TRAVERSAL`, and `HARDCODED_SECRETS`. "Parity" means the same vulnerability,
  expressed idiomatically in JS/TS, yields a finding of the same check id.
- **FR-003**: JS/TS findings MUST use the existing finding model and conventions —
  check id, severity rubric, OWASP-MCP and CWE references, file path, line number,
  snippet, and remediation — so output is uniform across languages.
- **FR-004**: The analysis MUST recognize the common JS/TS file extensions (at minimum
  `.js`, `.ts`; including the `.mjs/.cjs/.jsx/.tsx/.mts/.cts` variants) as in-scope
  source.
- **FR-005**: The analysis MUST NOT report matches that occur only inside comments or
  string/template literals that are not themselves the dangerous construct (false-positive
  guard that the current line-regex cannot provide).
- **FR-006**: The analysis MUST detect dangerous constructs even when they span multiple
  lines (false-negative guard that the current line-regex cannot provide).
- **FR-007**: A file that fails to parse MUST be skipped without aborting the overall
  scan, and MUST NOT be reported as "clean" in a way that hides risk.
- **FR-008**: Vendored, generated, and minified directories/files MUST be excluded
  consistently with the existing exclusion set.
- **FR-009**: The JS/TS analysis MUST be deterministic: the same input always yields the
  same findings (no run-to-run variation).
- **FR-010**: TypeScript-specific syntax MUST be parsed successfully and MUST NOT, on its
  own, generate findings (no penalising the use of types).
- **FR-011**: Each JS/TS-capable check MUST remain independently selectable/deselectable
  through the existing check-skip mechanism.
- **FR-012**: The feature MUST honour the project's dependency philosophy: any new
  capability needed to parse JS/TS is justified against the zero-/minimal-dependency
  principle in the implementation plan, and its trade-off recorded. *(Resolution of
  whether to vendor a parser, shell out to one, or implement a focused parser is a plan
  decision, not a spec decision.)*

### Key Entities *(include if feature involves data)*

- **Source analysis (per language)**: the capability that turns a JS/TS source file into
  a structure the checks can inspect (the JS/TS counterpart to the existing Python AST
  walk). Attributes: input file, parsed representation, parse-success/failure state.
- **Check-to-language coverage**: the mapping of each existing check to the set of
  languages it can analyse; the goal state is that the four static checks cover both
  Python and JS/TS.
- **Finding**: unchanged — reuses the existing model. JS/TS findings differ only in which
  file and construct they point at.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For each of the four static checks, a JS/TS "known-bad" fixture produces the
  expected finding in 100% of runs (parity true-positive rate matches the Python path).
- **SC-002**: For each of the four static checks, a JS/TS "known-good" fixture produces
  zero findings of that check in 100% of runs (no false positives on safe idioms).
- **SC-003**: A dangerous construct split across multiple lines is detected, where the
  pre-feature line-regex scanner missed it (demonstrated by a regression fixture).
- **SC-004**: Dangerous-looking text that appears only in a comment or string literal
  produces no finding (demonstrated by a regression fixture).
- **SC-005**: Scanning a tree that mixes Python and JS/TS produces the union of findings
  from both languages, with no crash and no cross-language interference.
- **SC-006**: A syntactically invalid JS/TS file never aborts or hangs the scan; the rest
  of the tree is still scanned to completion.

## Assumptions

- The realistic target is **parity for the four checks that exist today**, not inventing
  new JS/TS-only vulnerability classes (those can follow as separate features).
- "Same depth as Python" is benchmarked against the Python implementations' current
  heuristics, not against a hypothetical perfect analyzer; parity means "catches the
  equivalent idiom", not "byte-identical logic".
- The choice of parsing mechanism (a vendored pure-Python JS/TS parser, an external
  toolchain invoked as a subprocess, or a focused hand-written parser) is deliberately
  left to the implementation plan so the spec stays technology-agnostic.
- Tool-poisoning detection for JS/TS targets the same surface as Python: the
  descriptions/metadata attached to tool definitions (e.g. the SDK's tool-registration
  call), expressed in JS/TS idioms.
- Existing exclusion conventions (`node_modules`, `.venv`, `dist`, `build`, etc.) remain
  the basis for what is out of scope; this feature does not redefine them.
