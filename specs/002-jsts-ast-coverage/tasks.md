---
description: "Task list for first-class JavaScript/TypeScript analysis"
---

# Tasks: First-class JavaScript/TypeScript analysis

**Input**: Design documents from `specs/002-jsts-ast-coverage/`

**Prerequisites**: plan.md, spec.md (user stories), research.md, data-model.md, contracts/interfaces.md, quickstart.md

**Tests**: MANDATORY for this project. Per the constitution (`.specify/memory/constitution.md`,
Principles I & VI) tests are written FIRST, approved by the maintainer, and confirmed
FAILING (red) before implementation. Every newly JS/TS-covered check ships with a paired
vulnerable-fixture and clean-fixture test.

**Organization**: Tasks grouped by user story (US1 detection parity, US2 clean passes,
US3 semantic accuracy) so each is independently testable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no incomplete dependencies)
- **[Story]**: US1 / US2 / US3 (Setup, Foundational, Polish carry no story label)

## Path Conventions

Single project: package at `mcpfrisk/`, tests + fixtures at `tests/` (repo root).
JS/TS parsing lives in the new `mcpfrisk/core/sourcetree/` package.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Make the JS/TS parser available as an opt-in extra without touching the
dependency-free base install.

- [ ] T001 Add an optional `jsts` extra to `[project.optional-dependencies]` in `pyproject.toml` (`tree-sitter>=0.21`, `tree-sitter-typescript`, `tree-sitter-javascript`); add `jsts` into the `dev` extra so CI exercises the AST path. Keep core `dependencies` empty (Constitution IV). `tree-sitter-language-pack` noted as fallback grammar source.
- [ ] T002 [P] Create the `tests/fixtures/jsts/` directory and confirm `pytest` collects `tests/test_jsts_*.py` via the existing `[tool.pytest.ini_options]`.
- [ ] T003 [P] Add a "JavaScript/TypeScript support" subsection to `README.md`: the `pip install mcpfrisk[jsts]` line, which checks cover JS/TS, and the graceful-skip behaviour when the extra is absent.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The shared `core/sourcetree` analysis layer every check branch depends on.

**⚠️ CRITICAL**: No user-story work begins until this phase is complete.

### Foundational tests (write FIRST, confirm RED) ⚠️

- [ ] T004 [P] Create `tests/test_jsts_analyzer.py` asserting: (a) a valid `.ts` snippet parses to `ParsedSource(ok=True)`; (b) a syntactically broken `.ts` still returns `ok=True` with a usable tree (tree-sitter recovers, FR-007); (c) when the parser/extra is simulated-absent, `analyze()` returns `ParsedSource(ok=False)` and `jsts_available()` is `False` — never raises, never signals "clean". Confirm FAILING.

### Foundational implementation

- [ ] T005 Create `mcpfrisk/core/sourcetree/__init__.py` exposing `analyze(path) -> ParsedSource | None`, `jsts_available() -> bool`, and the `SourceLanguage` enum + extension mapping (`.js/.mjs/.cjs/.jsx`, `.ts/.mts/.cts`, `.tsx`) per data-model.md. Returns `None` for non-JS/TS paths.
- [ ] T006 Create `mcpfrisk/core/sourcetree/analyzer.py`: `ParsedSource` and `NodeMatch` dataclasses, lazy parser import (so missing extra ⇒ `ok=False`, not ImportError at module load), byte-based parse, and the node→`(line, snippet)` evidence helper (Principle V).
- [ ] T007 Create `mcpfrisk/core/sourcetree/jsts.py`: the tree-sitter adapter + query helpers from contracts/interfaces.md — `calls_to(callee_names)`, `string_arguments(match)`, `tool_descriptions()`, `functions_with_params(name_hints)`, `string_literals()` — selecting the `typescript`/`tsx`/`javascript` grammar per `SourceLanguage`. Make T004 GREEN.

**Checkpoint**: The analyzer parses JS/TS, recovers from malformed input, and degrades cleanly when the extra is missing. Checks can now consume it.

---

## Phase 3: User Story 1 - Detection parity (true positives) (P1) 🎯 MVP

**Goal**: For each static check, an idiomatic vulnerable `.ts` fixture produces the expected finding (SC-001).

**Independent Test**: Scan each vulnerable JS/TS fixture → the matching check id fires.

### Tests for User Story 1 (write FIRST, confirm RED) ⚠️

- [ ] T008 [P] [US1] Create `tests/fixtures/jsts/cmd_injection_vuln.ts`: a `server.tool(...)` callback running `` exec(`lsof -t -i tcp:${port}`) `` (the GHSA-3ch2-jxxc-v4xf pattern).
- [ ] T009 [P] [US1] Create `tests/fixtures/jsts/tool_poisoning_vuln.ts`: a `server.tool("x", …)` whose description contains an `<IMPORTANT>`/hidden-instruction pattern.
- [ ] T010 [P] [US1] Create `tests/fixtures/jsts/path_traversal_vuln.ts`: a tool taking a `filePath` arg passed to `fs.readFileSync` with no normalization.
- [ ] T011 [P] [US1] Create `tests/fixtures/jsts/secrets_vuln.ts`: a hardcoded API-key literal assigned to a secret-named const.
- [ ] T012 [US1] Add `tests/test_jsts_command_injection.py::test_vuln_ts_is_flagged` (CMD_INJECTION). Confirm RED.
- [ ] T013 [US1] Add `tests/test_jsts_tool_poisoning.py::test_vuln_ts_is_flagged` (TOOL_POISONING). Confirm RED.
- [ ] T014 [US1] Add `tests/test_jsts_path_traversal.py::test_vuln_ts_is_flagged` (PATH_TRAVERSAL). Confirm RED.
- [ ] T015 [US1] Add `tests/test_jsts_secrets.py::test_vuln_ts_is_flagged` (HARDCODED_SECRETS) — confirms parity (may already pass via existing cross-language regex; lock it in).

### Implementation for User Story 1

- [ ] T016 [US1] In `mcpfrisk/checks/command_injection.py`: replace `_scan_js_file` (line-regex) with an AST branch using `sourcetree.analyze` + `calls_to({"exec","execSync","child_process.exec",…})` and `string_arguments` (template-literal substitution / concatenation ⇒ finding). Keep the existing regex as the parser-absent fallback. Make T012 GREEN.
- [ ] T017 [US1] In `mcpfrisk/checks/tool_poisoning.py`: widen `run`/`applies_to` to JS/TS and scan `tool_descriptions()` with the existing poisoning pattern families. Make T013 GREEN.
- [ ] T018 [US1] In `mcpfrisk/checks/path_traversal.py`: widen `applies_to` to JS/TS and add a branch using `functions_with_params(path_hints)` + `calls_to({"fs.readFile…","open","path.join",…})` with the same "no visible normalization" heuristic. Make T014 GREEN.
- [ ] T019 [US1] In `mcpfrisk/checks/hardcoded_secrets.py`: confirm `.ts` is in the scanned extension set and T015 passes; no behaviour change yet (FP-scoping happens in US2).

**Checkpoint**: Every check fires on its vulnerable JS/TS fixture — parity TP achieved. MVP deliverable.

---

## Phase 4: User Story 2 - Clean servers pass cleanly (false-positive guards) (P1)

**Goal**: For each check, an idiomatic safe `.ts` fixture yields zero findings of that check (SC-002).

**Independent Test**: Scan each clean JS/TS fixture → zero findings of that check.

### Tests for User Story 2 (write FIRST, confirm RED) ⚠️

- [ ] T020 [P] [US2] Create `tests/fixtures/jsts/cmd_injection_clean.ts` (`execFile("lsof", ["-t","-i",`tcp:${port}`])` / arg array — no shell string).
- [ ] T021 [P] [US2] Create `tests/fixtures/jsts/tool_poisoning_clean.ts` (purely descriptive tool description).
- [ ] T022 [P] [US2] Create `tests/fixtures/jsts/path_traversal_clean.ts` (`path.resolve` + containment check before `fs` access).
- [ ] T023 [P] [US2] Create `tests/fixtures/jsts/secrets_clean.ts` (secret read from `process.env`).
- [ ] T024 [US2] Add `test_clean_ts_is_not_flagged` to each of the four `tests/test_jsts_*.py` files (SC-002). Confirm RED where the US1 branch is still too eager.

### Implementation for User Story 2

- [ ] T025 [US2] Harden the four JS/TS branches so the clean fixtures yield zero findings without breaking US1: CMD_INJECTION ignores `execFile`/array-arg `spawn`; PATH_TRAVERSAL recognizes `path.resolve`+containment / `realpath`; TOOL_POISONING only matches the poisoning families; HARDCODED_SECRETS scopes matches to `string_literals()` (drops comment FPs) and respects `process.env`. Make all T024 GREEN.

**Checkpoint**: US1 + US2 both pass for all four checks — the paired-fixture bar (Constitution VI) is met for JS/TS.

---

## Phase 5: User Story 3 - Semantic accuracy beyond line-regex (P2)

**Goal**: Detect multi-line dangerous constructs (SC-003) and ignore look-alikes in comments/strings (SC-004) — proof this is AST analysis, not regex.

**Independent Test**: The multi-line fixture is flagged; the comment/string fixture is not.

### Tests for User Story 3 (write FIRST, confirm RED) ⚠️

- [ ] T026 [P] [US3] Create `tests/fixtures/jsts/accuracy_multiline.ts`: an `exec(...)` whose interpolated command/template literal is split across several lines.
- [ ] T027 [P] [US3] Create `tests/fixtures/jsts/accuracy_comment_string.ts`: `exec(...)` appearing only inside a `//` comment and inside a normal string literal.
- [ ] T028 [US3] Add `tests/test_jsts_accuracy.py`: `test_multiline_call_is_flagged` (SC-003) and `test_exec_in_comment_or_string_is_not_flagged` (SC-004). Confirm RED against any residual regex behaviour.

### Implementation for User Story 3

- [ ] T029 [US3] Confirm/adjust the CMD_INJECTION AST branch (T016) so both accuracy tests pass — multi-line nodes are matched by structure; comment and string-literal nodes are excluded by node kind. Make T028 GREEN. (No new files; structural correctness of the AST branch.)

**Checkpoint**: All three stories independently functional; the AST advantage is demonstrated.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Remaining edge cases, mixed-language behaviour, CI, and the parser-absent path.

- [ ] T030 [P] Add `tests/test_jsts_accuracy.py::test_malformed_ts_does_not_abort_scan` (SC-006): a broken `.ts` alongside a valid file — the valid file is still scanned.
- [ ] T031 [P] Add `tests/test_jsts_accuracy.py::test_mixed_python_and_ts_tree` (SC-005): a folder with `.py` + `.ts` returns the union of findings, no cross-language interference.
- [ ] T032 [P] Add `tests/test_jsts_accuracy.py::test_parser_absent_skips_not_clean`: with `jsts_available()` False, JS/TS files are reported skipped (one notice), never "clean", no crash; CMD_INJECTION still works via its regex fallback.
- [ ] T033 Wire the parser-absent notice into the scan flow (`mcpfrisk/cli.py` / `core/report.py`): print the `pip install mcpfrisk[jsts]` hint once when JS/TS files are present but the extra is missing.
- [ ] T034 Update `.github/workflows/ci.yml`: install the `jsts` extra and run `tests/test_jsts_*.py` in the matrix; add one job WITHOUT the extra asserting the skip/fallback path (T032) passes.
- [ ] T035 [P] Confirm exclusions cover `node_modules`/`dist`/`build`/minified bundles for the new branches (FR-008) and add a small assertion if not already covered.
- [ ] T036 Run `quickstart.md` end-to-end and the full `pytest` suite (existing + new) green across Python 3.10–3.12.

---

## Dependencies & Execution Order

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: depends on Setup; BLOCKS all user stories (every check branch imports `core/sourcetree`).
- **US1 (Phase 3)**: depends on Foundational. MVP. The four checks are independent files → their fixture/test/impl chains run in parallel.
- **US2 (Phase 4)**: depends on Foundational + the US1 branches it hardens; independently testable via its own clean fixtures.
- **US3 (Phase 5)**: depends on the CMD_INJECTION AST branch (T016); independently testable.
- **Polish (Phase 6)**: depends on the branches it hardens.

### Within each story

- Tests are written and MUST FAIL before implementation (Constitution I, NON-NEGOTIABLE).
- Analyzer (Phase 2) before any check branch; vulnerable fixture/test before that check's impl; clean fixture/test before hardening.

### Parallel opportunities

- Setup: T002, T003.
- Foundational test T004 is one file; impl T005–T007 are sequential (same package).
- US1 fixtures T008–T011 are independent files → [P]; the four check impls (T016–T019) touch different files → effectively parallel once their tests are red.
- US2 fixtures T020–T023 → [P].
- US3 fixtures T026, T027 → [P].
- Polish tests T030, T031, T032, T035 touch independent areas → [P].

---

## Implementation Strategy

### MVP first (US1 only)

1. Phase 1 Setup → 2. Phase 2 Foundational (analyzer) → 3. Phase 3 US1 → **STOP & VALIDATE**: every check fires on its vulnerable `.ts` fixture. Demoable: "McpFrisk now finds the same bugs in TypeScript."

### Incremental delivery

US1 (parity TP) → US2 (no false positives — the trust gate) → US3 (AST accuracy that beats regex) → Polish (mixed-language, malformed, parser-absent, CI). Each increment keeps prior tests green.

---

## Notes

- [P] = different files, no incomplete dependencies.
- Verify every test fails before implementing it (Constitution I, NON-NEGOTIABLE).
- A missing parser extra is reported as *skipped*, never as *clean* (Constitution III).
- Checks never import `tree_sitter` directly — only via `core/sourcetree` (Principles II/IV).
- Commit after each task or logical group.
