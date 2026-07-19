<!--
Thanks for contributing to McpFrisk! Keep one logical change per PR and explain
the *why*, not just the *what*. See CONTRIBUTING.md and CONTEXT.md.
-->

## What & why

<!-- What does this change and why is it needed? Link any issue (Fixes #NN). -->

## Checklist

- [ ] **Test-first.** New behavior has a test; a bug fix has a regression test (failing test written before the fix).
- [ ] **Paired fixtures.** If this touches a check, it ships both a *vulnerable* and a *clean* fixture (Python and JS/TS where applicable).
- [ ] **Plugin isolation.** New checks are self-contained; checks don't import each other (shared logic lives in a non-check helper).
- [ ] **Zero-dep core respected.** No new runtime dependency in the base install; anything external is an optional extra that degrades cleanly.
- [ ] **Spec-Kit.** For a new check/feature, `specs/NNN-name/{spec,plan,tasks}.md` is included, with security research cited.
- [ ] `ruff check .` is clean and the full test suite is green locally.
- [ ] Docs updated where relevant (`README.md`, `CONTEXT.md`, `CHANGELOG.md`).

## Notes for reviewers

<!-- Anything worth calling out: trade-offs, follow-ups, areas needing extra eyes. -->
