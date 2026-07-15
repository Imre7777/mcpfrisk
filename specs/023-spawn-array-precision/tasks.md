# Tasks: spawn-Array-Präzision

Strikt TDD (rot → grün), ein Commit.

- **T001** `tests/test_cmd_injection_spawn.py` (rot): US1 spawn ohne shell:true
  (Variable + Template) → kein Finding; US2 spawn+`{shell:true}` → Finding;
  US3 exec/execSync unverändert gefährlich; US4 `spawn('sh',['-c',x])` → CRITICAL.
- **T002** `checks/command_injection.py`: `_JS_SPAWN_FAMILY`, `_JS_SHELL_TRUE_RE`,
  `_js_has_shell_true`, JS-Zweig von `_assess` umbauen (spawn-Guard).
- **T003** Volle Suite grün + ruff clean + Gegencheck an echtem JS-Repo,
  ROADMAP 0.1 abhaken, Commit + Push.
