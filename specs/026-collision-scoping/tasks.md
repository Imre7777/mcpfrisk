# Tasks: Collision-Scoping

Strikt TDD (rot → grün), ein Commit.

- **T001** `tests/test_collision_scoping.py` (rot): getrennte Dateien (exakt +
  near, auch same-dir) → kein Finding; dieselbe Datei → weiterhin geflaggt.
- **T002** `tool_name_collision.py`: `run()` nach `file` gruppieren (Datei-Scope,
  nach Real-World-Verifikation gewählt); exact/near pro Datei; Finding-Text auf
  Datei-Grenze schärfen.
- **T003** Volle Suite grün + ruff clean + Real-World-Gegencheck (SDK-Monorepos:
  cross-file-FP → 0), ROADMAP 0.2 abhaken, Commit + Push.
