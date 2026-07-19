# Tasks: Real-World-Korpus

Benchmark-Tooling (kein pytest-Rot/Grün) — Verifikation via Lauf + ruff.

- **T001** SHAs kuratierter Server via `git ls-remote` auflösen (gepinnt). ✅
- **T002** `benchmark/realworld_corpus.py`: Manifest + clone_pinned + scan_repo
  (DEVNULL) + provenance + write_reports + CLI. ✅
- **T003** Subset-Lauf zur Validierung; dann voller Manifest-Lauf →
  `REALWORLD.md` + `realworld.json`.
- **T004** ruff clean; ROADMAP 4.1 abhaken; README/benchmark-Verweis; Commit + Push.
