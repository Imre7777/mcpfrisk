# Implementation Plan: Real-World-Korpus

**Feature**: 031-realworld-corpus | **Constitution-Check**: n/a (Benchmark-Tooling,
kein Produktcode/Check; Zero-Dep-Kern unberührt — nutzt nur stdlib + git-CLI).

## Datei
`benchmark/realworld_corpus.py` (neu):
- `MANIFEST`: 14 gepinnte echte MCP-Server (SHA via `git ls-remote`, 2026-07-15).
- `clone_pinned` (shallow fetch des SHA), `scan_repo` (`python -m mcpfrisk`,
  DEVNULL für stdout/stderr, per-Repo-Timeout), `provenance`, `write_reports`.
- CLI: `--only`, `--timeout`, `--workdir`, `--keep`.
- Erzeugt `benchmark/REALWORLD.md` + `benchmark/realworld.json`.

## Verifikation
- Subset-Lauf (`--only ...`) validiert Klonen/Scannen/Report end-to-end.
- Voller Manifest-Lauf erzeugt den Snapshot (Ausfälle als Status protokolliert).
- Keine neuen pytest-Tests nötig (Tooling, kein Produktcode); ruff bleibt grün
  (benchmark/ ist nicht von ruff extend-exclude erfasst -> Datei muss lint-sauber
  sein).

## Risiken
- **Netzwerk/Größe**: manche Repos groß/langsam -> per-Repo-Timeout fängt das ab,
  Status „timeout" statt Hänger.
- **Windows-Encoding**: subprocess-Ausgabe verworfen (DEVNULL), JSON mit
  errors='replace' gelesen -> keine cp1252-Dekodierfehler.
- **Reproduzierbarkeit**: SHAs im Manifest gepinnt; Aktualisierung = SHAs neu
  auflösen + ersetzen.
