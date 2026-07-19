# Feature Specification: Reproduzierbarer Real-World-Korpus

**Feature Branch**: `031-realworld-corpus`

**Created**: 2026-07-15

**Status**: In Implementierung. ROADMAP Phase 4.1 (P1). Erster Baustein des
Benchmark-Beweises.

## Kontext / Motivation

Das gelabelte Korpus (`benchmark/corpus/`, 14 synthetische Samples) misst
Precision/Recall gegen bekannte Ground-Truth. Was fehlte: ein **reproduzierbares**
Signal, wie viel **Rauschen** McpFrisk auf **echten, seriösen** MCP-Servern
erzeugt — die Frage, die über „blamiert man sich?" entscheidet.

Frühere Real-World-Checks (Session 2026-07-14) klonten Repos ad hoc bei HEAD —
nicht reproduzierbar. Dieses Feature macht daraus einen **gepinnten** Korpus.

## Design

`benchmark/realworld_corpus.py`:
- **MANIFEST**: echte, populäre MCP-Server, jeweils auf einen `git ls-remote`-
  aufgelösten **Commit-SHA gepinnt** (Reproduzierbarkeit). Mix aus Python & TS.
- **clone_pinned**: Shallow-Fetch genau des SHA (`git fetch --depth 1 origin <sha>`),
  kein voller History-Clone.
- **scan_repo**: `python -m mcpfrisk scan --json` (nutzt den 028er Modul-Entry),
  Ausgabe verworfen (nur JSON-Datei ausgewertet), per-Repo-Timeout, Status
  (ok/timeout/error/clone-failed) + Findings-Zähler pro `check_id`.
- **EXCLUDES**: Test-/Beispiel-/Doku-Bäume (`tests`, `examples`, `docs`, …) —
  gescannt wird der *ausgelieferte* Servercode, wie ein Nutzer sein Repo real
  prüft. Transparent im Report gelistet.
- **provenance**: mcpfrisk-Commit/-Version, clean-tree-Flag, Zeitstempel,
  Python/Plattform, Exclude-Liste.
- Schreibt `benchmark/REALWORLD.md` + `benchmark/realworld.json`.

## Ehrliche Abgrenzung (Prinzip V)
Der Real-World-Korpus misst **Präzision/Rauschen auf echtem Code**, NICHT
gelabelten Recall — die wahren Schwachstellen dieser Repos sind nicht annotiert.
Das steht so im Report. Der gelabelte Recall/Precision-Test bleibt `RESULTS.md`.

## Akzeptanz
- Harness läuft reproduzierbar (`python -m benchmark.realworld_corpus`), gepinnt.
- `REALWORLD.md` + `realworld.json` mit Provenance erzeugt.
- `--only`/`--timeout`/`--keep`-Flags funktionieren; Ausfälle (timeout/clone)
  werden ehrlich als Status protokolliert, nicht verschwiegen.

## Nicht-Ziele / Folge-Arbeit
- Kein per-Finding-Handtriage aller Repos (der Report misst Rauschen; einzelne
  Findings sind Kandidaten für Triage/Folge-Fixes).
- Manifest ist auf Wachstum Richtung 30–50 Server ausgelegt (4.4).
- Precision/Recall/F1-Tabelle + Laufzeit-Vergleich: 4.2 / 4.3 (Folge-Features).
