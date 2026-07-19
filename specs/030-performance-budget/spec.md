# Feature Specification: Performance-Regressionstest

**Feature Branch**: `030-performance-budget`

**Created**: 2026-07-15

**Status**: Fertig. ROADMAP Phase 3.4 (P2).

## Kontext / Motivation

Auf einem großen Monorepo (python-sdk, 815 Dateien) lief der Scan früher >90s in
einen Timeout — v.a. PATH_TRAVERSAL/CMD_INJECTION mit ihrer Cross-Function-
Analyse. Nach den Excludes (022) und dem Datei-Scoping (026) ist das entschärft;
dieser Test verhindert einen stillen Rückfall (z.B. ein versehentlich
quadratischer Pass oder ein Per-Datei-Blowup).

## Ansatz (bewusst großzügig, nicht flaky)
- Synthetischer Baum aus **300** moderat realistischen Server-Dateien (eigene
  Instanz, Helfer, Cross-Function-Fluss mit `open`/`subprocess shell=True`/
  `urlopen`) — damit die AST-/Taint-schweren Checks echte Arbeit leisten.
- `run_static_scan` muss in **< 40s** durchlaufen. Lokale Messung ~5–6s → ~7–8x
  Puffer. Das ist **kein Mikro-Benchmark**: das Budget trippt nur bei einer
  *katastrophalen* Regression (Hang, O(n²) über Dateien, vielfacher Per-Datei-
  Blowup), nicht bei kleinen Schwankungen → robust gegen CI-Lastspitzen.
- Zusätzliche Assertion: der Scan erzeugt tatsächlich Findings (sonst wäre
  „schnell" wertlos — ein leer durchlaufender Scan).

## Akzeptanz
- Test grün (lokal ~6s), Budget 40s.
- Volle Suite grün, ruff clean.

## Nicht-Ziele
- Keine Mikro-/Vergleichs-Benchmarks (das ist Phase 4, der externe Benchmark).
- Kein O(n)-vs-O(n²)-Doppelmessung (verdoppelt Laufzeit + Flakiness) — das große
  N deckt katastrophale Skalierung bereits ab.
