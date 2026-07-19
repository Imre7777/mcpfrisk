# Feature Specification: Fuzz-/Property-Robustheit (Zero-Crash)

**Feature Branch**: `029-fuzz-robustness`

**Created**: 2026-07-15

**Status**: Fertig. ROADMAP Phase 3.2 (P1).

## Kontext / Motivation

Ein Security-Tool darf an **keinem** Eingabe-Müll crashen: ein ungefangener
Fehler mitten im Scan überspringt still Findings (verletzt Prinzip III, „nie
still clean"). Diese Feature fügt Property-/Fuzz-Tests hinzu, die adversarialen
Input gegen die zentralen Eingabepfade werfen und **Zero-Crash** verlangen.

**Bewusst stdlib statt hypothesis:** Die ROADMAP nannte `hypothesis`, aber das
ist eine externe Dev-Abhängigkeit (und lokal hier nicht installierbar). Die
Zero-Crash-Garantie ist mit stdlib-`random` (fester Seed → deterministisch)
vollständig erreichbar und passt zum Zero-Dep-Ethos. hypothesis bleibt eine
optionale spätere Aufwertung (besseres Shrinking), kein Muss.

## Abgedeckte Eingabepfade
- `is_excluded` / `exclude_context` — beliebige Pfade + Glob-Muster (wilde
  `[`/`{`/`*`/`!`, Steuerzeichen, Riesenlängen) → immer `bool`, nie Exception.
- `load_ignore_patterns` — beliebiger `.mcpfriskignore`-Inhalt → immer `tuple`.
- `analyze()` (SourceModel-Port) — kaputter/wüster Quelltext (`.py`/`.ts`/`.js`)
  UND roher Binärmüll → `None` bzw. `ok=False`, nie Exception.
- `run_static_scan` — ein ganzer Baum aus Müll-Dateien → wohldefiniertes
  `ScanResult`, kein Crash über alle 12 statischen Checks.

## Ergebnis
Alle Fuzz-Tests grün, **kein** Crash gefunden — die bestehende Degradations-/
Kapselungs-Architektur (ast/tree-sitter im Adapter gekapselt) hält beliebigem
Input stand. Die Tests zementieren das als Regression. Müll-Quelltext löst in
`ast.parse` harmlose `SyntaxWarning`s aus (erwartet, im Test unterdrückt).

## Nicht-Ziele
- Keine hypothesis-Abhängigkeit (bewusst).
- Keine Fuzzing der dynamischen (Netzwerk-)Checks — die haben eigene
  Timeout-/INCONCLUSIVE-Absicherung.
