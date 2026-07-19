# Feature Specification: TOOL_NAME_COLLISION Verzeichnis-Scoping

**Feature Branch**: `026-collision-scoping`

**Created**: 2026-07-15

**Status**: In Implementierung. ROADMAP Phase 0.2 (P1). Behebt die dominante
verbliebene False-Positive-Klasse aus der Real-World-Validierung an der Wurzel
(statt nur per `--exclude` aus Feature 022 zu entschärfen).

## Kontext / Motivation

**Der FP:** `TOOL_NAME_COLLISION` sammelt aktuell alle Tool-Definitionen über
**alle** gescannten Dateien und vergleicht sie **global**. In SDK-/Beispiel-
Monorepos (python-sdk, typescript-sdk) definieren viele **unabhängige**
Beispielserver jeweils Tools wie `echo`, `greet`, `noop` — die dann fälschlich
als Kollision quer über die ganze Repo gemeldet werden (die beobachtete Flut von
~83 Findings).

**Die Semantik:** Der eigentliche Angriff (Tool-Shadowing) setzt voraus, dass
**derselbe** Server zwei gleichnamige Tools registriert. Zwei getrennte Server,
die zufällig beide ein `echo` haben, überschatten sich **nicht** — sie laufen nie
im selben Namensraum. Global zu vergleichen ist also semantisch falsch.

**Der Fix:** Kollisionen nur innerhalb einer **Datei** werten (eine Quelldatei =
ein logisches Server-Boundary). Unabhängige Beispielserver liegen in getrennten
Dateien und kollidieren damit nicht mehr; echte Duplikate innerhalb derselben
Datei bleiben erhalten.

**Warum Datei statt Verzeichnis oder Instanz (evidenzbasiert):** Erst als
Verzeichnis-Scope getestet — die Real-World-Daten (2026-07) haben es aber
widerlegt: python-sdks Doku-Tutorials (`docs_src/.../tutorial001.py`,
`tutorial002.py`, …) sind **eigenständige, vollständige** Server (je eine eigene
`FastMCP()`-Instanz), die **flach dasselbe Verzeichnis teilen** — Verzeichnis-
Scoping meldete sie weiter fälschlich (53 FP). Ebenso mcp-atlassian:
`confluence.py` (`confluence_mcp`) und `jira.py` (`jira_mcp`) sind getrennte
Sub-Server, die beim Mounten geprefixt werden — auch das sind **keine**
Kollisionen. In beiden Fällen ist die Datei das Server-Boundary; **alle**
beobachteten FP sind cross-file. Instanz-Tracking wäre theoretisch am
präzisesten, braucht aber Import-/Receiver-Auflösung im SourceModel-Port
(deutlich komplexer) — Datei-Scope trifft dieselben Fälle bei minimalem Aufwand.
Verbleibende, bewusst akzeptierte Grenze: ein über **mehrere Dateien** verteilter
EINZELserver, der denselben Tool-Namen doppelt registriert, wird nicht gemeldet
(ohne Import-Auflösung nicht von getrennten Servern zu unterscheiden; real selten).

## User Scenarios

### US1 — getrennte Dateien = keine Kollision (der Fix)
Zwei eigenständige Server, egal ob in getrennten Verzeichnissen
(`examples/a/main.py`, `examples/b/main.py`) oder flach im selben Verzeichnis
(`docs/tutorial001.py`, `tutorial002.py`), definieren beide ein Tool `echo` →
**kein** Finding. Ebenso getrennte Sub-Server-Instanzen (`confluence_mcp` in
`confluence.py`, `jira_mcp` in `jira.py`).

### US2 — Duplikat in DERSELBEN Datei bleibt erfasst
Zweifaches `echo` in **einer** Datei → weiterhin MEDIUM.

### US3 — Near-Duplicate ebenfalls datei-gebunden
`get_item`/`get_items` in derselben Datei → weiterhin LOW; über getrennte Dateien
→ **kein** Finding.

## Functional Requirements
- **FR1**: Exakte und Near-Duplicate-Vergleiche laufen nur zwischen Occurrences
  aus derselben Datei (`file`).
- **FR2**: Bestehendes Verhalten bei Ein-Datei-Fixtures unverändert.
- **FR3**: Deterministische, stabile Ausgabe (gleicher Input → gleiche Findings).
- **FR4**: Finding-Text nennt die Datei-Grenze transparent.

## Nicht-Ziele
- Kein Instanz-genaues Server-Tracking (Datei genügt für die Monorepo-Flut).
- Cross-Server/Cross-Repo-Kollision bleibt out of scope (kann McpFrisk nicht sehen).
- Testdatei-interne Duplikate (z.B. mehrere Testfälle mit gleichem Tool-Namen in
  einer `test_*.py`) sind Sache von `--exclude`/`.mcpfriskignore` (Feature 022),
  nicht dieses Scopings.
