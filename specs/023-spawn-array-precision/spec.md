# Feature Specification: spawn-Array-Präzision (JS/TS CMD_INJECTION)

**Feature Branch**: `023-spawn-array-precision`

**Created**: 2026-07-14

**Status**: Design entschieden — in Implementierung. Präzisions-Fix aus der
Real-World-Validierung (ROADMAP Phase 0.1, P0): der einzige bekannte Bug, der
auf **korrektem, empfohlenem** Nutzercode falsch anschlägt.

**Input**: JS/TS-Code, der `spawn(cmd, [args])` **ohne** `{shell: true}` nutzt —
die von Node ausdrücklich empfohlene, sichere Form (kein Shell-Kontext).

## Kontext / Motivation

**Der Bug:** `checks/command_injection.py::_assess` bewertet für JS/TS alle
gefährlichen Segmente (`exec`, `execSync`, `spawn`, `spawnSync`) über **denselben**
Pfad. Bei nicht-konstantem erstem Argument (Variable oder Template-Literal) meldet
er HIGH. Das ist für `exec`/`execSync` korrekt — deren erstes Argument ist ein
**Shell-Kommandostring** (`/bin/sh -c <arg>`). Für `spawn`/`spawnSync` ist es
**falsch**: dort ist das erste Argument ein **Programmname**, die Argumente stehen
in einem separaten Array, und es wird **keine Shell** gestartet, außer man setzt
explizit `{shell: true}`.

**Folge:** `spawn(cmd, [userInput])` — die sichere Standardform — wird als HIGH
Command Injection geflaggt. Das meckert Best-Practice-Code an und ist auf jedem
JS/TS-MCP-Server, der `spawn` korrekt nutzt, ein False Positive.

**Node-Semantik (Recherche-geerdet):**
- `exec(cmd)` / `execSync(cmd)` → führt `cmd` **immer** über eine Shell aus.
  Variable/interpolierte Eingabe = Shell-Injection.
- `spawn(prog, args)` / `spawnSync(prog, args)` → startet `prog` direkt (execvp),
  Argumente als separate argv-Elemente, **keine** Shell — außer `{shell: true}`.
- `execFile(prog, args)` / `execFileSync` → nie Shell (bereits gar nicht geflaggt).

**Bewusste Präzisions-Entscheidung (Prinzip III):** Wir unterdrücken ein Finding
nur, wenn wir sicher sind, dass **keine** Shell im Spiel ist. `spawn` ohne
`shell: true` und ohne das `sh -c`-Interpreter-Muster ist genau so ein Fall.

## User Scenarios

### US1 — spawn ohne Shell ist sauber (der Fix)
`spawn(cmd, [userInput])` bzw. `spawn(\`${bin}\`, args)` ohne `{shell: true}`
→ **kein** Finding.

### US2 — spawn mit shell:true bleibt gefährlich
`spawn(cmd, args, {shell: true})` mit nicht-konstantem `cmd`/Array → Shell wird
aktiv → Finding (HIGH/CRITICAL), wie `exec`.

### US3 — exec/execSync unverändert
`exec(\`ls ${dir}\`)` / `execSync(cmd)` → weiterhin gefährlich (immer Shell).

### US4 — `sh -c <tainted>` bleibt CRITICAL
`spawn('sh', ['-c', tainted])` (Interpreter-Name als args[0]) → weiterhin
CRITICAL, unabhängig von der Familie/Option (echte Shell-Invokation).

## Functional Requirements
- **FR1**: `spawn`/`spawnSync` ohne `shell: true` und ohne `sh -c`-Muster erzeugen
  **kein** CMD_INJECTION-Finding, auch bei variablem/interpoliertem erstem Argument.
- **FR2**: `spawn`/`spawnSync` **mit** `{shell: true}` werden wie `exec` bewertet.
- **FR3**: `exec`/`execSync`-Verhalten bleibt unverändert.
- **FR4**: Das `sh -c <tainted>`-Interpreter-Muster bleibt CRITICAL (alle Familien).
- **FR5**: `shell: true` wird aus dem Options-Objekt-Argument erkannt (in JS steht
  es NICHT in `call.keywords`, sondern als Objekt-Literal in `call.args`).

## Nicht-Ziele
- Kein neues Finding für „arbitrary program execution" bei `spawn(varProg, ...)` —
  das ist eine andere, schwächere Klasse und würde neue FP erzeugen.
- `shell: <dynamischer Ausdruck>` (statt Literal `true`) wird als Nicht-Shell
  behandelt (seltener Sonderfall, dokumentierte Grenze).
