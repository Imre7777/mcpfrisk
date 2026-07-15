# Implementation Plan: spawn-Array-Präzision

**Feature**: 023-spawn-array-precision | **Constitution-Check**: bestanden.

- **I Test-First**: `tests/test_cmd_injection_spawn.py` rot zuerst.
- **II Plugin-Isolation**: Änderung nur in `checks/command_injection.py`.
- **III FP-over-FN**: reduziert FP; Unterdrückung nur bei beweisbar shell-freiem
  `spawn`. `sh -c` und `shell:true` bleiben erfasst → keine echte Lücke.
- **IV Zero-Deps**: stdlib (`re`).
- **VI Paired-Fixture**: je Fall vuln+clean (spawn ohne/mit shell:true, exec).

## Änderung in `_assess` (JS/TS-Zweig)

Neue Konstanten:
```python
_JS_SPAWN_FAMILY = frozenset({"spawn", "spawnSync"})
_JS_SHELL_TRUE_RE = re.compile(r"shell\s*:\s*true\b")
```

Neuer Helfer:
```python
@staticmethod
def _js_has_shell_true(call) -> bool:
    # shell:true steht in JS als Objekt-Literal-Argument, nicht in keywords.
    return any(_JS_SHELL_TRUE_RE.search(a.text or "") for a in call.args)
```

Umbau des JS-Zweigs (Reihenfolge):
1. `first.is_constant_string` → wie bisher: `sh -c <tainted>`-Interpreter-Muster
   prüfen (CRITICAL), sonst `None` (Konstante ist nicht injizierbar).
2. `first.is_array` → `None`.
3. **NEU**: `spawn_family = seg in _JS_SPAWN_FAMILY`; `shell_true = _js_has_shell_true(call)`.
   Wenn `spawn_family and not shell_true` → `None` (spawn ohne Shell: erstes Arg ist
   Programmname, kein Shell-Kommando).
4. Danach unverändert: `first.has_interpolation` → HIGH; `first.referenced_names`
   → HIGH; sonst `None`. (Gilt jetzt für exec/execSync **oder** spawn+shell:true.)

`seg` wird aus `call.callee.rsplit(".",1)[-1]` gewonnen (Member- wie nackter Aufruf).

## Risiko
- Der `sh -c`-Pfad läuft VOR dem spawn-Guard (er hängt an `is_constant_string`),
  bleibt also erhalten. Test US4 sichert das ab.
- FN-Grenze `shell: <var>`: dokumentiert, selten; bewusst akzeptiert (Nicht-Ziel).
