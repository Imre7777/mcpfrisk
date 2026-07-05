# Implementation Plan: Cross-Function-Taint (012-cross-function-taint)

**Spec**: [`spec.md`](./spec.md) | **Status**: IMPLEMENTIERT (2026-07-05).

## Technical Context

Erweiterung von `mcpfrisk/checks/path_traversal.py` um eine Cross-Function-
Taint-Ebene. KEINE Änderung am `SourceModel`-Port (die vorhandenen Felder
`CallSite.callee`/`.args`/`.keywords` und `FunctionDef.name`/`.params`/
`.body_calls`/`.body_text` genügen -- empirisch bestätigt). KEIN neuer Check,
KEINE neue Dependency.

- **Betroffene Dateien**:
  - `mcpfrisk/checks/path_traversal.py` — der Cross-Function-Pass.
  - `tests/fixtures/` — neue paired fixtures (Py + JS/TS).
  - `tests/test_path_traversal_crossfn.py` *(neu)* — die Cross-Function-Tests.
  - **KEINE** Änderung an `core/sourcetree/*`, `command_injection.py`,
    Registry.

## Architektur-Entscheidungen

1. **Reiner Check-Level-Zusatz, kein Port-Umbau.** `run()` hat bereits die
   volle Funktionsliste (`model.functions()`). Ein `name -> FunctionDef`-Map
   plus ein zweiter Pass über die Funktionen reicht -- Plugin-Isolation voll
   erhalten (nur diese eine Check-Datei ändert sich).
2. **Eine Ebene Propagation (F → H).** F muss einen echten pfad-artigen
   Parameter haben (die Quelle). Für jeden Aufruf `H(...)` in F's Körper, bei
   dem ein getaintetes Argument (positional ODER keyword) übergeben wird, gilt
   H's entsprechender Parameter als getaintet. Dann wird H's Körper mit dieser
   propagierten Taint-Menge auf einen Sink geprüft. KEINE Transitivität (F→H→G)
   in v1 -- dokumentierte Grenze, vermeidet FP-/Komplexitäts-Ausufern.
3. **Bindung positional + keyword.** Positional: `call.args[i].referenced_names
   & F_tainted` → `H.params[i]` getaintet. Keyword (Python): `call.keywords[k]`
   getaintet → Parameter `k` getaintet. (JS/TS hat i.d.R. keine Keyword-Args;
   positional deckt den JS-Fall ab.)
4. **Reuse der intra-prozeduralen Sink-Logik.** `_scan_function` wird um einen
   optionalen Parameter `seed_tainted: set[str]` erweitert (zusätzliche, von
   außen getaintete Parameter-Namen). Für den intra-Fall ist er leer
   (Verhalten unverändert); für den cross-Fall enthält er die propagierten
   Helper-Parameter. So teilen sich beide Pfade dieselbe Taint-→-Sink- und
   Validierungs-Logik (DRY, konsistentes Verhalten).
5. **Dedup nach Sink-Fundstelle.** Der intra-Pass läuft zuerst und sammelt die
   gemeldeten Sink-`(file, line)`. Der cross-Pass meldet einen Sink nur, wenn
   seine Fundstelle noch nicht belegt ist -- kein Doppel-Finding.
6. **Validierung im Helper unterdrückt.** Der cross-Pass nutzt dieselbe
   `has_validation`-Prüfung auf H's `body_text` wie der intra-Pass -- ein
   validierender Helper bleibt befundfrei (FR-005).
7. **Eigener Finding-Text mit Fluss-Beschreibung.** Das cross-Finding nennt die
   Entry-Funktion F, den Helper H und den Sink, macht den Ein-Ebenen-Scope
   transparent, behält CWE-22/MCP05/HIGH.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Fixtures + Tests zuerst (rot), dann Erweiterung. |
| II. Plugin Isolation | ✅ | Nur `path_traversal.py` geändert; kein Port-/Fremd-Check-Eingriff. |
| III. FP over FN | ✅ | Validierender Helper → kein Finding; Dedup; konservative Ein-Ebenen-Grenze. |
| IV. Zero Unnecessary Deps | ✅ | stdlib-only, keine Port-Erweiterung. |
| V. Evidence-Grounded | ✅ | Finding verortet den konkreten Sink (Datei:Zeile) + beschreibt den Fluss. |
| VI. Paired Fixture Testing (NON-NEGOTIABLE) | ✅ | vulnerable (Fluss zum Sink) + clean (Helper validiert) Fixture, Python UND JS/TS. |
| VII. Security-Research Currency | N/A | Keine neue Bedrohungsklasse -- Tiefe-Erweiterung eines bestehenden Checks; Wettbewerbs-Research in spec.md. |

**Gate-Ergebnis: PASS.**

## Test Strategy (TDD, Prinzip I & VI)

`tests/fixtures/` (neue kleine Dateien; bestehende vulnerable/clean-Server
unberührt, damit deren Finding-Zahlen stabil bleiben):
- `crossfn_vuln.py` — `read_file(filename)` → `_load(filename)` (Param `x`,
  NICHT pfad-artig) → `open(x)`; plus eine Keyword-Variante `_fetch(target=…)`.
- `crossfn_clean.py` — derselbe Fluss, aber der Helper validiert
  (`is_relative_to`) vor `open` → kein Finding.
- `tests/fixtures/jsts/crossfn_vuln.ts` + `crossfn_clean.ts` — benannte
  `function`-Helfer, positional.

`tests/test_path_traversal_crossfn.py`:
- US1: positional Fluss → 1 HIGH-Finding am Sink in H (Py + JS/TS); clean → 0.
- US2: keyword Fluss (Python) → 1 Finding; Keyword an anderen Param → 0.
- US3: Helper öffnet konstanten/eigenen Wert → 0; Dedup (Helper-Param IST
  pfad-artig → nur intra, nicht zusätzlich cross); zwei Ebenen tief → 0
  (dokumentierte Grenze, kein Crash).
- Regression: bestehende `test_checks.py`/`test_jsts_checks.py`/
  `test_finding_precision.py`-PATH_TRAVERSAL-Fälle bleiben unverändert grün;
  clean-Server weiter 0.

Reihenfolge: Fixtures+Tests (rot) → `path_traversal.py`-Erweiterung → volle
Suite grün → Doku.

## Risiken / Restunsicherheiten

- **FP durch zu breite Bindung**: nur ein Argument, das nachweislich einen
  getainteten Namen referenziert, propagiert -- konstante/eigene Helper-Werte
  lösen nichts aus. Validierender Helper unterdrückt. Ein-Ebenen-Grenze hält
  die Ausbreitung klein.
- **Dedup-Korrektheit**: intra zuerst, cross prüft belegte Sink-Fundstellen ab
  -- getestet über den "Helper-Param IST pfad-artig"-Fall.
- **JS-Arrow-Helper nicht erfasst**: dokumentierte v1-Grenze (Port-Namensgap);
  benannte Funktionen decken den Hauptfall ab.
