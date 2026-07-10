# Implementation Plan: Dynamic-Helpers-Cleanup (013)

**Spec**: [`spec.md`](./spec.md) | **Status**: IMPLEMENTIERT (2026-07-05).

## Technical Context

Reines Refactoring (verhaltensneutral) + Doku-Korrektur. Kein neues Verhalten,
keine neue Erkennung, keine neue Dependency.

- **Neue Datei**: `mcpfrisk/checks/_dynamic_helpers.py` (check-agnostisches
  Utility-Modul, kein `BaseCheck`).
- **Geänderte Dateien**: `mcpfrisk/checks/schema_fuzzing.py`,
  `error_leakage.py`, `rbac_cross_tenant.py`, `rate_limiting.py` (Importe statt
  Duplikate); `MARKET-RESEARCH.md` (Korrekturen).
- **Neuer Test** *(optional, klein)*: `tests/test_dynamic_helpers.py` — sichert
  den Contract des gemeinsamen Moduls (is_read_tool, find_leak, tool_properties)
  und dass die Checks keine eigene Kopie mehr definieren.

## Architektur-Entscheidungen

1. **Gemeinsames Modul, kein Check** — `_dynamic_helpers.py` ist ein reines
   Utility (Konstanten + freie Funktionen), analog `_ssrf_callback.py`. Es
   importiert KEINEN Check → keine Zyklen, Prinzip II gewahrt.
2. **Öffentliche Namen ohne Unterstrich-Präfix im gemeinsamen Modul**
   (`READ_HINTS`, `find_leak`, …) — das Modul selbst ist per `_`-Dateiname als
   intern markiert; die Symbole darin sind für die Checks bestimmt, daher ohne
   führenden Unterstrich importierbar. Die Checks können lokale Aliase behalten,
   wo das die Diffs kleiner hält.
3. **Verhaltensneutralität ist das oberste Gebot.** Die bestehende Suite
   (aktuell 193 Tests) ist das Sicherheitsnetz: nach dem Refactor MUSS sie
   unverändert grün sein. Kein Test-Erwartungswert wird angepasst; nur falls
   ein Test ein privates Symbol direkt importierte, wird der Import
   nachgezogen (per Grep vorab prüfen).
4. **Byte-Gleichheit als Migrations-Garantie.** Da die Duplikate bestätigt
   wertgleich sind, ist der Umzug ein 1:1-Move -- kein Merge unterschiedlicher
   Varianten, kein Verhaltensrisiko.
5. **MARKET-RESEARCH.md: nur Fakten-Korrektur, keine Strategie-Umschreibung.**
   Die veralteten Selbsteinschätzungen (JS/TS-Abdeckung, Regelanzahl,
   Baseline/SARIF/Action, Cross-Function-Taint) werden auf den Ist-Stand
   gebracht; die Wettbewerbsanalyse und die verbleibenden offenen Punkte
   (eigenes Benchmark, Tier 3) bleiben inhaltlich erhalten.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ (angepasst für Refactor) | Die vorhandene, umfassende Suite IST der Rot-Grün-Wächter: sie muss vor UND nach dem Move grün sein; optionaler kleiner Contract-Test fürs neue Modul zuerst. |
| II. Plugin Isolation | ✅ **zentral** | Gemeinsames Utility ist check-agnostisch (kein `BaseCheck`, importiert keinen Check) -- Präzedenz `_ssrf_callback.py`. Checks nutzen, hängen nicht voneinander ab. |
| III. FP over FN | ✅ | Verhaltensneutral; die Konsolidierung REDUZIERT das Drift-/FN-Risiko (ein Ort der Wahrheit). |
| IV. Zero Unnecessary Deps | ✅ | stdlib-only. |
| V. Evidence-Grounded | ✅ | Keine Änderung an der Beleg-Logik der Findings. |
| VI. Paired Fixture Testing | ✅ | Keine neue Detektionslogik; bestehende paired fixtures bleiben die Absicherung. |
| VII. Security-Research Currency | N/A | Kein neuer Check. |

**Gate-Ergebnis: PASS** (Test-First-Interpretation für Refactor dokumentiert).

## Test Strategy (TDD, Prinzip I)

1. **Vor dem Move**: `grep -rn "_find_leak\|_READ_HINTS\|_LEAK_PATTERNS\|
   _MUTATE_HINTS\|_is_read_tool\|_properties\|_required\|_truncate" tests/`
   -- prüfen, ob ein Test ein privates Symbol direkt importiert (dann Import
   nachziehen).
2. **Optionaler Contract-Test zuerst** (`tests/test_dynamic_helpers.py`, rot):
   `is_read_tool("get_x")` True, `is_read_tool("delete_x")` False;
   `find_leak("Traceback (most recent call last)")` trifft, `find_leak("ok")`
   None; `tool_properties`/`tool_required` lesen ein `inputSchema` korrekt.
   Plus: keiner der vier Checks definiert die Symbole noch selbst
   (`assert not hasattr(module, "_LEAK_PATTERNS")` o.ä. bzw. Identitäts-Check
   gegen das gemeinsame Modul).
3. **Move ausführen**, dann **volle Suite** `pytest -q` -- MUSS unverändert grün
   sein (193 + optional der neue Contract-Test).
4. **MARKET-RESEARCH.md** aktualisieren (kein Test, reine Doku; per Review
   verifizieren).

Reihenfolge: Grep-Check → Contract-Test (rot) → `_dynamic_helpers.py` anlegen →
Checks umstellen → Suite grün → MARKET-RESEARCH.md → Commit/Push.

## Risiken / Restunsicherheiten

- **Versteckte Verhaltensänderung**: minimiert durch bestätigte Byte-Gleichheit
  und die unveränderte Suite als Netz. Falls doch ein Test kippt, war die
  Annahme "wertgleich" falsch -- dann stoppen und untersuchen, nicht den Test
  anpassen.
- **Direkter Privat-Import in Tests**: vorab per Grep abgefangen.
- **Scope-Disziplin**: KEINE funktionale Erweiterung (keine neuen Leak-Marker,
  keine neue Tool-Hint) in diesem Feature -- reiner Umzug. Erweiterungen sind
  ein separates künftiges Thema.
