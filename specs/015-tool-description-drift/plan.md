# Implementation Plan: TOOL_DESCRIPTION_DRIFT (015)

**Spec**: [`spec.md`](./spec.md) | **Status**: Design entschieden, IMPLEMENTIERT (2026-07-05).

## Technical Context

Neuer statischer (Tier-1-)Check + ein kleines Core-Modul + ein `scan`-Flag.
stdlib-only (`hashlib`, `json`), nutzt den bestehenden `SourceModel`-Port
(`tool_definitions()`) und `iter_source_files`. KEINE Check-zu-Check-
Abhängigkeit.

- **Neue Dateien**:
  - `mcpfrisk/core/tool_baseline.py` — Snapshot/Load/Write/Diff + Pfad-Helfer.
  - `mcpfrisk/checks/tool_description_drift.py` — der Check.
  - `tests/fixtures/jsts/` ggf. ein Tool-Fixture; Python-Fixtures inline.
  - `tests/test_tool_description_drift.py`.
- **Geändert**: `mcpfrisk/checks/registry.py` (ein `STATIC_CHECKS`-Eintrag);
  `mcpfrisk/cli.py` (`scan --write-tools-baseline`).
- **KEINE** Änderung an `core/sourcetree/*` oder anderen Checks.

## Architektur-Entscheidungen

1. **Konvention statt Konfiguration.** Baseline-Pfad ist fest
   `<ziel>/.mcpfrisk-tools.json` (bzw. `<datei>.parent/…` bei Einzeldatei-Ziel).
   Ein `BaseCheck` bekommt nur `run(target_path)` (keine CLI-Config) — die
   Konvention löst das ohne neue Plumbing-Fläche; CLI-Write nutzt denselben
   Pfad-Helfer aus `core/tool_baseline.py` (eine Quelle der Wahrheit).
2. **Drift ist ein Zwei-Zustands-Vergleich → baseline-gated Check.** `applies_to`
   ist True NUR wenn die Baseline existiert (opt-in). Ohne Baseline: skipped
   (kein FP, keine Nag-INFO). So bleibt auch der Integrationstest
   `test_all_static_checks_actually_run` (reines Quellcode-Ziel ohne Baseline)
   unverändert — der Check ist dort „skipped".
3. **Snapshot = Name → sha256(normalisierte Beschreibung)[:16].** Whitespace
   wird normalisiert (führend/folgend strippen, interne Folgen kollabieren),
   damit reine Reformatierung keine Drift ist (gleiche Philosophie wie der
   Finding-Fingerprint in 010). Nur der Hash wird gepinnt (kompakt, kein
   Text-Leak); der aktuelle Text steht als Beleg im Finding.
4. **Zwei Drift-Klassen.** `CHANGED` (Hash weicht ab) → MEDIUM; `NEW` (Tool
   nicht im Baseline) → LOW. `removed` wird ignoriert (kein Rug-Pull).
5. **Write ist eine dedizierte Pin-Aktion.** `scan --write-tools-baseline`
   schreibt den Snapshot und beendet mit 0 (kein Scan-Gate) — klare
   „pin"-Semantik, analog zum bewussten Review-Schritt.
6. **Kein Selbst-Interferenz-Problem.** `iter_source_files` liefert nur
   `*.py`/`*.js`-… (keine `*.json`) → die Baseline-Datei wird von keinem
   Source-Check gelesen; `analyze()` auf JSON gibt es nicht. Sauber getrennt.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Tests zuerst (rot), dann Modul/Check/CLI. |
| II. Plugin Isolation | ✅ | Neue Dateien + ein Registry-Eintrag; kein Fremd-Check-Import. Core-Modul ist check-agnostisch. |
| III. FP over FN | ✅ | Opt-in (ohne Pin nichts); Whitespace-normalisiert; „neu" nur LOW; malformte Baseline = kein Crash/kein FP. |
| IV. Zero Unnecessary Deps | ✅ | stdlib `hashlib`/`json`. |
| V. Evidence-Grounded | ✅ | Finding nennt Tool + aktuellen Beschreibungs-Ausschnitt (Datei/Zeile aus tool_definitions). |
| VI. Paired Fixture Testing | ✅ | changed/new (vuln) UND unverändert (clean) gegen einen gepinnten Baseline, Python + JS/TS. |
| VII. Security-Research Currency | ✅ | Frischer Research-Pass (CVE-2025-54136, Cisco-Threat-Formalisierung, mcp-scan/mcp-warden Pinning) in spec.md. |

**Gate-Ergebnis: PASS.**

## Test Strategy (TDD, Prinzip I & VI)

`tests/test_tool_description_drift.py`:
- Helper: eine Tool-Quelle in tmp_path schreiben, `--write-tools-baseline`-
  Äquivalent (core.tool_baseline.write) pinnen, dann Quelle ändern und den
  Check laufen lassen.
- US1: Beschreibung geändert → 1 MEDIUM (Tool genannt, aktueller Text im Beleg);
  unverändert → 0. Whitespace-only-Änderung → 0.
- US2: neues Tool nicht im Baseline → 1 LOW; im Baseline → 0.
- US3: keine Baseline → applies_to False / run() == []; malformte Baseline →
  []; `write` → Round-Trip (schreiben, dann Scan = 0 Drift).
- JS/TS: geänderte `server.tool("x","<neue Beschreibung>",…)` gegen Pin → MEDIUM.
- CLI: `scan --write-tools-baseline` schreibt die Datei und exitet 0.
- Regression: ohne Baseline keine Findings; bestehende Suite unverändert grün.

Reihenfolge: Tests (rot) → `core/tool_baseline.py` → `checks/
tool_description_drift.py` → Registry → CLI-Flag → volle Suite grün → Doku.

## Risiken / Restunsicherheiten

- **Baseline-Pfad-Konsistenz** zwischen Check (liest) und CLI (schreibt): EIN
  Pfad-Helfer in `core/tool_baseline.py`, von beiden genutzt.
- **Einzeldatei-Ziel**: Pfad-Helfer nutzt `target.parent`, wenn Ziel eine
  Datei ist — Test deckt beides ab.
- **Hash-Kürzung** auf 16 hex: Kollisionsrisiko vernachlässigbar für den Zweck
  (Drift-Erkennung, kein kryptografischer Integritätsbeweis) — im Finding-Text
  klar als „review, nicht Beweis" gerahmt.
- **Dynamischer Rug-Pull** (laufender Server) ist bewusst v1-out-of-scope
  (mögliche Tier-2-Erweiterung), damit die Vorlage stdlib/statisch bleibt.
