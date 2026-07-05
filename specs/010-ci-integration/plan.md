# Implementation Plan: CI-Integration (010-ci-integration)

**Spec**: [`spec.md`](./spec.md) | **Status**: IMPLEMENTIERT (2026-07-02).
Volle Suite grün, keine Regression.

## Technical Context

Reine CI/UX-Infrastruktur, kein neuer Check, keine neue Security-Erkennung.
Baut auf dem bereits bestehenden `Finding`-Typ (gemeinsam für Tier 1 + Tier 2)
und den bestehenden `report.py`-Funktionen auf.

- **Sprache/Runtime**: Python 3.10+, **stdlib-only** (`hashlib`, `json`).
- **Betroffene/neue Dateien**:
  - `mcpfrisk/core/baseline.py` *(neu)* — Fingerprint + Load/Write/Split.
  - `mcpfrisk/core/sarif.py` *(neu)* — SARIF-2.1.0-Writer.
  - `mcpfrisk/cli.py` — `--baseline`/`--write-baseline` (scan + probe),
    `--sarif` (nur scan).
  - `action.yml` *(neu, Repo-Root)* — Composite GitHub Action.
  - `tests/test_baseline.py`, `tests/test_sarif.py` *(neu)*.

## Architektur-Entscheidungen

1. **Fingerprint ist eine reine Funktion von `Finding` + `target_path`,
   keine Methode auf `Finding` selbst.** `Finding` bleibt eine einfache
   Datenklasse ohne Kenntnis vom Scan-Ziel (Pfad-Relativierung braucht den
   `target_path`-Kontext, den nur der Aufrufer hat). Lebt in
   `core/baseline.py`, importiert `Finding` -- keine Rückabhängigkeit.
2. **Baseline-Split passiert in `cli.py`, nicht in `report.py`.** `report.py`
   bleibt reine Präsentations-/Serialisierungs-Schicht ohne Baseline-Wissen
   (Single Responsibility). `cli.py` berechnet `new`/`known` und reicht
   beides an eine (minimal erweiterte) Report-Funktion bzw. druckt selbst
   eine kurze Baseline-Zusammenfassung.
3. **Exit-Code-Entscheidung nutzt `ScanResult(target_path=..., findings=new).has_blocking_findings(fail_on)`**
   statt die Schwellenwert-Logik zu duplizieren -- Wiederverwendung der
   bestehenden, bereits getesteten Methode auf einer gefilterten Kopie.
4. **SARIF ist read-only gegenüber `ScanResult`** -- eine reine
   Serialisierungs-Funktion `write_sarif_report(result, path)`, analog zu
   `write_json_report`. Kein Einfluss auf Exit-Code/Baseline-Logik.
5. **`action.yml` installiert aus `${{ github.action_path }}`**, nicht von
   PyPI (dort noch nicht veröffentlicht) -- funktioniert sowohl beim
   Dogfooding im eigenen Repo als auch bei externer Nutzung
   (`uses: Imre7777/mcpfrisk@<ref>`), da GitHub den Action-Checkout für
   Composite Actions immer bereitstellt, unabhängig von einem expliziten
   `actions/checkout`-Schritt des Aufrufers.
6. **SARIF bewusst nur für `scan` (Tier 1), nicht für `probe` (Tier 2).**
   Tier-2-Findings haben keinen Datei/Zeile-Ort im Repo -- SARIF/GitHub Code
   Scanning ist für genau das gebaut. Baseline-Diffing dagegen ist
   transport-/tier-unabhängig (funktioniert für jeden `Finding`), daher für
   beide CLI-Befehle.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Tests zuerst (rot), dann Implementierung. |
| II. Plugin Isolation | ✅ | Neue, eigenständige Module (`baseline.py`, `sarif.py`); keine bestehenden Checks angefasst. |
| III. FP over FN | ✅ | Baseline-Findings bleiben sichtbar (nie stillschweigend verschwinden); korrupte Baseline → leere Baseline, kein Crash. |
| IV. Zero Unnecessary Deps | ✅ | stdlib-only (`hashlib`, `json`). |
| V. Evidence-Grounded | ✅ | Fingerprint deterministisch aus vorhandenen Finding-Feldern, keine Heuristik. |
| VI. Paired Fixture Testing | N/A | Kein Detection-Check -- Infrastruktur. Trotzdem: Tests für "Baseline vorhanden" UND "Baseline fehlt/korrupt" (analoges Prinzip). |
| VII. Security-Research Currency | N/A | Keine neue Bedrohungsklasse, reine CI-Infrastruktur; Wettbewerbs-Research bereits in spec.md dokumentiert. |

**Gate-Ergebnis: PASS.**

## Test Strategy (TDD, Prinzip I)

`tests/test_baseline.py`:
- Fingerprint ist stabil über zwei Aufrufe mit identischem Finding.
- Fingerprint ändert sich, wenn check_id/Pfad/Zeile/Titel sich ändern;
  bleibt GLEICH, wenn nur der Snippet-Text sich ändert.
- Fingerprint nutzt relativen Pfad (zwei verschiedene `target_path`-Präfixe,
  gleiche relative Struktur → gleicher Fingerprint).
- `load_baseline`: fehlende Datei → leeres Set; korruptes JSON → leeres Set
  (kein Crash).
- `write_baseline` → `load_baseline` Round-Trip liefert dieselben Fingerprints.
- `split_new_vs_known`: bekannte Findings landen in `known`, neue in `new`.

`tests/test_sarif.py`:
- Erzeugtes SARIF ist valides JSON mit `version == "2.1.0"`,
  `runs[0].tool.driver.name == "mcpfrisk"`.
- Ein Finding pro `results`-Eintrag, korrektes `ruleId`, Severity→level-
  Mapping (CRITICAL/HIGH→error, MEDIUM→warning, LOW/INFO→note).
- Finding mit Datei+Zeile → `physicalLocation` gesetzt; Finding ohne
  Datei/Zeile → kein Crash, `locations` leer/fehlend.
- Leere Findings-Liste → valides SARIF mit leerem `results`-Array.

CLI-Tests (Erweiterung `tests/test_cli_output.py` oder neue Datei):
- `--write-baseline` schreibt eine Datei, die anschließend von `--baseline`
  gelesen werden kann.
- Mit Baseline: ein zuvor bekanntes Finding blockiert den Build nicht mehr
  (Exit-Code 0), bleibt aber im Report sichtbar.
- Ohne Baseline: unverändertes bisheriges Verhalten (Regression).
- `--sarif` erzeugt eine Datei mit erwartetem Inhalt für einen echten Scan
  gegen die bestehenden Fixtures.

Reihenfolge: `core/baseline.py` + Tests → `core/sarif.py` + Tests →
CLI-Wiring + Tests → `action.yml` → volle Suite grün → Doku.

## Risiken / Restunsicherheiten

- **SARIF-Schema-Drift**: SARIF 2.1.0 ist ein großes Schema; dieser Writer
  deckt bewusst nur das ab, was GitHub Code Scanning tatsächlich braucht
  (kein Vollständigkeitsanspruch gegen die volle Spezifikation).
- **`action.yml` lässt sich nicht durch pytest testen** (kein GitHub-Actions-
  Runner lokal) -- Validierung über YAML-Syntax-Check + manuelles
  Nachvollziehen der Schritte, nicht über eine automatisierte Testsuite.
- **Baseline-Datei-Format-Stabilität**: `"version": 1` im Schema vorgesehen,
  falls das Format sich künftig ändert (Migrationspfad offen, kein Bedarf
  jetzt).
