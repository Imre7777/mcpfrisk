# Implementation Plan: DEPENDENCY_SCAN (019)

**Spec**: [`spec.md`](./spec.md) | **Status**: Design entschieden, in Implementierung (2026-07-12).

## Technical Context

Ein neuer statischer (Tier-1-)Check, der `osv-scanner` **wrappt** (kein Nachbau).
stdlib-only im Basis-Install (`subprocess`, `shutil`, `json`), nutzt
`rglob_or_file`/`DEFAULT_EXCLUDED_DIRS` aus `core/fs`. KEINE Check-zu-Check-
Abhängigkeit. `osv-scanner` ist eine optionale externe Laufzeit-Voraussetzung.

- **Neue Dateien**:
  - `mcpfrisk/checks/dependency_scan.py` — der Check + ToolRunner-Port +
    osv-scanner-Default-Runner + reine Übersetzungs-/Severity-Logik.
  - `tests/test_dependency_scan.py`.
- **Geändert**: `mcpfrisk/checks/registry.py` (ein `STATIC_CHECKS`-Eintrag).
- **KEINE** pyproject-Änderung: osv-scanner ist ein Go-Binary, kein Python-Extra
  — es wird separat installiert und über den PATH erkannt (dokumentiert im README).

## Architektur-Entscheidungen

1. **Wrapper, kein Nachbau (Design-Prinzip 3).** McpFrisk baut keine CVE-DB; es
   delegiert an osv-scanner und übersetzt dessen JSON in die einheitliche
   Finding-/SARIF-/Baseline-Pipeline. Der Mehrwert ist EIN Gate/Report/Exit-Code
   für MCP-Findings UND Dependency-CVEs.
2. **Dependency-Injection des ToolRunners.** `DependencyScanCheck(runner=None)`;
   Default = osv-scanner-Subprozess. Tests injizieren einen Fake-Runner mit
   Canned-JSON → die Übersetzungs-Logik ist offline + ohne installiertes Tool
   testbar. Registry ruft `DependencyScanCheck()` (Default-Runner) — kein Bruch.
3. **Zero-Dep-Kern (Prinzip IV).** osv-scanner ist NICHT gebündelt; fehlt es,
   `applies_to` False → sauber „skipped". Kein Python-Dependency im Basis-Install.
4. **Nie werfen, nie stiller Clean (Prinzip III).** `run()` fängt alles ab.
   Exit-Code 1 = Vulns (kein Fehler, JSON wird geparst). Anderer Exit/Timeout/
   kein JSON → ein einzelnes INFO-Finding (transparent), keine Vuln-Findings,
   kein Crash. Ein echter „0 Vulns"-Report → [] (echt sauber).
5. **Reine Übersetzungsfunktionen.** `_translate(report_json) -> list[Finding]`
   und `_severity_from(vuln) -> Severity` sind pur und einzeln getestet
   (Prinzip V: Evidenz aus dem Report, keine Heuristik).
6. **Severity aus CVSS/Label**, unbekannt → MEDIUM (konservativ). Referenz pro
   Finding = CVE-/OSV-/GHSA-ID + Advisory-Links (kein eigenes CWE-Mapping).

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Tests zuerst (rot) gegen Canned-Report, dann Check. |
| II. Plugin Isolation | ✅ | Neue Check-Datei + ein Registry-Eintrag; kein Fremd-Check-Import. |
| III. FP over FN | ✅ | Findings kommen aus einer maßgeblichen Advisory-DB (osv), nicht aus Heuristik; Tool-Fehler → INFO, nie stiller Clean. |
| IV. Zero Unnecessary Deps | ✅ | Basis-Install stdlib-only; osv-scanner ist optionale externe Laufzeit-Voraussetzung, kein Python-Dependency. |
| V. Evidence-Grounded | ✅ | Finding nennt Paket+Version+CVE/OSV-ID+Fix+Advisory-Links aus dem Report. |
| VI. Paired Fixture Testing | ✅ | Report mit Vuln (vuln) UND ohne (clean) + Tool-fehlt/Tool-Fehler/malformt. |
| VII. Security-Research Currency | ✅ | osv-scanner ist die maßgebliche, gepflegte Quelle; Prinzip 3 (nicht neu erfinden) explizit in spec.md. |

**Gate-Ergebnis: PASS.**

## Test Strategy (TDD, Prinzip I & VI)

`tests/test_dependency_scan.py` (Fake-Runner injiziert, kein echtes osv-scanner):
- `_severity_from`: CVSS 9.8→CRITICAL, 7.5→HIGH, 5.0→MEDIUM, 2.0→LOW, unbekannt→MEDIUM.
- US1: Canned-Report mit `requests 2.19.0`/CVE → 1 Finding (Paket+Version+ID+Fix
  im Text, MCP04); „0 Vulns"-Report → 0.
- US2: mehrere Vulns / mehrere Pakete → korrekte Anzahl, dedup über Lockfiles.
- US3: Runner `available()==False` → `applies_to` False; Runner-Fehler
  (`ok=False`) → 1 INFO, keine Vuln-Findings, kein Crash; malformtes JSON → 1 INFO.
- Regression: Integrationstest `test_all_static_checks_actually_run` unverändert
  (ohne Tool/Manifest „skipped"); `run()` wirft nie.

Reihenfolge: Tests (rot) → `dependency_scan.py` (Port + Default-Runner +
Übersetzung) → Registry → volle Suite grün → Doku (inkl. README-Hinweis zur
osv-scanner-Installation).

## Risiken / Restunsicherheiten

- **osv-scanner-CLI-Drift**: die Aufruf-Syntax variiert zwischen Versionen. Das
  betrifft nur den Default-Runner (real installiertes Tool); die getestete
  Übersetzungs-Logik ist davon unabhängig. Ein unerwarteter Exit-Code → INFO
  (transparent), kein Crash.
- **JSON-Schema-Varianz**: das Übersetzungs-Parsing ist defensiv (fehlende Felder
  → best-effort, nie Crash); unbekannte Severity → MEDIUM.
- **„Skipped" statt „clean" bei fehlendem Tool**: bewusst — transparent in
  `checks_skipped`, nicht als Pass. Der README dokumentiert die Installation.
