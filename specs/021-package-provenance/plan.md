# Implementation Plan: PACKAGE_PROVENANCE (021)

**Spec**: [`spec.md`](./spec.md) | **Status**: Design entschieden, in Implementierung (2026-07-12).

## Technical Context

Ein neuer statischer (Tier-1-)Check, der `npm audit signatures` **wrappt** —
architektonisch identisch zu DEPENDENCY_SCAN (019). stdlib-only im Basis-Install,
DI-Runner, `applies_to`-gated, nie werfen. KEINE Check-zu-Check-Abhängigkeit.

- **Neue Dateien**:
  - `mcpfrisk/checks/package_provenance.py` — Check + ToolRunner-Port +
    `_NpmSignaturesRunner` + reine `_translate`-Logik.
  - `tests/test_package_provenance.py`.
- **Geändert**: `mcpfrisk/checks/registry.py` (ein `STATIC_CHECKS`-Eintrag).
- **KEINE** pyproject-Änderung (npm ist externe Laufzeit-Voraussetzung).

## Architektur-Entscheidungen

1. **Spiegelt DEPENDENCY_SCAN.** Gleiches Muster: DI-Runner (`available()`/
   `scan()`), reine Übersetzung im Check, Exit-Code-≠-0-bei-Beanstandung ist kein
   Fehler, Tool-Fehler → INFO, `run()` wirft nie. Konsistenz + wiederverwendetes,
   bewährtes Design.
2. **Nur belastbare Signale (Prinzip III).** `invalid` (Tampering) → HIGH
   (CWE-347); `missing` (keine Registry-Signatur) → LOW. **Fehlende Provenance-
   Attestation wird bewusst NICHT geflaggt** (zu verbreitet → Rauschen).
3. **`applies_to` = npm verfügbar UND npm-Lockfile vorhanden.** `npm audit
   signatures` braucht eine Lockfile; ohne beides sauber „skipped".
4. **Defensives Parsing.** Das `invalid`/`missing`-Schema wird best-effort
   gelesen (fehlende Felder übersprungen); nicht-parsebarer Output → INFO.
5. **MCP04 / CWE-347.** Supply-Chain + Signaturprüfung.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Tests zuerst (rot) gegen Canned-Report, dann Check. |
| II. Plugin Isolation | ✅ | Neue Datei + ein Registry-Eintrag; kein Fremd-Check-Import. |
| III. FP over FN | ✅ | Nur invalid/missing (belastbar); fehlende Provenance NIE geflaggt; Tool-Fehler → INFO. |
| IV. Zero Unnecessary Deps | ✅ | Basis-Install stdlib-only; npm optionale externe Laufzeit-Voraussetzung. |
| V. Evidence-Grounded | ✅ | Finding nennt Paket+Version+Signatur-Status aus dem Tool-Report. |
| VI. Paired Fixture Testing | ✅ | Report mit invalid/missing (vuln) UND sauber (clean) + Degradation. |
| VII. Security-Research Currency | ✅ | npm-Signaturen/Provenance-Landschaft + bewusste FP-Entscheidung in spec.md. |

**Gate-Ergebnis: PASS.**

## Test Strategy (TDD, Prinzip I & VI)

`tests/test_package_provenance.py` (Fake-Runner injiziert, kein echtes npm):
- US1: Canned-Report mit `invalid: [foo@1.0.0]` → 1 HIGH (Paket+Version, CWE-347);
  sauberer Report → 0.
- US2: `missing: [bar@2.0.0]` → 1 LOW; kombiniert invalid+missing → 2 (dedup je
  Paket/Version/Klasse).
- US3: Runner `available()==False` ODER keine Lockfile → `applies_to` False;
  Runner-Fehler (`ok=False`) → 1 INFO; malformtes JSON → 1 INFO; `run()` wirft nie.
- Regression: Integrationstest unverändert (ohne npm/Lockfile „skipped").

Reihenfolge: Tests (rot) → `package_provenance.py` → Registry → volle Suite grün
→ Doku.

## Risiken / Restunsicherheiten

- **npm-CLI-Ausgabe-Drift**: `npm audit signatures --json` variiert zwischen
  Versionen. Betrifft nur den Default-Runner (real installiertes npm); die
  getestete Übersetzung nutzt das dokumentierte invalid/missing-Schema, und ein
  unerwarteter Output degradiert zu INFO (transparent), nie Crash. Klar in
  spec.md als Rest-Unsicherheit vermerkt.
- **„skipped" statt „clean"** bei fehlendem npm: bewusst, transparent in
  `checks_skipped`.
