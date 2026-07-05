# Feature Specification: Dynamic-Check-Helper konsolidieren + MARKET-RESEARCH aktualisieren

**Feature Branch**: `013-dynamic-helpers-cleanup`

**Created**: 2026-07-05

**Status**: VORBEREITET — spec/plan/tasks geschrieben, NICHT implementiert.
Implementierung folgt nach dem Kontext-Reset.

**Input**: Backlog-Option 3 (Code-Cleanup) nach Abschluss der neuen Checks
(011/012). Zwei getrennte, risikoarme Aufräum-Arbeiten:
1. Die in den vier `call()`-basierten Tier-2-Checks duplizierte Helfer-Logik
   in ein gemeinsames, check-agnostisches Modul ziehen (der Tier-2-Audit
   nannte das als reales, wenn auch latentes Wartungsrisiko).
2. `MARKET-RESEARCH.md` korrigieren, wo die Selbsteinschätzung durch die
   seither umgesetzten Features (002 JS/TS, 010 CI, 011/012) überholt ist.

**Kein neues Verhalten, keine neue Erkennung** — reines Refactoring +
Doku-Korrektur.

## Kontext / Motivation

**Belegte Duplikation (verifiziert 2026-07-05):**
- `_READ_HINTS` (10 Einträge) und `_MUTATE_HINTS` (15 Einträge) sind
  **byte-identisch** in allen vier Checks `rbac_cross_tenant.py`,
  `schema_fuzzing.py`, `error_leakage.py`, `rate_limiting.py` (Hashes je
  identisch bestätigt).
- Das Leak-Marker-Regex-Set (`_TRACEBACK_RE`, `_PY_FRAME_RE`, `_JS_FRAME_RE`,
  `_WIN_PATH_RE`, `_UNIX_PATH_RE`, `_SQL_ERROR_RE`, `_EXCEPTION_CLASS_RE`,
  `_LEAK_PATTERNS`) und die Funktion `_find_leak` sind **byte-identisch**
  zwischen `schema_fuzzing.py` und `error_leakage.py`.
- Die Schema-Helfer `_properties`/`_required` und die Tool-Klassifikation
  `_is_read_tool` existieren als (nahezu) identische Kopie in allen vier
  Checks; `_truncate` in dreien.

**Warum das ein Risiko ist (nicht nur Kosmetik):** heute kein Drift, aber
nichts erzwingt, dass eine Verbesserung an einer Stelle propagiert. Ergänzt
z.B. jemand einen Go-Panic- oder Rust-`thread 'main' panicked`-Marker in
`schema_fuzzing`, aber nicht in `error_leakage`, entsteht ein **asymmetrischer
False Negative** — genau die Klasse Fehler, die Prinzip III/VI verhindern
sollen, und kein Test würde die Divergenz fangen. Der Audit hat das explizit
als konsolidierungswürdig markiert.

**Warum das Prinzip II (Plugin Isolation) NICHT verletzt:** Prinzip II verbietet
Abhängigkeiten **eines Checks von einem ANDEREN Check** (damit die Regression
eines Checks keinen anderen mitreißt). Ein gemeinsames, check-AGNOSTISCHES
Utility-Modul, das selbst kein `BaseCheck`/`BaseDynamicCheck` ist, ist genau
das erlaubte Muster — `mcpfrisk/checks/_ssrf_callback.py` ist der bereits
existierende Präzedenzfall (ein geteilter Nicht-Check-Helfer). Die Checks
*nutzen* eine Utility, sie *hängen* nicht voneinander ab.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Ein gemeinsames Helfer-Modul, ein Ort der Wahrheit (Priority: P1)

Als Maintainer:in möchte ich, dass die Tool-Hints, Schema-Helfer und
Leak-Marker an EINER Stelle stehen, damit eine Verbesserung automatisch für
alle vier Checks gilt und nicht still divergiert.

**Independent Test**: nach dem Refactor definiert KEINER der vier Checks
`_READ_HINTS`/`_MUTATE_HINTS`/`_LEAK_PATTERNS`/`_find_leak` selbst; alle
importieren aus `mcpfrisk/checks/_dynamic_helpers.py`. Die volle bestehende
Test-Suite bleibt **unverändert grün** (Verhalten identisch).

**Acceptance Scenarios**:

1. **Given** das konsolidierte Helfer-Modul, **When** die volle Suite läuft,
   **Then** alle bestehenden Tests (schema_fuzzing/error_leakage/rbac/
   rate_limiting/…) bleiben grün OHNE Änderung ihrer Erwartungen.
2. **Given** die vier Checks, **When** man ihren Quelltext prüft, **Then**
   enthält keiner mehr eine eigene Kopie der konsolidierten Symbole (ein Test
   kann das über den Import/`getattr` verifizieren).

---

### User Story 2 — MARKET-RESEARCH.md spiegelt den echten Stand (Priority: P2)

Als Projektinhaber:in möchte ich, dass die Wettbewerbs-Selbsteinschätzung nicht
überholte Schwächen behauptet, die längst geschlossen sind.

**Independent Test**: die veralteten Aussagen sind korrigiert (Beleg per
Grep/Review), ohne die strategische Substanz des Dokuments zu verfälschen.

**Acceptance Scenarios**:

1. **Given** §5-Vergleichstabelle, **When** aktualisiert, **Then** spiegelt sie:
   JS/TS wird von ALLEN statischen Checks per AST abgedeckt (nicht "nur 1 von
   4", überholt seit Feature 002); Regelanzahl 5 statisch + 6 dynamisch;
   Baseline-Diffing/SARIF/GitHub-Action vorhanden (Feature 010);
   Cross-Function-Taint eine Ebene vorhanden (Feature 012).
2. **Given** §6/§7 (Differenzierungs-/Roadmap-Punkte), **When** aktualisiert,
   **Then** sind die inzwischen erledigten Punkte (JS/TS-Erstklassigkeit,
   Cross-Function-Taint, Baseline, SARIF, GitHub Action) als erledigt markiert,
   die noch offenen (eigenes Benchmark, Tier 3) bleiben stehen.

---

### Edge Cases

- **Ein Test importiert bislang ein privates Symbol direkt** (z.B.
  `from mcpfrisk.checks.schema_fuzzing import _find_leak`): der Refactor MUSS
  solche Importe entweder erhalten (Re-Export) oder den Test mitziehen —
  nichts darf rot werden.
- **Subtile Verhaltensänderung durch Zusammenführung**: die konsolidierten
  Symbole MÜSSEN wertgleich zu den bisherigen sein (byte-identisch bestätigt),
  damit das Refactoring nachweislich verhaltensneutral ist.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Ein neues Modul `mcpfrisk/checks/_dynamic_helpers.py` MUSS die
  gemeinsamen Symbole beherbergen: `READ_HINTS`, `MUTATE_HINTS`,
  `is_read_tool(name)`, `tool_properties(tool)`, `tool_required(tool)`, das
  Leak-Marker-Set + `find_leak(text)`, `truncate(text, limit)`.
- **FR-002**: `schema_fuzzing.py`, `error_leakage.py`, `rbac_cross_tenant.py`,
  `rate_limiting.py` MÜSSEN diese Symbole importieren statt sie zu duplizieren.
- **FR-003**: Das Refactoring MUSS **verhaltensneutral** sein: die vollständige
  bestehende Test-Suite bleibt grün, ohne dass Test-Erwartungen geändert
  werden (nur ggf. Import-Zeilen, falls ein Test ein privates Symbol direkt
  referenzierte).
- **FR-004**: Das gemeinsame Modul DARF selbst KEIN `BaseCheck`/
  `BaseDynamicCheck` sein und KEINEN Check importieren (check-agnostisch,
  Plugin-Isolation gewahrt — analog `_ssrf_callback.py`).
- **FR-005**: `MARKET-RESEARCH.md` MUSS an den überholten Stellen (§5-Tabelle,
  §6/§7-erledigte Punkte) korrigiert werden, ohne die strategische Substanz zu
  verfälschen.
- **FR-006**: Es DARF KEINE neue Laufzeit-Abhängigkeit entstehen (stdlib-only).

### Key Entities

- **`_dynamic_helpers.py`**: check-agnostisches Utility-Modul (kein Check).

## Success Criteria *(mandatory)*

- **SC-001**: Kein Dynamic-Check definiert die konsolidierten Symbole mehr
  selbst; alle importieren aus dem gemeinsamen Modul.
- **SC-002**: Volle Suite grün, KEINE geänderten Test-Erwartungen (reiner
  Refactor); die Finding-Ausgaben aller vier Checks sind unverändert.
- **SC-003**: `MARKET-RESEARCH.md` enthält keine überholte "JS/TS nur 1 von 4"-
  bzw. "Cross-Function fehlt / Baseline fehlt / kein SARIF / keine Action"-
  Aussage mehr.
- **SC-004**: Basis-Install bleibt dependency-frei; Plugin-Isolation gewahrt.

## Assumptions

- Die konsolidierten Symbole sind heute wertgleich (byte-identisch bestätigt),
  daher ist die Zusammenführung ohne Verhaltensänderung möglich.
- Out of scope: die statischen Checks (CMD/PATH/SECRETS/POISONING/COLLISION)
  teilen sich bereits `fs.py`/`sourcetree`; keine weitere Konsolidierung dort
  nötig. Keine funktionale Erweiterung der Leak-Marker o.ä. in diesem Feature
  (reiner Umzug; Marker-Erweiterungen sind ein separates künftiges Thema).
