# Feature Specification: CI-Integration (Baseline-Diffing, SARIF, GitHub Action)

**Feature Branch**: `010-ci-integration`

**Created**: 2026-07-02

**Status**: IMPLEMENTIERT (2026-07-02). `core/baseline.py`, `core/sarif.py`,
CLI-Flags (`--baseline`/`--write-baseline`/`--sarif`) und `action.yml`.

**Input**: Nach Abschluss der gesamten Tier-2-Roadmap (6/6 Checks) und einem
vollständigen Tier-1/2-Audit (12 Bugfixes) wurde eine erneute Konkurrenz-
Recherche (MARKET-RESEARCH.md) konsultiert: der größte verbleibende Hebel
gegen den direkten Konkurrenten `agent-audit` liegt NICHT in neuen Checks,
sondern in CI/UX-Funktionen, die `agent-audit` bereits hat und McpFrisk
fehlen: Baseline-/Diff-Scanning, SARIF-Output (GitHub Code Scanning) und eine
offizielle, wiederverwendbare GitHub Action. Kein neuer Check, keine neue
Sicherheits-Erkennung — reine CI/UX-Infrastruktur auf Basis bestehender
Findings.

## Kontext / Motivation

**Wettbewerbs-Lücke (MARKET-RESEARCH.md §5-7, Stand Juni/Juli 2026):**
`agent-audit` (der reifste direkte Konkurrent) bietet bereits: (a) eine
offizielle GitHub Action mit SARIF-Upload in den GitHub-Security-Tab, und
(b) Baseline-Scanning (nur neue Findings zwischen Commits reporten). Beides
fehlt McpFrisk komplett — aktuell nur ein roher CI-Workflow im eigenen Repo,
kein SARIF, kein Baseline-Diffing. Das ist laut eigener Recherche (§7,
Priorität 2+3) der Bereich mit dem höchsten Aufwand/Nutzen-Verhältnis, bevor
neue Checks oder Tier 3 drankommen: *"Ohne das bleibt mcpfrisk für
GitHub-native Teams eine Stufe unbequemer in der Integration als die
Konkurrenz."*

**Warum das WICHTIG ist, nicht nur "nice to have":** ein CI-Gate, das bei
jedem Lauf ALLE historischen Findings erneut zeigt, ist in der Praxis
unbrauchbar für Teams mit bestehendem Code (sie können nicht jeden bekannten,
akzeptierten Befund bei jedem PR neu abarbeiten) — das ist der Punkt, an dem
ein Scanner entweder ignoriert oder deaktiviert wird. Baseline-Diffing ist
damit keine Kosmetik, sondern Voraussetzung für echten CI-Alltagseinsatz.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Nur neue Findings blockieren den Build (Priority: P1)

Als Team mit bestehendem Code möchte ich, dass ein CI-Gate nur NEUE Findings
(seit dem letzten akzeptierten Stand) blockierend behandelt, nicht bereits
bekannte/akzeptierte Alt-Befunde.

**Why this priority**: ohne das ist McpFrisk für jedes Repo mit
Bestandscode praktisch unbenutzbar als hartes CI-Gate.

**Independent Test**: ein Scan mit `--write-baseline baseline.json` erzeugt
eine Baseline-Datei aus den aktuellen Findings. Ein zweiter Scan mit
`--baseline baseline.json` gegen denselben Code liefert 0 blockierende
Findings (alle bereits in der Baseline). Wird dem Code eine NEUE
Schwachstelle hinzugefügt, blockiert genau diese eine, alle anderen bleiben
non-blocking.

**Acceptance Scenarios**:

1. **Given** eine geschriebene Baseline-Datei, **When** derselbe Code erneut
   gescannt wird, **Then** 0 blockierende Findings (Exit-Code 0), aber die
   Findings werden weiterhin sichtbar als "bekannt/Baseline" ausgewiesen
   (Prinzip III: nie stillschweigend verschwinden lassen).
2. **Given** dieselbe Baseline, **When** eine neue Schwachstelle hinzukommt,
   **Then** genau diese blockiert (Exit-Code 1 bei Erreichen des
   `--fail-on`-Schwellenwerts), die bekannten Alt-Findings weiterhin nicht.
3. **Given** keine Baseline-Datei existiert am angegebenen Pfad, **When**
   `--baseline` verwendet wird, **Then** wird das wie eine leere Baseline
   behandelt (alle Findings gelten als neu) — kein Fehler, kein Crash.

---

### User Story 2 — SARIF-Output für GitHub Code Scanning (Priority: P2)

Als GitHub-natives Team möchte ich McpFrisk-Findings direkt im
GitHub-Security-Tab sehen (Code-Zeilen-Annotationen), nicht nur im
Terminal/JSON.

**Why this priority**: Standard-Erwartung für GitHub-native Teams;
`agent-audit` bietet das bereits.

**Independent Test**: `mcpfrisk scan ./server --sarif results.sarif`
erzeugt eine Datei, die dem SARIF-2.1.0-Schema entspricht (gültiges JSON,
`runs[0].tool.driver.name == "mcpfrisk"`, ein `result` pro Finding mit
korrekter `ruleId`, `level` und `physicalLocation`).

**Acceptance Scenarios**:

1. **Given** ein Scan mit Findings, **When** `--sarif <path>` gesetzt ist,
   **Then** wird eine valide SARIF-2.1.0-Datei geschrieben, mit einem
   `result`-Eintrag pro Finding (Severity → SARIF-`level`-Mapping:
   CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`).
2. **Given** ein Scan ohne Findings, **When** `--sarif <path>` gesetzt ist,
   **Then** wird eine valide SARIF-Datei mit leerem `results`-Array
   geschrieben (kein Crash, kein fehlendes File).
3. **Given** ein Finding ohne `file_path`/`line_number` (kommt bei Tier-1-
   Checks praktisch nie vor, aber defensiv), **When** SARIF geschrieben
   wird, **Then** wird das Finding ohne `physicalLocation` aufgenommen statt
   zu crashen.

---

### User Story 3 — Eine offizielle, wiederverwendbare GitHub Action (Priority: P3)

Als Nutzer:in möchte ich McpFrisk mit einer Zeile in meine
GitHub-Actions-Pipeline einbinden (`uses: Imre7777/mcpfrisk@v1`), ohne
manuell Python-Setup + pip install + Kommandozeile zu konfigurieren.

**Why this priority**: senkt die Integrationshürde auf das Niveau der
Konkurrenz; niedrigste Priorität der drei, weil sie auf US1+US2 aufbaut
(Baseline + SARIF müssen zuerst existieren, damit die Action sie nutzen kann).

**Independent Test**: `action.yml` im Repo-Root ist eine gültige Composite
Action (`using: composite`), die Python einrichtet, McpFrisk aus dem
Action-Checkout selbst installiert (kein PyPI-Release nötig), scannt, SARIF
hochlädt und den Build-Status korrekt widerspiegelt.

**Acceptance Scenarios**:

1. **Given** ein Repo, das `uses: Imre7777/mcpfrisk@<ref>` mit `path`-Input
   referenziert, **When** der Workflow läuft, **Then** wird McpFrisk aus dem
   Action-eigenen Checkout installiert (`${{ github.action_path }}`), nicht
   aus PyPI (dort noch nicht veröffentlicht).
2. **Given** Findings über dem `fail-on`-Schwellenwert, **When** die Action
   läuft, **Then** wird das SARIF-Ergebnis TROTZDEM hochgeladen (bevor der
   Job als fehlgeschlagen markiert wird) — ein fehlgeschlagener Scan darf
   den Security-Tab nicht leer lassen.

---

### Edge Cases

- **Baseline-Datei ist beschädigt/kein valides JSON**: wird wie eine leere
  Baseline behandelt (alle Findings neu), kein Crash (Prinzip III).
- **Baseline über verschiedene Maschinen/CI-Runner hinweg**: Fingerprints
  verwenden Pfade RELATIV zum Scan-Ziel, nicht absolute Pfade — sonst wäre
  jede Baseline nur auf der Maschine gültig, auf der sie erzeugt wurde.
- **`--baseline` und `--write-baseline` gleichzeitig**: erlaubt (liest die
  alte Baseline für den Vergleich dieses Laufs, schreibt danach die neue —
  nützlich zum "Baseline aktualisieren nach Review").
- **SARIF für Tier-2-Findings (dynamische Checks)**: bewusst NICHT
  angeboten — SARIF/GitHub Code Scanning ist auf Datei+Zeile im Repo
  ausgelegt; Tier-2-Findings haben keinen natürlichen Repo-Ort. `--sarif`
  bleibt ein `scan`-only-Flag.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Es MUSS einen stabilen, Maschinen-/Pfad-unabhängigen
  Fingerabdruck pro Finding geben (check_id + Pfad relativ zum Scan-Ziel +
  Zeile + Titel), der über mehrere Läufe hinweg für dasselbe Finding gleich
  bleibt.
- **FR-002**: `mcpfrisk scan` MUSS `--write-baseline PATH` unterstützen (schreibt
  die Fingerabdrücke der aktuellen Findings) und `--baseline PATH` (lädt eine
  vorhandene Baseline und trennt Findings in "neu" vs. "bekannt").
- **FR-003**: Nur "neue" Findings DÜRFEN in die `--fail-on`-Schwellenwert-
  Prüfung einfließen; "bekannte" Findings MÜSSEN weiterhin sichtbar bleiben
  (im Terminal-Report separat ausgewiesen, im JSON-Report als eigenes Feld),
  NIEMALS kommentarlos verschwinden.
- **FR-004**: Eine fehlende oder nicht parsebare Baseline-Datei MUSS wie eine
  leere Baseline behandelt werden (kein Fehler, kein Crash).
- **FR-005**: `mcpfrisk scan` MUSS `--sarif PATH` unterstützen und eine valide
  SARIF-2.1.0-Datei schreiben (ein `result` pro Finding, Severity→level-
  Mapping, `physicalLocation` wenn Datei+Zeile bekannt).
- **FR-006**: Es DARF KEINE neue Laufzeit-Abhängigkeit für Baseline/SARIF
  entstehen (stdlib-only: `hashlib`, `json`).
- **FR-007**: Es MUSS eine `action.yml` (Composite Action) im Repo-Root
  geben, die McpFrisk aus dem eigenen Action-Checkout installiert (kein
  PyPI-Release vorausgesetzt), scannt, SARIF hochlädt und den Build-Status
  korrekt widerspiegelt (SARIF-Upload auch bei fehlgeschlagenem Scan).
- **FR-008**: Baseline-Unterstützung MUSS auch für `mcpfrisk probe`
  angeboten werden (dieselbe Fingerprint-/Split-Logik, `Finding` ist der
  gemeinsame Typ für Tier 1 und Tier 2) — konsistente CLI-Oberfläche.

### Key Entities

- **Baseline-Datei**: JSON `{"version": 1, "fingerprints": [str, ...]}`.
- **Fingerprint**: `sha256(check_id|relativer_pfad|zeile|titel)[:16]`.
- **SARIF-Report**: SARIF-2.1.0-JSON, ein `run` mit `tool.driver` (Name,
  Version, `rules`) und `results` (ein Eintrag pro Finding).

## Success Criteria *(mandatory)*

- **SC-001**: Ein Baseline-Workflow (schreiben → gleicher Scan → 0 neue
  Findings → neue Schwachstelle → genau 1 neues Finding) funktioniert
  nachweislich per Test.
- **SC-002**: Eine erzeugte SARIF-Datei ist valides JSON mit der erwarteten
  Struktur (Rules, Results, Severity-Mapping) für sowohl "Findings vorhanden"
  als auch "keine Findings".
- **SC-003**: `action.yml` ist syntaktisch valides YAML und installiert
  McpFrisk nachweislich aus dem eigenen Checkout (kein PyPI-Zwang).
- **SC-004**: Keine Regression; Basis-Install bleibt dependency-frei.

## Assumptions

- Baseline-Dateien werden vom Team ins Repo eingecheckt (wie eine
  `.gitignore`-artige Allowlist), nicht in einem externen Service verwaltet.
- Der exakte Snippet-Text fließt bewusst NICHT in den Fingerprint ein
  (kleine Formatierungsänderungen dürfen den Fingerprint nicht kippen) —
  check_id + Pfad + Zeile + Titel identifizieren praktisch immer denselben
  Befund.
- Out of scope (entschieden): SARIF für Tier-2/dynamische Findings (kein
  natürlicher Repo-Ort); ein Baseline-Diff über Git-Commits hinweg (das wäre
  eine andere, git-abhängige Methodik — hier bewusst git-frei, stdlib-only);
  Veröffentlichung auf PyPI (separates, nicht-technisches Vorhaben).
