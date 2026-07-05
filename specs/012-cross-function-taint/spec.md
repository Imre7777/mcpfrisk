# Feature Specification: Cross-Function-Taint für PATH_TRAVERSAL (Tier 1)

**Feature Branch**: `012-cross-function-taint`

**Created**: 2026-07-05

**Status**: IMPLEMENTIERT (2026-07-05). PATH_TRAVERSAL erweitert; volle Suite grün (193/193).

**Input**: Zweiter der beiden "neue Checks"-Backlog-Punkte (MARKET-RESEARCH.md
§6.1). KEIN neuer Check, sondern eine Erkennungs-Tiefe-Erweiterung von
`PATH_TRAVERSAL`: Taint-Verfolgung über EINE Funktionsgrenze hinweg innerhalb
derselben Datei. Kontert direkt die vom härtesten direkten Konkurrenten
(`agent-audit`) selbst dokumentierte Schwäche ("nur intra-procedural, kein
Cross-Function-Tracking").

## Kontext / Motivation

**Wettbewerbs-Lücke (MARKET-RESEARCH.md §2.1/§6.1):** `agent-audit` gibt offen
zu, nur **intra-procedural** zu tainten -- ein Datenfluss über Funktionsgrenzen
wird nicht erkannt. McpFrisk hat aktuell dieselbe Grenze. Wer sie schließt
(auch nur eine Ebene tief), hat einen konkreten, benchmarkbaren Vorteil in
exakt der Dimension, die der Konkurrent als eigene Schwäche benennt.

**Empirisch bestätigter Scope (2026-07-05):** Eine Verifikation zeigte, dass
die Cross-Function-Lücke **nur `PATH_TRAVERSAL`** real betrifft:
- `PATH_TRAVERSAL`: `read_file(filename) → _load(filename) → open(x)` wird
  **nicht** erkannt, sobald der Helper-Parameter nicht zufällig pfad-artig
  benannt ist -- die Quelle (pfad-artiger Tool-Parameter) und der Sink
  (`open()`) liegen in verschiedenen Funktionen. Echte False Negatives.
- `CMD_INJECTION`: **keine** reale Lücke -- sein Gefahrensignal (`shell=True`
  bzw. interpolierter Befehl) sitzt IMMER am Sink selbst; es flaggt den Helper
  direkt, unabhängig von der Argument-Herkunft. `subprocess.run(x)` ohne
  `shell=True` ist keine Shell-Injection (korrekt kein Finding). Daher wird
  `CMD_INJECTION` bewusst NICHT verändert.

**Was neu erkannt wird:** ein pfad-artiger Tool-Parameter einer Funktion F,
der an einen im **selben Modul** definierten Helper H **weitergereicht** wird
(positional oder als Keyword-Argument), wobei H den (so getainteten) Wert ohne
erkennbare Validierung an eine datei-öffnende Funktion (`open`, `fs.readFile`,
…) gibt. Genau der "dünne Wrapper-Helper"-Fall, der in echtem Code extrem
häufig ist.

**OWASP/CWE:** unverändert `PATH_TRAVERSAL` -- OWASP **MCP05**, **CWE-22**.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Taint über einen Helper-Aufruf (positional) (Priority: P1)

Als Server-Autor:in möchte ich, dass ein Path-Traversal auch dann erkannt
wird, wenn der pfad-artige Parameter über einen Helper-Aufruf an den `open()`-
Sink gelangt (nicht alles in einer Funktion steht).

**Why this priority**: der Kernfall der Erweiterung; schließt die dokumentierte
Konkurrenz-Lücke.

**Independent Test**: verwundbarer Fixture -- `read_file(filename)` ruft
`_load(filename)` (Param NICHT pfad-artig benannt, z.B. `x`), `_load` macht
`open(x)` ohne Validierung → 1 Finding (HIGH), das den Sink in `_load` verortet
und den Fluss (F-Parameter → H-Parameter → Sink) beschreibt. Sauberer Fixture
(Helper validiert vor `open`) → kein Finding.

**Acceptance Scenarios**:

1. **Given** F mit pfad-artigem Parameter, der positional an Helper H
   weitergereicht wird, und H öffnet ihn ohne Validierung, **When** der Check
   läuft, **Then** 1 Finding (HIGH) am Sink in H, mit Fluss-Beschreibung.
2. **Given** derselbe Fluss, aber H validiert den Pfad (realpath/is_relative_to/
   startsWith) vor `open`, **When** der Check läuft, **Then** kein Finding.

---

### User Story 2 — Taint über ein Keyword-Argument (Python) (Priority: P2)

Als Server-Autor:in möchte ich, dass die Cross-Function-Verfolgung auch greift,
wenn der Wert als **Keyword-Argument** weitergereicht wird (`_load(path=filename)`).

**Why this priority**: gängige Python-Aufrufform; ohne sie bliebe eine offen-
sichtliche Umgehung.

**Independent Test**: `_load(target=filename)` → H's Parameter `target` gilt als
getaintet → Finding. Wird das Keyword an einen ANDEREN, nicht getainteten
Parameter gebunden → dieser Sink bleibt befundfrei.

**Acceptance Scenarios**:

1. **Given** F reicht den pfad-artigen Wert als Keyword `name=filename` an H,
   **When** H's Parameter `name` an `open()` fließt, **Then** 1 Finding (HIGH).

---

### User Story 3 — Keine False Positives / keine Doppelmeldung (Priority: P3)

Als Nutzer:in möchte ich, dass die Erweiterung keine neuen Fehlalarme erzeugt
und einen Sink nicht doppelt (intra + cross) meldet.

**Acceptance Scenarios**:

1. **Given** ein Helper, der einen NICHT getainteten (konstanten/eigenen)
   Wert öffnet, **When** der Check läuft, **Then** kein Cross-Function-Finding.
2. **Given** ein Sink, den bereits die bestehende intra-prozedurale Logik
   meldet (Helper-Param IST pfad-artig), **When** der Check läuft, **Then**
   wird dieser Sink NICHT zusätzlich als Cross-Function-Finding gemeldet
   (Dedup nach Sink-Fundstelle Datei:Zeile).
3. **Given** ein Fluss, der ZWEI Funktionsebenen tief ist (F → G → H → Sink),
   **When** der Check läuft, **Then** ist das (v1) nicht abgedeckt -- bewusste,
   dokumentierte Grenze (eine Ebene). Kein falscher Anspruch, kein Crash.

---

### Edge Cases

- **Helper ist eine Arrow-Function-Konstante (JS/TS)** (`const _load = (x) => …`):
  deren Name wird vom Port aktuell nicht erfasst -- daher (v1) nicht als Ziel
  eines Cross-Function-Flusses auflösbar. Dokumentierte Grenze; benannte
  Funktionen (`function _load(x)` / Python `def`) werden erfasst.
- **Rekursion / Selbstaufruf**: eine Ebene Propagation → keine Endlosschleife.
- **Mehrere Funktionen gleichen Namens im Modul**: seltener Randfall; letzte
  Definition gewinnt (Laufzeit-Semantik von Python) -- akzeptabel für v1.
- **Sink im Helper mit Validierung**: der Helper-Körper wird (wie intra) auf
  `SAFE_VALIDATION_HINTS` geprüft; validiert er, kein Finding.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `PATH_TRAVERSAL` MUSS Taint EINE Funktionsgrenze weit verfolgen:
  ein pfad-artiger Parameter (bzw. ein daraus intra-prozedural getainteter
  Wert) einer Funktion F, der an einen im **selben Modul** definierten Helper
  H weitergereicht wird, MUSS H's entsprechenden Parameter als getaintet
  behandeln.
- **FR-002**: Die Bindung MUSS **positional** (Argument-Position → Parameter-
  Position) UND per **Keyword** (Python `name=wert` → Parameter `name`)
  erfolgen.
- **FR-003**: Erreicht der so getaintete Helper-Parameter (bzw. ein daraus
  intra-H getainteter Wert) eine datei-öffnende Funktion ohne erkennbare
  Validierung im Helper-Körper, MUSS ein Finding (Severity HIGH, CWE-22)
  entstehen, das den Sink in H verortet und den Fluss (F→H→Sink) beschreibt.
- **FR-004**: Ein Sink DARF nicht doppelt gemeldet werden -- Dedup nach
  Fundstelle (Datei:Zeile). Die bestehende intra-prozedurale Meldung hat
  Vorrang.
- **FR-005**: Ein Helper, der den Wert vor dem Öffnen validiert, MUSS
  befundfrei bleiben (keine neuen FP).
- **FR-006**: Die Erweiterung DARF KEINE neue `SourceModel`-Port-Fähigkeit und
  KEINE neue Dependency einführen (nutzt vorhandene `callee`/`args`/`keywords`/
  `params`/`body_calls`/`body_text`). stdlib-only.
- **FR-007**: Die Verfolgung ist auf EINE Ebene begrenzt (F→H). Tiefere Ketten
  sind v1 out of scope -- die Grenze wird in Doku/Finding-Kontext transparent.
- **FR-008**: Funktioniert für Python UND JS/TS (benannte Helfer) über den
  gemeinsamen Port.

### Key Entities

- **Propagierter Taint**: Menge der Helper-Parameter-Namen, die durch einen
  getainteten Argument-Fluss aus F als getaintet gelten.

## Success Criteria *(mandatory)*

- **SC-001**: Der zuvor übersehene Cross-Function-Fluss (Helper-Param NICHT
  pfad-artig benannt) erzeugt jetzt ein HIGH-Finding; ein validierender Helper
  bleibt befundfrei -- Python UND JS/TS (paired fixtures).
- **SC-002**: Keine Doppelmeldung (intra + cross) desselben Sinks.
- **SC-003**: Keine Regression: alle bestehenden PATH_TRAVERSAL-Tests
  (intra-prozedural, Triage-Hinweis, clean-Server) bleiben grün; die
  bestehenden Finding-Zahlen ändern sich nicht unerwartet.
- **SC-004**: Keine neue Port-Fähigkeit/Dependency; Basis-Install bleibt
  dependency-frei.

## Assumptions

- `functions()` liefert für Python-`def` und JS/TS-`function`-Deklarationen
  Name + Parameter + `body_calls`; `CallSite` trägt `args` (positional) und
  `keywords`. Das genügt für die Bindung (empirisch bestätigt).
- Out of scope (entschieden): Cross-MODULE-Taint (Helper aus anderer Datei --
  bräuchte Import-/Modulauflösung, die der Port nicht hat); mehr als eine
  Ebene; Arrow-Function-Konstanten als Helper-Ziel (Port erfasst deren Namen
  nicht); `CMD_INJECTION` (empirisch keine reale Lücke).
