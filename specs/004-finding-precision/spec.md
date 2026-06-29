# Feature Specification: Befund-Präzision (Finding Precision)

**Feature Branch**: `004-finding-precision`

**Created**: 2026-06-29

**Status**: Draft

**Input**: User description: "Aus dem Fazit der Real-Repo-Validierung ein Feature
machen und umsetzen, bevor es weitergeht."

## Kontext / Motivation

Die Validierung von McpFrisk gegen echte öffentliche MCP-Server-Repos
(`modelcontextprotocol/servers`, `egoist/fetch-mcp`, `modelcontextprotocol/python-sdk`)
hat **nicht** falsche Stille (False Negatives) zutage gefördert, sondern drei
*Präzisions*-Schwächen, die die Triage der Findings unnötig teuer machen:

1. **Überzogene Severity** bei `CMD_INJECTION`: `subprocess.run([cmd, "--version"], shell=True)`
   wurde als **CRITICAL** gemeldet, obwohl der Befehl eine konstante Argument-Liste
   ist (kein interpolierter String) — das `shell=True` ist redundant/irreführend,
   aber kein direkter RCE-Pfad. Laut Rubrik (Prinzip V) ist das höchstens MEDIUM.
2. **Abgeschnittene Belege**: Bei mehrzeiligen Aufrufen zeigte das Snippet nur die
   erste physische Zeile (`process = subprocess.run(`) statt des vollständigen
   Aufrufs — das untergräbt Prinzip V (jedes Finding braucht ein verwertbares Snippet).
3. **Fehlender Triage-Kontext** bei `PATH_TRAVERSAL`: Das Taint-Tracking ist bewusst
   intra-prozedural. Beim `filesystem`-Server (der über eine *separate* Funktion
   `validatePath()` korrekt absichert) erzeugte das 8 Findings, ohne den Reviewer
   darauf hinzuweisen, dass im selben Modul eine Validierungsfunktion existiert.

**Leitplanke (NON-NEGOTIABLE):** Dieses Feature darf **kein** Finding unterdrücken
oder herunterstufen-bis-zur-Unsichtbarkeit und **keine** Pfade ausschließen
(Constitution Prinzip III „False Positives over False Negatives" + „Conservative
excludes: never exclude paths merely because they contain 'test'"). Es verbessert
ausschließlich *Severity-Genauigkeit*, *Beweis-Qualität* und *Triage-Kontext*.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Akkurate Command-Injection-Severity (Priority: P1)

Als Server-Autor:in möchte ich, dass eine konstante Argument-Liste mit redundantem
`shell=True` nicht als CRITICAL, sondern als das gemeldet wird, was sie ist (ein
Best-Practice-Verstoß), damit echte RCE-CRITICALs nicht im Rauschen untergehen.

**Why this priority**: Severity steuert das CI-Gate (`--fail-on`). Eine falsche
CRITICAL kann einen Build grundlos blockieren und die Glaubwürdigkeit des Tools
untergraben. Höchster Hebel bei geringstem Risiko.

**Independent Test**: Fixture mit `subprocess.run([cmd], shell=True)` scannen →
genau ein CMD_INJECTION-Finding mit Severity **MEDIUM** (nicht CRITICAL). Fixture
mit `subprocess.run(f"... {x}", shell=True)` bleibt **CRITICAL**.

**Acceptance Scenarios**:

1. **Given** ein Aufruf `subprocess.run([cmd, "--version"], shell=True)`, **When**
   gescannt wird, **Then** ist die Severity MEDIUM und der Befund wird weiterhin
   gemeldet (nicht unterdrückt).
2. **Given** ein Aufruf `subprocess.run(f"git {arg}", shell=True)`, **When**
   gescannt wird, **Then** bleibt die Severity CRITICAL (keine Regression).
3. **Given** `subprocess.run(['ls','-la'])` ohne `shell=True`, **When** gescannt
   wird, **Then** kein Finding (keine Regression).

---

### User Story 2 - Vollständige Beleg-Snippets (Priority: P2)

Als Reviewer:in möchte ich bei einem mehrzeiligen verdächtigen Aufruf den
*vollständigen* Aufruf im Snippet sehen, nicht nur die erste Zeile, damit ich
das Finding ohne Sprung in die Datei beurteilen kann.

**Why this priority**: Direkt an Prinzip V (Evidence-Grounded). Verbessert jede
Call-basierte Finding-Ausgabe, ohne Detektionslogik zu ändern.

**Independent Test**: Fixture mit einem über mehrere Zeilen umgebrochenen
gefährlichen Aufruf scannen → das Snippet enthält Callee **und** das relevante
Argument in einer kompakten Zeile.

**Acceptance Scenarios**:

1. **Given** ein über 3 Zeilen umgebrochener `subprocess.run(...)`-Aufruf, **When**
   gescannt wird, **Then** enthält das Snippet sowohl `subprocess.run` als auch das
   interpolierte Argument (Whitespace zu Einzelspaces kollabiert, gedeckelt).
2. **Given** ein einzeiliger Aufruf, **When** gescannt wird, **Then** bleibt das
   Snippet semantisch unverändert (keine Regression der bestehenden Tests).

---

### User Story 3 - Triage-Kontext bei separater Pfad-Validierung (Priority: P3)

Als Reviewer:in eines Servers, der Pfade in einer *eigenen* Funktion validiert
(z.B. `validatePath()`), möchte ich, dass ein PATH_TRAVERSAL-Finding mich darauf
hinweist, dass im selben Modul eine Validierungsfunktion existiert — damit ich
einen wahrscheinlichen False Positive in Sekunden statt Minuten einordnen kann.

**Why this priority**: Adressiert die häufigste FP-Quelle der Validierung
(inter-prozedurale Validierung), **ohne** das Finding zu unterdrücken — der
Hinweis macht den Reviewer handlungsfähig (Prinzip III), die Severity bleibt HIGH.

**Independent Test**: Modul mit `validatePath()` + separater datei-öffnender
Funktion (tainted Param, keine eigene Validierung) scannen → Finding feuert
weiterhin (HIGH) **und** die Beschreibung nennt die Validierungsfunktion als
Triage-Hinweis. Ein Modul ohne solche Funktion erhält keinen Hinweis.

**Acceptance Scenarios**:

1. **Given** ein Modul mit einer Funktion, deren Körper `realpath`/`resolve`/
   `startsWith` enthält, plus eine andere Funktion, die einen tainted Pfad ohne
   eigene Validierung öffnet, **When** gescannt wird, **Then** feuert das
   PATH_TRAVERSAL-Finding (Severity HIGH) und die Beschreibung enthält einen
   Hinweis inkl. Name der Validierungsfunktion.
2. **Given** ein Modul ohne jede Validierungsfunktion, **When** gescannt wird,
   **Then** feuert das Finding ohne Zusatz-Hinweis (kein irreführender Kontext).
3. **Given** der saubere Fixture-Server (Validierung in derselben Funktion),
   **When** gescannt wird, **Then** weiterhin kein Finding (keine Regression).

---

### Edge Cases

- **Array mit interpoliertem ersten Element** (`subprocess.run([f"sh -c {x}"], shell=True)`):
  bleibt sichtbar (mindestens MEDIUM), da FP > FN — wird nicht stillgelegt.
- **Sehr langer Aufruf** (viele Argumente/Zeilen): Snippet wird auf eine maximale
  Länge gedeckelt und mit `…` abgeschlossen, statt den Report zu fluten.
- **Validierungs-Hinweis-Wort nur im Kommentar** einer anderen Funktion: wird
  durch Kommentar-Stripping ignoriert (bestehende Lesson-Learned-Regel gilt auch
  für die Modul-Ebene), damit kein irreführender „es existiert Validierung"-Hinweis
  entsteht.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Das System MUSS einen `subprocess`-Aufruf, dessen erstes Argument eine
  Argument-Liste/-Tupel ist UND der `shell=True` setzt, als **MEDIUM** melden
  (statt CRITICAL), mit einer Beschreibung, die das redundante `shell=True` benennt.
- **FR-002**: Das System MUSS interpolierte Shell-Befehle mit `shell=True`
  weiterhin als **CRITICAL** melden (keine Abschwächung des echten RCE-Pfads).
- **FR-003**: Das System MUSS für Call-basierte Findings ein Snippet liefern, das
  den vollständigen Aufruf abbildet (über Zeilengrenzen hinweg), Whitespace zu
  Einzelspaces kollabiert und auf eine konfigurierte Maximallänge deckelt.
- **FR-004**: Das System MUSS bei einem PATH_TRAVERSAL-Finding, wenn im selben
  Modul eine *andere* Funktion mit erkennbarer Pfad-Validierung existiert, einen
  Triage-Hinweis (inkl. Funktionsname) an die Finding-Beschreibung anhängen.
- **FR-005**: Das System DARF KEIN Finding unterdrücken, herunterstufen bis zur
  CI-Unsichtbarkeit, oder Pfade ausschließen, um Präzision zu erreichen
  (Prinzip III + Conservative-excludes). Alle Änderungen sind additiv/kalibrierend.
- **FR-006**: Bestehende Snippet-Garantien MÜSSEN erhalten bleiben — insbesondere
  die Secret-Redaction (`HARDCODED_SECRETS` zeigt nie den Klartext).

### Key Entities

- **CallSite.snippet**: der serialisierte Beleg eines Aufrufs; künftig mehrzeilen-fähig.
- **Finding.severity**: kalibriert gemäß Rubrik (Prinzip V).
- **Finding.description**: Träger des optionalen Triage-Hinweises (US3).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Beim Scan von `modelcontextprotocol/python-sdk` wird das
  `subprocess.run([cmd,"--version"], shell=True)` in `cli.py` als MEDIUM statt
  CRITICAL gemeldet (verifizierbar am JSON-Report).
- **SC-002**: Kein einziger der 68 bestehenden Tests bricht (keine Regression);
  die Suite bleibt grün über Python 3.10–3.12.
- **SC-003**: Beim Scan von `modelcontextprotocol/servers` tragen die
  PATH_TRAVERSAL-Findings im `filesystem`-Server einen Hinweis auf die
  `validatePath`-Funktion — die Anzahl der Findings bleibt aber unverändert
  (nichts unterdrückt).
- **SC-004**: Mehrzeilige Aufrufe erscheinen mit vollständigem, gedeckeltem Snippet.

## Assumptions

- Die Verbesserung bleibt rein statisch (Tier 1), stdlib-only, kein neuer Dep.
- „Validierungsfunktion" wird heuristisch über die bestehenden
  `SAFE_VALIDATION_HINTS` erkannt (keine vollständige Datenfluss-Analyse) — der
  Hinweis ist bewusst als *Triage-Hilfe*, nicht als Beweis formuliert.
- Snippet-Maximallänge: 200 Zeichen (kompromiss zwischen Vollständigkeit und
  Report-Lesbarkeit), bei Überschreitung mit `…` gekürzt.
