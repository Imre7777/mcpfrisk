# Implementation Plan: SCHEMA_DOCSTRING_MISMATCH (016)

**Spec**: [`spec.md`](./spec.md) | **Status**: Design entschieden, in Implementierung (2026-07-10).

## Technical Context

Eine kleine **additive Port-Erweiterung** (`ToolDefinition.parameters`) plus ein
neuer statischer (Tier-1-)Check. stdlib-only (`re`), nutzt den bestehenden
`SourceModel`-Port (`tool_definitions()`, jetzt mit Parametern) und
`iter_source_files`. KEINE Check-zu-Check-Abhängigkeit.

- **Geänderte Dateien (Port, additiv)**:
  - `mcpfrisk/core/sourcetree/model.py` — `ToolDefinition.parameters:
    list[str] = field(default_factory=list)`.
  - `mcpfrisk/core/sourcetree/python_ast.py` — Signatur-Parameter je Tool
    (args + kwonlyargs, framework-injizierte ausgefiltert).
  - `mcpfrisk/core/sourcetree/treesitter.py` — Parameter aus dem Schema-/
    `inputSchema`-Objekt des `tool(...)`/`registerTool(...)`-Aufrufs.
- **Neue Dateien**:
  - `mcpfrisk/checks/schema_docstring_mismatch.py` — der Check.
  - `tests/fixtures/jsts/` ggf. ein Schema-Fixture (sonst inline).
  - `tests/test_schema_docstring_mismatch.py`.
- **Geändert (Registry)**: `mcpfrisk/checks/registry.py` (ein `STATIC_CHECKS`-
  Eintrag).
- **KEINE** Änderung an anderen Checks; die Port-Erweiterung ist rückwärts-
  kompatibel (Default `[]`).

## Architektur-Entscheidungen

1. **Port-Erweiterung ist additiv.** `parameters` bekommt `default_factory=list`.
   Alle bestehenden `ToolDefinition(name, description, line)`-Konstruktionen
   (beide Adapter) bleiben gültig; kein Check und `tool_baseline` müssen sich
   ändern. Der Snapshot in `tool_baseline` hasht weiterhin NUR die Beschreibung
   → kein Baseline-Format-Bruch.
2. **Python-Parameter = Signatur.** Für ein `@mcp.tool`-dekoriertes
   `FunctionDef` sind die modell-befüllten Parameter die Funktionsargumente
   (`args` + `kwonlyargs`). Framework-Injektionen (`self`, `cls`, `ctx`,
   `context`) werden ausgefiltert — sie sind keine Schema-Felder.
3. **JS/TS-Parameter = Schema-Objekt-Keys.** Im `tool(name, desc, schema,
   handler)`/`registerTool(name, {description, inputSchema})`-Aufruf ist das
   Schema entweder (a) das Objekt-Argument, dessen Keys KEINE Metadaten-Keys
   (`description`/`name`/`title`/`annotations`) sind (rohes Zod-Objekt), oder
   (b) die `inputSchema`-Property eines Metadaten-Objekts. Die Top-Level-Keys
   dieses Objekts sind die Parameter-Namen. Verschachtelte/importierte Schemata
   sind out of scope (nur inline sichtbares Schema).
4. **Doppeltes Signal, damit FP-arm (Prinzip III).** Ein Parameter wird NUR
   geflaggt, wenn er (a) einem strengen sensiblen Namensmuster entspricht UND
   (b) in der Beschreibung nicht erwähnt wird. Reiner Zahlen-Mismatch ist
   bewusst out of scope.
5. **"Erwähnt" ist token-tolerant.** Der Parameter gilt als dokumentiert, wenn
   sein Roh-Name ODER eines seiner Wort-Token (Split an `_`/CamelCase, z.B.
   `api_key` → {api, key}) case-insensitiv in der Beschreibung vorkommt. Das
   verhindert FP bei geringfügig anderer Schreibweise in der Prosa.
6. **Ein Finding pro (Tool, sensibler undokumentierter Parameter).** Klarer,
   einzeln behebbarer Beleg; Severity HIGH (realistischer Exfiltrations-Pfad
   unter Auto-Approval).

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Tests zuerst (rot), dann Port/Check/Registry. |
| II. Plugin Isolation | ✅ | Neue Check-Datei + ein Registry-Eintrag; kein Fremd-Check-Import. Port bleibt check-agnostisch. |
| III. FP over FN | ✅ | Doppeltes Signal (sensibel + undokumentiert); token-tolerantes "erwähnt"; nicht-sensible/injizierte Parameter ignoriert; ohne Schema keine Aussage. |
| IV. Zero Unnecessary Deps | ✅ | stdlib `re`. |
| V. Evidence-Grounded | ✅ | Finding nennt Tool + konkreten Parameter-Namen + Datei/Zeile aus tool_definitions. |
| VI. Paired Fixture Testing | ✅ | vuln (sensibel+undokumentiert) UND clean (dokumentiert / nicht-sensibel) je Python + JS/TS. |
| VII. Security-Research Currency | ✅ | Frischer Research-Pass (Full-Schema-Poisoning / Advanced Tool Poisoning, MSB Out-of-Scope-Parameter) in spec.md. |

**Gate-Ergebnis: PASS.**

## Test Strategy (TDD, Prinzip I & VI)

`tests/test_schema_docstring_mismatch.py`:
- Port zuerst: ein Test, dass `analyze(py).tool_definitions()[0].parameters`
  die Signatur-Parameter (ohne `self`/`ctx`) liefert und der JS/TS-Adapter die
  Schema-Keys — der macht die Port-Erweiterung rot, bevor der Check existiert.
- US1 (Python): sensibler undokumentierter Parameter → 1 HIGH (Tool+Parameter
  genannt); derselbe in der Beschreibung erwähnt → 0; nur nicht-sensible
  Parameter → 0.
- US2 (JS/TS): `server.tool(name, desc, { url, session_token }, handler)` →
  1 HIGH; `registerTool(name, {description, inputSchema:{...}})`-Form ebenso;
  dokumentiert → 0.
- US3: Tool ohne extrahierbare Parameter → 0; `ok=False`-Datei → übersprungen;
  `self`/`ctx` nie geflaggt; leere Beschreibung + sensibler Parameter → 1.
- Regression: Integrationstest `test_all_static_checks_actually_run` bekommt den
  neuen Check; bestehende Suite unverändert grün; `tool_baseline`-Round-Trip
  unverändert (Beschreibungs-Hash nur).

Reihenfolge: Tests (rot) → `model.py`-Feld → `python_ast.py`-Parameter →
`treesitter.py`-Parameter → `checks/schema_docstring_mismatch.py` → Registry →
volle Suite grün → Doku.

## Risiken / Restunsicherheiten

- **JS/TS-Schema-Erkennung**: Die Metadaten-vs-Schema-Heuristik (Keys
  `description`/`name`/`title`/`annotations` = Metadaten) deckt die geläufigen
  SDK-Formen ab; exotische/rein importierte Schemata bleiben unerkannt → dann
  keine Parameter → kein FP (nur ein FN, akzeptabel per Prinzip III).
- **Sensibles Muster zu breit/eng**: streng gehalten (kein nacktes `auth`/
  `session`, nur `auth_token`/`session_token`/`session_id`), um FP zu vermeiden;
  bewusst eher FN als FP.
- **Backward-Compat des Ports**: neues Feld mit Default `[]`; ein Regressionslauf
  der vollen Suite belegt, dass `TOOL_POISONING`/`TOOL_NAME_COLLISION`/
  `tool_baseline` unverändert bleiben.
