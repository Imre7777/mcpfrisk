# Implementation Plan: TOOL_NAME_COLLISION (011-tool-name-collision)

**Spec**: [`spec.md`](./spec.md) | **Status**: IMPLEMENTIERT (2026-07-05).

## Technical Context

Neuer statischer (Tier-1-)Check über `BaseCheck`, rein auf dem bestehenden
`SourceModel`-Port (`tool_definitions()` liefert Name+Datei+Zeile) -- keine
neue Port-Fähigkeit, keine neue Dependency. "Fast gratis" laut Review
(MARKET-RESEARCH.md-Audit).

- **Sprache/Runtime**: Python 3.10+, **stdlib-only** (eigene kleine
  Edit-Distanz-Funktion, kein `python-Levenshtein`).
- **Betroffene/neue Dateien**:
  - `mcpfrisk/checks/tool_name_collision.py` *(neu)* — der Check.
  - `mcpfrisk/checks/registry.py` — ein Eintrag in `STATIC_CHECKS`.
  - `tests/fixtures/` — verwundbare + saubere Fixtures (Py + JS/TS).
  - `tests/test_tool_name_collision.py` *(neu)*.
  - **KEINE** Änderung an `core/sourcetree/*` oder bestehenden Checks.

## Architektur-Entscheidungen

1. **Aggregation über alle Dateien im Check selbst.** Anders als die vier
   bestehenden Checks (die pro Datei arbeiten) braucht Kollisions-Erkennung
   den GESAMTEN Tool-Bestand des Scan-Ziels. `run(target_path)` iteriert
   `iter_source_files`, sammelt alle `ToolDefinition`s (Name+Datei+Zeile),
   und vergleicht sie danach global. Das bleibt innerhalb des `BaseCheck`-
   Vertrags (`run(target_path) -> list[Finding]`) -- keine Runner-Änderung.
2. **Exakt vs. near-duplicate als zwei getrennte Severities.** Exaktes
   Duplikat = MEDIUM (undefiniertes Client-Verhalten, plausibler Shadowing-
   Vektor). Near-duplicate = LOW (Confusion-Risiko, häufiger legitim). Das
   folgt der Severity-Rubrik (MEDIUM = Best-Practice-Verstoß ohne unmittelbaren
   Exploit; LOW = Stil/Confusion).
3. **Near-Duplicate-Heuristik konservativ (Prinzip III/V).** Ein Paar gilt als
   near-duplicate, wenn eines zutrifft: (a) Gleichheit nach Normalisierung
   (lowercase, `_`/`-`/Leerzeichen entfernt) -- fängt `send_mail`/`sendMail`/
   `send-mail`; (b) Edit-Distanz 1 auf den Rohnamen; (c) einer ist echtes
   Präfix des anderen UND beide ≥ 4 Zeichen UND der Rest ist kurz (≤ 2 Zeichen,
   z.B. `get_item`/`get_items` via Plural-`s`). Sehr kurze Namen (≤ 2 Zeichen)
   sind von der Near-Duplicate-Prüfung ausgenommen (Edit-Distanz 1 wäre dort
   fast immer erfüllt) -- exakte Duplikate weiterhin gemeldet.
4. **Jede Paarung genau einmal.** Kanonische Paar-Ordnung (sortierte
   Fundstellen) + ein `seen`-Set verhindert A-B/B-A-Doppelmeldung. Bei einem
   Namen mit 3+ exakten Vorkommen: ein Finding, das alle Fundstellen listet
   (nicht paarweise gesprengt).
5. **Fundstelle als Identität.** (Datei, Zeile) ist der Schlüssel gegen
   Doppelzählung; eine `ToolDefinition` an derselben Stelle zählt nie gegen
   sich selbst.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Fixtures + Tests zuerst (rot), dann Check. |
| II. Plugin Isolation | ✅ | Neue Datei + ein `STATIC_CHECKS`-Eintrag; kein bestehender Check/Port angefasst. |
| III. FP over FN | ✅ | Konservative Near-Duplicate-Heuristik; klar verschiedene Namen → kein Finding; Scope-Grenze (nur intra-repo) transparent. |
| IV. Zero Unnecessary Deps | ✅ | stdlib-only, eigene Edit-Distanz. |
| V. Evidence-Grounded | ✅ | Finding nennt beide konkreten Fundstellen (Datei:Zeile) + beide Namen. |
| VI. Paired Fixture Testing (NON-NEGOTIABLE) | ✅ | vulnerable (Duplikat/near) + clean (eindeutig) Fixture, Python UND JS/TS. |
| VII. Security-Research Currency | ✅ | Frischer Research-Pass (Invariant Labs Cross-Server-Shadowing, Akto MCP Attack Matrix, Mend.io Shadow MCP, MSB-Benchmark) in spec.md. |

**Gate-Ergebnis: PASS.**

## Test Strategy (TDD, Prinzip I & VI)

`tests/fixtures/` (neue kleine Fixture-Dateien, damit die bestehenden
vulnerable/clean-Server unberührt bleiben und deren Finding-Zahlen stabil):
- `collision_vuln.py` — zwei `@mcp.tool()`-Funktionen mit exakt gleichem Namen
  + ein Near-Duplicate-Paar.
- `collision_clean.py` — mehrere eindeutig benannte Tools (inkl. Tools, die
  ein gemeinsames Wort teilen aber klar verschieden sind: `list_users`,
  `create_user`).
- `tests/fixtures/jsts/collision_vuln.ts` + `collision_clean.ts` — dasselbe
  für `server.tool(...)`.

`tests/test_tool_name_collision.py`:
- US1: exaktes Duplikat (Py + JS/TS) → 1 MEDIUM-Finding, beide Fundstellen im
  Beleg; clean → 0.
- US2: near-duplicate (`get_item`/`get_items`, `sendMail`/`send_mail`) →
  1 LOW-Finding; klar verschieden → 0.
- US3: kein Tool → 0; gemeinsames Wort aber eindeutig → 0.
- FR-005: keine Doppelmeldung/Doppelzählung (3 exakte Vorkommen → 1 Finding,
  alle Fundstellen genannt).
- Regression: die bestehenden vulnerable/clean-Server erzeugen weiterhin
  KEINE TOOL_NAME_COLLISION-Findings (sie haben keine Kollisionen) -- die
  Gesamt-Finding-Zahlen anderer Tests bleiben stabil.

Reihenfolge: Fixtures+Tests (rot) → `checks/tool_name_collision.py` →
Registry → volle Suite grün → Doku.

## Risiken / Restunsicherheiten

- **Near-Duplicate-Schwellenwert-Kalibrierung**: zu locker → FP bei legitimen
  verwandten Tools (`get_user`/`get_users` sind evtl. bewusst beide da). Daher
  LOW (nicht MEDIUM) und konservative Regeln; der Finding-Text macht klar, dass
  das ein Review-Hinweis ist, kein harter Defekt.
- **Scope-Missverständnis**: Nutzer könnten erwarten, dass der Check
  Cross-Server-Shadowing findet -- der Finding-/Doku-Text stellt die
  Intra-Repo-Grenze explizit klar.
