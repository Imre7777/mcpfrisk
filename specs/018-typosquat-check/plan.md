# Implementation Plan: TYPOSQUAT_CHECK (018)

**Spec**: [`spec.md`](./spec.md) | **Status**: Design entschieden, in Implementierung (2026-07-12).

## Technical Context

Ein neuer statischer (Tier-1-)Check plus ein geteilter Nicht-Check-Helfer für
Namens-Distanz. stdlib-only (`json`, `re`, optional `tomllib`), nutzt
`rglob_or_file`/`DEFAULT_EXCLUDED_DIRS` aus `core/fs`. KEINE Check-zu-Check-
Abhängigkeit.

- **Neue Dateien**:
  - `mcpfrisk/checks/_name_similarity.py` — `damerau_le_1(a, b)` (geteilter
    Nicht-Check-Helfer, Präzedenz: `_dynamic_helpers.py`/`_ssrf_callback.py`).
  - `mcpfrisk/checks/typosquat.py` — der Check + kuratierte Allowlists +
    Manifest-Parser.
  - `tests/test_typosquat.py`.
- **Geändert**: `mcpfrisk/checks/registry.py` (ein `STATIC_CHECKS`-Eintrag).
- **KEINE** Änderung an anderen Checks (`tool_name_collision.py` behält seinen
  eigenen Levenshtein-Helfer — bewusst nicht refactored, um seine Tests nicht zu
  destabilisieren; die Helfer unterscheiden sich ohnehin: dort Levenshtein-≤1,
  hier Damerau-≤1).

## Architektur-Entscheidungen

1. **Kuratierte Allowlist als FP-Bremse (Prinzip III).** Kandidaten werden NUR
   gegen eine kleine, kuratierte Menge bekannter MCP-Pakete verglichen — nicht
   gegen das Ökosystem. Damit ist die Vergleichsfläche winzig; ein beliebiges
   Projekt-Paket ist zu keinem MCP-Kernpaket nah.
2. **Doppeltes Signal: nah UND nicht exakt.** Ein Kandidat wird geflaggt, wenn er
   (a) nicht exakt in der Allowlist steht UND (b) in Damerau-Distanz ≤ 1 zu einem
   Allowlist-Eintrag liegt. Der exakte Treffer ist das legitime Paket.
3. **Ökosystem-getrennt.** npm-Kandidaten (aus `package.json`) nur gegen npm-
   Allowlist; PyPI-Kandidaten (`requirements.txt`/`pyproject.toml`) nur gegen
   PyPI-Allowlist. Kein Cross-Match (weniger FP).
4. **Mindestlänge 5.** Kurze Namen (inkl. `mcp`) sind keine Vergleichsziele —
   Distanz 1 ist dort fast immer erfüllt (FP-Quelle).
5. **PEP-503-Normalisierung für PyPI**, lowercase für npm — Kandidaten UND
   Allowlist identisch normalisiert.
6. **pyproject best-effort via stdlib-`tomllib`.** Ab 3.11 vorhanden; auf 3.10
   sauber übersprungen (kein Crash, nur weniger Kandidaten) — Basis-Install
   bleibt dependency-frei.
7. **Damerau statt reiner Levenshtein.** Adjazenz-Vertauschung (`fatsmcp` →
   `fastmcp`) ist ein klassischer Tippfehler, den Levenshtein-≤1 verfehlt.

## Constitution Check (Gate)

| Prinzip | Status | Begründung |
|---|---|---|
| I. Test-First (NON-NEGOTIABLE) | ✅ | Tests zuerst (rot), dann Helfer/Check/Registry. |
| II. Plugin Isolation | ✅ | Neue Check-Datei + geteilter Nicht-Check-Helfer + ein Registry-Eintrag; kein Fremd-Check-Import. |
| III. FP over FN | ✅ | Kuratierte Allowlist (winzige Fläche); doppeltes Signal (nah UND ≠); Mindestlänge; malformt/fehlend → nichts. |
| IV. Zero Unnecessary Deps | ✅ | stdlib `json`/`re`/optional `tomllib`. |
| V. Evidence-Grounded | ✅ | Finding nennt Kandidat + ähnliches bekanntes Paket + Datei. |
| VI. Paired Fixture Testing | ✅ | typosquat (vuln) UND exakt/unverwandt (clean), npm + PyPI. |
| VII. Security-Research Currency | ✅ | Frischer Pass (npm/PyPI-Typosquatting, MCP-Kernpaket-Squatting) in spec.md + Refresh-Hinweis an der Allowlist. |

**Gate-Ergebnis: PASS.**

## Test Strategy (TDD, Prinzip I & VI)

`tests/test_typosquat.py`:
- Helfer zuerst: `damerau_le_1` (Substitution/Insert/Delete/Transposition == 1;
  gleich == True; Distanz ≥ 2 == False).
- US1 (npm): `package.json` mit `@modelcontextprotcol/server-github` → 1 MEDIUM
  (Kandidat + bekanntes Paket genannt); exakt korrekt → 0.
- US2 (PyPI): `requirements.txt` mit `fatsmcp` → 1 MEDIUM (Damerau); `fastmcp`
  korrekt → 0.
- US3: nur `express`/`requests`/`left-pad` → 0; kein Manifest → applies_to False
  / run() == []; malformtes JSON/TOML → 0 (kein Crash).
- pyproject (tomllib-gated): `[project].dependencies = ["fatsmcp"]` → 1 (skip auf
  < 3.11).
- Regression: bestehende Suite unverändert; Integrationstest
  `test_all_static_checks_actually_run` unverändert (der Check ist ohne Manifest
  „skipped", wie 014/015).

Reihenfolge: Tests (rot) → `_name_similarity.py` → `typosquat.py` → Registry →
volle Suite grün → Doku.

## Risiken / Restunsicherheiten

- **Allowlist-Staleness**: das MCP-Ökosystem verschiebt sich schnell (Prinzip
  VII) — die Allowlist trägt einen Refresh-Kommentar; sie ist bewusst klein
  gehalten, damit sie wartbar bleibt.
- **Seltener FP**: ein legitimes Paket, das zufällig Distanz 1 zu einem MCP-
  Kernpaket hat. Durch die winzige Allowlist + Mindestlänge unwahrscheinlich; der
  Finding-Text rahmt es als „prüfen", nicht als Beweis (MEDIUM, nicht HIGH).
- **pyproject auf 3.10**: ohne `tomllib` kein pyproject-Kandidat — dokumentierte,
  saubere Degradation (kein Crash), nicht als „sicher" fehlinterpretierbar.
