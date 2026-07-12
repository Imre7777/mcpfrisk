# Feature Specification: TYPOSQUAT_CHECK (Tier 1, statisch)

**Feature Branch**: `018-typosquat-check`

**Created**: 2026-07-12

**Status**: Design entschieden — in Implementierung. Phase 3 (Tier 3, Supply-
Chain) des "Top-Produkt zuerst"-Plans.

**Input**: Ein in einem Dependency-Manifest (`package.json`, `requirements.txt`,
`pyproject.toml`) referenzierter Paketname, der einem **bekannten, populären
MCP-Paket verwechselbar ähnlich** ist — aber nicht exakt gleich: der klassische
**Typosquatting-/Dependency-Confusion**-Vektor.

## Kontext / Motivation

**Sicherheits-Recherche (Prinzip VII, Stand 2026-07-12):**

- **Typosquatting** ist eine der meistgenutzten Supply-Chain-Angriffsklassen
  (npm/PyPI): ein bösartiges Paket wird unter einem Namen veröffentlicht, der
  sich nur um ein Zeichen / eine Vertauschung von einem populären Paket
  unterscheidet (`@modelcontextprotcol/server-github` statt
  `@modelcontextprotocol/…`, `fatsmcp` statt `fastmcp`). Ein Tippfehler beim
  `npm install`/`pip install` zieht das Angreifer-Paket — mit dessen
  Install-Skripten und Code — ins Projekt.
- Für einen **MCP-Server-Autor** ist das doppelt relevant: (a) die eigenen
  Dependencies können typosquatted sein, (b) das MCP-Ökosystem hat wenige, sehr
  populäre Kern-Pakete (`@modelcontextprotocol/*`, `mcp`, `fastmcp`), die
  attraktive Squatting-Ziele sind.
- Existierende generische Tools (osv-scanner, npm-audit) prüfen bekannte
  *CVEs*, aber **kein** Pre-Deploy-MCP-Scanner prüft speziell die Nähe zu den
  bekannten MCP-Kern-Paketen.

**Wie McpFrisk das FP-arm nutzt (Prinzip III — Typosquat-Checks sind notorisch
FP-anfällig):** McpFrisk vergleicht die Paketnamen aus den Manifesten **nur gegen
eine kleine, kuratierte Allowlist bekannter populärer MCP-Pakete** — nicht gegen
das ganze Ökosystem. Geflaggt wird ein Kandidat NUR, wenn er (a) **nicht exakt**
einem bekannten Paket entspricht UND (b) in **Damerau-Levenshtein-Distanz ≤ 1**
(eine Ersetzung/Einfügung/Löschung ODER eine Vertauschung benachbarter Zeichen)
zu einem bekannten Paket liegt. So bleibt die Vergleichsfläche winzig und
belastbar: ein beliebiges Projekt-Paket (`express`, `requests`) ist zu keinem
MCP-Kernpaket nah und wird nie geflaggt; nur echte Beinahe-Treffer schlagen an.

**OWASP/CWE-Mapping:** OWASP **MCP04** (Supply Chain); CWE: **CWE-829**
(Inclusion of Functionality from Untrusted Control Sphere) — dieselbe Supply-
Chain-Referenz wie `MCP_CONFIG_AUDIT`s UNPINNED_PACKAGE.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Typosquat eines bekannten MCP-Pakets (Priority: P1)

Als MCP-Server-Autor:in möchte ich in CI gewarnt werden, wenn eine meiner
Dependencies einem bekannten MCP-Kernpaket verwechselbar ähnlich, aber nicht
identisch ist — bevor der Tippfehler ein Angreifer-Paket ins Deployment zieht.

**Why this priority**: der Kern-Angriff; das Distanz-≤-1-gegen-Allowlist-Signal
ist belastbar und FP-arm.

**Independent Test**: `package.json` mit Dependency
`@modelcontextprotcol/server-github` (Scope-Tippfehler) → 1 Finding (MEDIUM,
CWE-829), das den Kandidaten UND das ähnliche bekannte Paket nennt. Die exakte,
korrekte Dependency `@modelcontextprotocol/server-github` → kein Finding.

**Acceptance Scenarios**:

1. **Given** ein Manifest mit einem Paketnamen in Distanz ≤ 1 zu einem bekannten
   MCP-Paket (aber ≠), **When** der Check läuft, **Then** ein Finding (MEDIUM,
   MCP04/CWE-829), das Kandidat + ähnliches bekanntes Paket + Datei nennt.
2. **Given** dasselbe Manifest mit dem **exakt korrekten** bekannten Paket,
   **When** der Check läuft, **Then** kein Finding.

---

### User Story 2 — Vertauschung + PyPI (Priority: P2)

Als Python-MCP-Autor:in möchte ich denselben Schutz für `requirements.txt` /
`pyproject.toml`, inkl. Zeichen-Vertauschungen (`fatsmcp` → `fastmcp`).

**Why this priority**: Sprach-/Ökosystem-Parität (npm UND PyPI); Vertauschung ist
ein klassischer Tippfehler, den reine Levenshtein-Distanz-1 nicht abdeckt.

**Independent Test**: `requirements.txt` mit `fatsmcp` → 1 Finding (Damerau-
Vertauschung zu `fastmcp`). `requests`, `fastmcp` (korrekt) → kein Finding.

**Acceptance Scenarios**:

1. **Given** ein PyPI-Manifest mit einer Adjazenz-Vertauschung eines bekannten
   Pakets, **When** der Check läuft, **Then** 1 Finding (MEDIUM).

---

### User Story 3 — Kein Rauschen / sichere Degradation (Priority: P3)

Als Nutzer:in möchte ich, dass unverdächtige Dependencies nie gemeldet werden und
ein malformtes/fehlendes Manifest nichts behauptet.

**Acceptance Scenarios**:

1. **Given** nur unverwandte Pakete (`express`, `requests`, `left-pad`), **When**
   der Check läuft, **Then** kein Finding.
2. **Given** kein Manifest im Ziel, **When** gescannt wird, **Then** erzeugt der
   Check nichts (`applies_to` False, skipped).
3. **Given** ein malformtes `package.json`/`pyproject.toml`, **When** gescannt
   wird, **Then** kein Crash, kein Finding.

---

### Edge Cases

- **Kurze Namen**: bekannte Ziele UND Kandidaten unter einer Mindestlänge
  (`< 5`) werden vom Vergleich ausgenommen — Distanz 1 ist bei sehr kurzen Namen
  fast immer erfüllt (FP-Quelle). Das kurze Kernpaket `mcp` ist daher bewusst
  **kein** Vergleichsziel.
- **Normalisierung**: PyPI-Namen werden nach PEP 503 normalisiert (lowercase,
  Läufe von `._-` → `-`), npm-Namen lowercase — Kandidaten UND Allowlist gleich.
- **Exakter Treffer = legitim**: ein Kandidat, der exakt einem bekannten Paket
  entspricht, wird nie geflaggt (das ist genau das echte Paket).
- **Ökosystem-getrennt**: npm-Kandidaten werden nur gegen die npm-Allowlist
  geprüft, PyPI-Kandidaten nur gegen die PyPI-Allowlist (kein Cross-Match).
- **pyproject nur best-effort**: `tomllib` ist erst ab Python 3.11 in der stdlib;
  auf 3.10 wird `pyproject.toml` sauber übersprungen (kein Crash, nur weniger
  Kandidaten) — `package.json`/`requirements.txt` laufen immer.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Der Check MUSS Paketnamen aus `package.json` (dependencies/
  devDependencies/optional/peer), `requirements.txt` und `pyproject.toml`
  (`[project].dependencies`, optional-deps, poetry-deps) extrahieren.
- **FR-002**: Kandidaten MÜSSEN gegen eine **kuratierte Allowlist** bekannter
  MCP-Pakete geprüft werden (npm ⟷ npm, PyPI ⟷ PyPI). Ein Finding entsteht NUR,
  wenn der Kandidat nicht exakt in der Allowlist steht UND in **Damerau-
  Levenshtein-Distanz ≤ 1** zu einem Allowlist-Eintrag liegt.
- **FR-003**: Namen unter der Mindestlänge (`< 5`) werden nicht verglichen (weder
  als Kandidat noch als Ziel).
- **FR-004**: Ein Treffer erzeugt ein Finding MEDIUM (MCP04, CWE-829) mit
  Kandidat + ähnlichem bekanntem Paket + Datei + Verify/Pin-Hinweis.
- **FR-005**: `applies_to` = mindestens ein Manifest im Ziel; ein malformtes/
  fehlendes Manifest wird sauber übersprungen (kein Crash, kein Finding).
- **FR-006**: stdlib-only (`json`, `re`, optional `tomllib`); KEINE Check-zu-
  Check-Abhängigkeit. Der Distanz-Helfer liegt in einem geteilten Nicht-Check-
  Modul (`checks/_name_similarity.py`).

### Key Entities

- **Allowlist**: zwei normalisierte Mengen bekannter Pakete (npm, PyPI) —
  kuratiert, mit Refresh-Hinweis (Prinzip VII: das MCP-Ökosystem verschiebt sich
  schnell).
- **damerau_le_1(a, b)**: True bei Distanz 0/1 (Ersetzung/Einfügung/Löschung ODER
  Adjazenz-Vertauschung).

## Success Criteria *(mandatory)*

- **SC-001**: Ein Beinahe-Treffer (Distanz ≤ 1, ≠) eines bekannten Pakets → 1
  MEDIUM-Finding; das exakt korrekte Paket → befundfrei.
- **SC-002**: Unverwandte Pakete → nie ein Finding; kein Manifest → skipped;
  malformtes Manifest → kein Crash.
- **SC-003**: Funktioniert für npm (`package.json`) UND PyPI (`requirements.txt`,
  `pyproject.toml`), inkl. Adjazenz-Vertauschung (Damerau).
- **SC-004**: Keine Regression; Plugin-Isolation gewahrt; Basis-Install
  dependency-frei (pyproject nur best-effort via stdlib-`tomllib`).

## Assumptions

- Die Allowlist ist bewusst klein und kuratiert (offizielle
  `@modelcontextprotocol/*`-Server + SDK, `mcp`/`fastmcp` u.a.) — sie ist die
  FP-Bremse und muss periodisch aktualisiert werden.
- Out of scope (v1): (a) Typosquat von **MCP-Config-Launch-Paketen**
  (`npx <pkg>` in mcp.json) — die Config-Fläche gehört `MCP_CONFIG_AUDIT` (014),
  das ungepinnte Launches bereits flaggt; (b) Homoglyph-/Unicode-Confusables
  jenseits von ASCII-Distanz 1; (c) Versions-/Registry-Abgleich (das ist
  `DEPENDENCY_SCAN`s Feld, Feature 019); (d) Dependency-Confusion über
  interne/private Registries.
