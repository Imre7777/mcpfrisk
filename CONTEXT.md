# CONTEXT.md — Übergabe-Briefing für Claude Code

Dieses Dokument ist für eine neue Claude-Instanz (Claude Code) geschrieben,
die dieses Projekt zum ersten Mal sieht. Es enthält alles, was in einem
vorherigen Chat mit Claude (Web/App) an Recherche, Entscheidungen und
Code entstanden ist. Lies dieses Dokument **vollständig**, bevor du
Code änderst — viele Designentscheidungen sind nicht offensichtlich aus
dem Code allein ersichtlich.

> **Siehe auch [`MARKET-RESEARCH.md`](./MARKET-RESEARCH.md)** für die
> ausführliche Wettbewerbsanalyse (direkte Konkurrenten wie `agent-audit`
> und `mcp-sec-audit`, die akademische Benchmark-Landschaft, und eine
> priorisierte Differenzierungsstrategie). Abschnitt 6 und 7 davon sollten
> die Roadmap in diesem Dokument (Abschnitt 6) ergänzen bzw. teilweise
> neu priorisieren.

---

## 1. Was ist das Projekt?

**McpFrisk** ist ein Security-Scanner für **MCP-Server-Quellcode**, der
sich an **Server-Autoren** richtet und **vor dem Deploy/Release** läuft
(CI-Pipeline, pre-commit, lokal vor dem Push) — nicht beim Endnutzer,
der einen fertigen Server installiert.

Tagline: *"Security linting for MCP servers, before they ship."*

### Warum dieser Fokus? (Marktpositionierung)

Es gibt bereits gute Tools, die installierte MCP-Server beim **Endnutzer**
scannen (z.B. `mcp-scan` von Invariant Labs, `mcp-shield`). Es gibt auch
Enterprise-Gateways, die zur **Laufzeit** Policy durchsetzen (Akto,
Harmonic Security). Was in der Recherche (Stand: Juni 2026) **nicht**
als gut besetzt auffiel: ein leichtgewichtiges Tool, das ein Server-Autor
in seine eigene CI/CD-Pipeline einbaut, bevor er released — das Pendant
zu `npm audit` oder `eslint`, aber für MCP-Sicherheitsmuster.

**Wichtig:** Mehrere Namens-Kandidaten (`mcp-sentinel`, `mcp-guard`,
`mcp-shield`, `mcp-bouncer`, `mcp-warden`) waren beim Namens-Check bereits
mehrfach vergeben — teils mit sehr ähnlichem Scope (z.B. existiert ein
`mcp-sentinel` auf PyPI, das ebenfalls Fuzzing/Schema-Tests gegen
laufende Server macht). `mcpfrisk` war zum Zeitpunkt der Recherche frei.
**Vor dem ersten öffentlichen Push unbedingt noch einmal live prüfen:**
`pip install mcpfrisk` (sollte "not found" zeigen) und die GitHub-URL
`github.com/<user>/mcpfrisk` aufrufen (sollte 404 sein).

---

## 2. Aktueller Stand (was funktioniert bereits)

4 statische Checks sind implementiert, getestet und funktionieren:

| Check ID | Datei | Was wird erkannt | OWASP MCP Top 10 | CWE |
|---|---|---|---|---|
| `CMD_INJECTION` | `checks/command_injection.py` | Shell-Aufrufe mit unsanitiertem Input (Python + JS/TS: AST-basiert via SourceModel-Port; Regex nur als jsts-absent-Fallback) | MCP05 | CWE-78 |
| `PATH_TRAVERSAL` | `checks/path_traversal.py` | Dateipfad-Konstruktion aus Tool-Parametern ohne Sandboxing/Normalisierung | MCP05 | CWE-22 |
| `HARDCODED_SECRETS` | `checks/hardcoded_secrets.py` | API-Keys/Tokens im Quellcode (bekannte Formate + Entropie-Heuristik) | MCP01 | CWE-798 |
| `TOOL_POISONING` | `checks/tool_poisoning.py` | Versteckte Instruktionen in Tool-Docstrings (das MCP-spezifischste Risiko) | MCP04 | CWE-94 |

Alle vier sind in `mcpfrisk/checks/registry.py` registriert.

**Test-Status:** 17 pytest-Tests in `tests/test_checks.py`, alle grün.
Jeder Check hat mindestens einen True-Positive-Test (gegen
`tests/fixtures/vulnerable_server.py`) und einen False-Positive-Test
(gegen `tests/fixtures/clean_server.py`).

**CLI funktioniert:**
```bash
pip install -e ".[dev]"
mcpfrisk scan ./pfad/zum/server
mcpfrisk scan ./pfad/zum/server --json report.json --fail-on critical
```

---

## 3. Architektur — wie das Projekt strukturiert ist und warum

```
mcpfrisk/
├── core/
│   ├── models.py         # Finding, Severity, ScanResult + Tier-2-Modelle (BoundaryOutcome, *Probe)
│   ├── base_check.py      # BaseCheck (statisch) / BaseDynamicCheck (Tier 2, implementiert)
│   ├── runner.py          # Statische Orchestrierung
│   ├── dynamic_runner.py  # Tier-2-Orchestrierung: DynamicRunner + DynamicSession (stdlib)
│   ├── sourcetree/        # SourceModel-Port + Python-/tree-sitter-Adapter (JS/TS, Tier 1)
│   └── report.py          # Terminal-Ausgabe + JSON-Export (statisch + dynamisch)
├── checks/
│   ├── registry.py        # STATIC_CHECKS + DYNAMIC_CHECKS -- HIER neue Checks eintragen
│   ├── command_injection.py
│   ├── path_traversal.py
│   ├── hardcoded_secrets.py
│   ├── tool_poisoning.py
│   ├── auth_boundary.py    # Tier 2: AUTH_BOUNDARY
│   ├── ssrf_check.py        # Tier 2: SSRF_CHECK (out-of-band Callback)
│   └── _ssrf_callback.py    # Loopback-Callback-Listener für SSRF_CHECK
└── cli.py                 # argparse Entry Point (scan + probe), ruft runner/dynamic_runner + report
```

### Designprinzip: Plugin-Architektur (Open/Closed)

Jeder Check ist eine eigenständige Klasse, die von `BaseCheck` erbt und
eine `run(target_path) -> list[Finding]`-Methode implementiert. Ein neuer
Check bedeutet: **eine neue Datei + ein Eintrag in `registry.py`** —
sonst wird **kein bestehender Code berührt**. Das ist bewusst so gebaut,
weil die Roadmap (siehe unten) auf 15+ Checks anwachsen soll.

Wenn du einen neuen Check hinzufügst:
1. Neue Datei in `mcpfrisk/checks/`, Klasse erbt von `BaseCheck`
2. `check_id` (Großbuchstaben, Unterstriche, z.B. `SSRF_CHECK`) vergeben
3. `run()` implementieren, gibt `list[Finding]` zurück
4. In `checks/registry.py` zur `STATIC_CHECKS`-Liste hinzufügen
5. Test-Fixtures: entweder neue Schwachstelle in `vulnerable_server.py`
   ergänzen, oder eine eigene kleine Fixture-Datei anlegen
6. Tests in `tests/test_checks.py` ergänzen (True-Positive +
   False-Positive-Fall, siehe bestehende Testklassen als Vorlage)

### Designprinzip: Severity-Stufen

`Severity` in `core/models.py` hat 5 Stufen (CRITICAL, HIGH, MEDIUM, LOW,
INFO). Die CLI hat `--fail-on <stufe>` (Default: `high`) für CI-Gates.
Bei der Zuordnung einer Severity zu einem neuen Finding: orientiere dich
an den bestehenden Checks. Faustregel: CRITICAL = direkter Exploit-Pfad
ohne weitere Bedingungen (RCE, Secret-Leak), HIGH = Exploit unter
realistischen Bedingungen möglich, MEDIUM = Best-Practice-Verstoß ohne
unmittelbaren Exploit-Pfad.

### Designprinzip: Lieber False Positives als False Negatives

Explizit im README dokumentiert und sollte bei jeder neuen Check-Logik
gelten: ein übersehener echter Befund ist schlimmer als ein zu
vorsichtiger Alarm. Im Zweifel: Finding werfen, aber mit klarer
`description`, die dem Nutzer hilft, selbst zu beurteilen, ob es ein
False Positive ist.

---

## 4. Bekannte Bugs aus der Entwicklung (Lessons Learned — wichtig!)

Diese drei Bugs sind beim Erstbau aufgetreten und wurden gefixt. Sie sind
als Regressionstests in `tests/test_checks.py` verewigt — **bitte nicht
versehentlich wieder einführen**, wenn du an der Logik arbeitest:

1. **Kommentare als Code-Validierung fehlinterpretiert** (`path_traversal.py`):
   `SAFE_VALIDATION_HINTS` wurde gegen den vollen Funktionsquelltext
   inklusive Kommentaren geprüft. Ein Kommentar wie
   `# kein realpath-Check hier!` enthielt zufällig den Hint-String
   `"realpath"` und wurde als *vorhandene* Validierung gewertet — das
   Gegenteil der Absicht. Fix: `_strip_comments()` entfernt `#`-Zeilen
   vor der Hint-Suche. **Bei jedem neuen text-basierten Heuristik-Check:
   immer überlegen, ob Kommentare die Erkennung verfälschen können.**

2. **Zu aggressive Verzeichnis-Excludes verschluckten echte Findings:**
   Ursprünglich wurden Pfade mit `"tests"`/`"test"` im Namen pauschal von
   `PathTraversalCheck` und `ToolDescriptionPoisoningCheck` ausgeschlossen
   (Gedanke: "Testcode ist nicht produktionsrelevant"). Das traf aber auch
   das eigene `tests/fixtures/`-Verzeichnis und hätte in der Praxis jeden
   MCP-Server, der seine Tools z.B. unter `src/test_utils/` ablegt,
   komplett unsichtbar gemacht. Fix: Excludes nur noch für echte
   Build-/Dependency-Verzeichnisse (`node_modules`, `.venv`, `__pycache__`).
   **Vorsicht bei neuen Excludes: lieber zu wenig als zu viel ausschließen.**

3. **OpenAI-Key-Regex erkannte `sk-proj-...`-Varianten nicht:**
   Moderne OpenAI-Keys haben oft das Präfix `sk-proj-` statt nur `sk-`.
   Der ursprüngliche Regex `sk-[a-zA-Z0-9]{20,}` (nur alphanumerisch nach
   `sk-`) hat den Bindestrich im Präfix nicht abgedeckt. Fix in
   `hardcoded_secrets.py`. **Bei Secret-Pattern-Erweiterungen: aktuelle
   Key-Formate der jeweiligen Anbieter checken, Präfixe ändern sich.**

**Allgemeine Lektion:** Jeder neue Check sollte zwingend gegen ein
absichtlich verwundbares UND ein absichtlich sauberes Fixture getestet
werden, bevor er als "fertig" gilt. Nur gegen die verwundbare Seite zu
testen hätte alle drei Bugs oben übersehen.

---

## 5. Sicherheits-Recherche-Stand (Kontext für neue Checks)

Diese Zahlen/Quellen stammen aus einer Web-Recherche, durchgeführt im
Juni 2026. Bei der Priorisierung neuer Checks sind sie die Grundlage —
wenn du weitere Checks baust, lohnt sich eine kurze erneute Recherche
(Stand kann sich schnell ändern, MCP-Ökosystem bewegt sich extrem schnell):

- **Command/Shell Injection ist mit ~43% die häufigste CVE-Kategorie**
  im MCP-Ökosystem. Grund: viele MCP-Server sind dünne Wrapper um
  CLI-Tools, `exec()`/`subprocess.run()` mit String-Interpolation ist
  die häufigste Falle.
- **82% der untersuchten Implementierungen (2.614 gescannt) sind für
  Path Traversal anfällig.** Selbst Anthropics eigener
  `mcp-server-git` war betroffen (CVE-2025-68145 u.a.).
- **38-41% der offiziell registrierten MCP-Server hatten überhaupt
  keine sinnvolle Authentifizierung.** Das ist der wichtigste Treiber
  für den Tier-2-Check `AUTH_BOUNDARY` (siehe Roadmap).
- **36.7% der MCP-Server potenziell SSRF-anfällig** (z.B. der
  MarkItDown-Bug, der AWS-EC2-Metadaten über eine ungeprüfte
  URL-Fetch-Funktion leakte).
- **Tool-Poisoning-Angriffe gelingen in 84% der Fälle bei aktiviertem
  Auto-Approval.** Invariant Labs' Demo: ein Tool namens "add" (für
  Addition) mit einer Beschreibung, die `<IMPORTANT>`-Tags enthält,
  die das Modell anweisen, `~/.ssh/id_rsa` zu lesen und mitzusenden.
- **OWASP hat einen eigenen "MCP Top 10"** (Beta, Stand Juni 2026),
  der als Referenzrahmen für `owasp_mcp_ref`-Felder in den Findings
  dient: MCP01 (Credential Exposure), MCP04 (Tool Poisoning), MCP05
  (Command/Path Injection), MCP07 (Insufficient Authentication), u.a.
  Quelle: `owasp.org/www-project-mcp-top-10/`

### Bereits existierende Konkurrenz-Tools (zur Abgrenzung)

- **`mcp-scan`** (Invariant Labs) — scannt *installierte* Server-Configs
  beim Endnutzer, nutzt einen Cloud-Klassifikator für Tool-Poisoning.
  Unser Tool macht das *lokal* und *vor dem Release*, nicht als
  Nutzer-seitiger Schutz.
- **ToolHive, Sentry MCP Monitoring** — Runtime-Observability (Metriken,
  Traces), kein Pre-Deploy-Scan.
- **Akto, CyberMCP, Harmonic Gateway** — Enterprise-Runtime-Gateways
  mit Policy-Enforcement, deutlich komplexer/teurer als unser Scope.
- **`mcp-sentinel` (PyPI, Dev07-Harsh)** — macht Fuzzing/Schema-Tests
  gegen einen *laufenden* Server (ähnlich unserem geplanten Tier 2,
  aber ohne den Pre-Deploy-Static-Scan-Fokus von Tier 1).

**Unsere Nische bleibt: statischer Code-Scan VOR dem Deploy, einfach
genug für Solo-Maintainer, CI-first.**

---

## 6. Roadmap

### Tier 2 — Dynamische Checks (brauchen einen laufenden MCP-Server)

Architektur implementiert (`BaseDynamicCheck` in `core/base_check.py`,
`DynamicRunner` + `DynamicSession` in `core/dynamic_runner.py`, eigene
`DYNAMIC_CHECKS`-Registry, Drei-Zustands-Verdikt `BoundaryOutcome`).
Diese Checks verbinden sich per HTTP mit einem echten laufenden Server
(stdlib `urllib`/`http.server` — bewusst **ohne** externe Abhängigkeit,
kein `dynamic`/`mcp`-Extra nötig), nicht nur Quellcode lesen.

Priorisiert nach Recherche-Relevanz:

1. **`AUTH_BOUNDARY`** ✅ **ERLEDIGT** — Requests ohne/mit falschem Token
   senden, prüfen ob der Server wirklich 401/403 liefert. Größte
   Hebelwirkung laut Recherche (38-41% ohne Auth). (Spec: `001-auth-boundary`.)
4. **`SSRF_CHECK`** ✅ **ERLEDIGT** — entdeckt URL-akzeptierende Tools und
   beweist *out-of-band* über einen einmaligen Loopback-Callback-Listener,
   ob der Server zu Requests gegen kontrollierte/interne Ziele gebracht
   werden kann (direkte Fetches + Redirect-Bypass; spricht zusätzlich
   `169.254.169.254` an, CWE-918). Ein eingehender Callback-Treffer ist der
   Beweis (keine Heuristik); ein abgesicherter Server (Denylist + Post-DNS-
   IP-Prüfung) bleibt befundfrei. Spec: `003-ssrf-check`.
2. **`RBAC_CROSS_TENANT`** — simuliert mehrere Rollen/Nutzer-Kontexte,
   prüft auf Namespace-Leckage zwischen Tools (z.B. liefert Tool A für
   Rolle "Student" Daten, die nur Rolle "Teacher" sehen sollte). Das
   ist die Schwachstellenklasse, die der/die Projektersteller(in) aus
   einem früheren eigenen Projekt (LeoWiki) aus erster Hand kennt —
   hoher persönlicher Erfahrungswert hier.
3. **`SCHEMA_FUZZING`** — malformed/oversized/typenfehlerhafte Parameter
   senden, prüfen auf Crashes oder Stacktrace-Leaks in Fehlerantworten.
5. **`ERROR_LEAKAGE`** — Fehlerantworten auf Pfade, Stacktraces,
   DB-Schema-Informationen prüfen.
6. **`RATE_LIMITING`** — parallele Last erzeugen, auf fehlende
   Constraints prüfen.

### Tier 3 — Supply-Chain & Spec-Compliance

- **`DEPENDENCY_SCAN`** — Wrapper um bestehende, gute Tools
  (`osv-scanner`, `pip-audit`) statt Neuerfindung. Prinzip: für
  generische Dependency-CVEs gibt es bereits exzellente Tools, unser
  Mehrwert liegt in den MCP-*spezifischen* Checks.
- **`TYPOSQUAT_CHECK`** — Levenshtein-Distanz des Paketnamens gegen
  bekannte populäre MCP-Server-Namen (Schutz vor Tippfehler-Angriffen
  wie dem dokumentierten Postmark-MCP-Incident).
- **`PACKAGE_PROVENANCE`** — npm-Provenance-Attestation / Signatur-Check.
- **`PROTOCOL_COMPLIANCE`** — korrekte JSON-RPC-Error-Codes, Vorbereitung
  auf die MCP-Spec-Release-Candidate-Änderungen (zum Zeitpunkt der
  Recherche: RC für 2026-07-28 angekündigt, finale Spec entsprechend
  danach erwartet — **unbedingt aktuellen Stand der MCP-Spec-Version
  prüfen, das ändert sich laufend**).

### Mittelfristig (Produktreife)

- ~~JS/TS-Abdeckung auf alle Checks ausweiten~~ **ERLEDIGT** (Feature
  `002-jsts-ast-coverage`): alle Code-Checks decken JS/TS per AST über den
  sprach-agnostischen `core/sourcetree`-Port ab (optionales `jsts`-Extra).
- ~~Befund-Präzision aus Real-Repo-Validierung~~ **ERLEDIGT** (Feature
  `004-finding-precision`): Severity-Kalibrierung (`subprocess.run([cmd],
  shell=True)` → MEDIUM statt CRITICAL, da kein interpolierter Befehl),
  vollständige mehrzeilen-feste Snippets (`condense_snippet` im sourcetree-Port)
  und ein PATH_TRAVERSAL-Triage-Hinweis, wenn das Modul eine *separate*
  Validierungsfunktion besitzt. **Wichtig:** rein additiv/kalibrierend — kein
  Finding wird unterdrückt, keine Pfade ausgeschlossen (Prinzip III + die
  "never exclude paths containing test"-Lesson). Validiert gegen
  `modelcontextprotocol/{servers,python-sdk}` und `egoist/fetch-mcp`.
- GitHub Action als eigenständiges, wiederverwendbares Composite-Action
  veröffentlichen (`uses: <user>/mcpfrisk-action@v1`), nicht nur der
  rohe CI-Workflow in diesem Repo.
- Erwägen: optionaler LLM-Judge-Call für `TOOL_POISONING` als
  Ergänzung zur Pattern-Heuristik (höhere Erkennungsrate bei
  raffinierteren Umschreibungen, die simple Regexe umgehen — Trade-off:
  kostet API-Calls, macht das Tool nicht mehr "zero dependency").

---

## 7. Was als Erstes zu tun ist (konkrete nächste Schritte)

1. **Vor irgendwas anderem:** `pip install -e ".[dev]"` und
   `pytest tests/ -v` laufen lassen — sollte 17/17 grün zeigen. Falls
   nicht, ist beim Transfer/Setup etwas schiefgegangen, das zuerst
   geklärt werden muss.
2. **LICENSE-Datei finalisieren** — aktuell nur ein Platzhalter mit
   Anleitung. Apache-2.0-Volltext von
   `https://www.apache.org/licenses/LICENSE-2.0.txt` holen und
   Copyright-Namen im Appendix eintragen.
3. **`pyproject.toml` personalisieren** — `authors`, GitHub-URLs unter
   `[project.urls]` mit echtem Username ausfüllen.
4. **Verfügbarkeit von `mcpfrisk` final live verifizieren** (siehe
   Abschnitt 1) — erst dann GitHub-Repo unter diesem Namen anlegen,
   `git init`, ersten Commit, Push.
5. **Danach:** einen der Tier-2-Checks angehen (Vorschlag: mit
   `AUTH_BOUNDARY` starten, da am einfachsten zu testen und höchste
   Recherche-Relevanz) — dafür zuerst `core/base_check.py` und einen
   neuen `core/dynamic_runner.py` entwerfen, der einen Test-MCP-Server
   per stdio hochfährt und mit dem `mcp`-Python-SDK als Client
   verbindet.
6. **Gegen echte MCP-Server aus der Smithery-Registry testen** —
   bisher nur gegen selbstgebaute Fixtures validiert. Ein Sanity-Check
   gegen 3-5 echte, öffentliche MCP-Server-Repos würde zeigen, wie gut
   die Heuristiken in der Praxis (mit mehr Code-Stil-Varianz) performen.

---

## 9. Arbeiten mit GitHub Spec-Kit ab jetzt

Ab diesem Punkt wird die Weiterentwicklung über **GitHub Spec-Kit**
(Spec-Driven Development) gesteuert, nicht mehr ad-hoc. Das hier ist
eine Kurzanleitung für den Einstieg plus der fertige Text für den
allerersten Befehl.

### 9.1 Warum kein vorgefertigtes `.specify/`-Verzeichnis im ZIP liegt

Spec-Kit ist ein **CLI-Tool**, das die komplette `.specify/`-Struktur
(inklusive `constitution.md`-Template, Scripts, Slash-Commands für
Claude Code) selbst erzeugt — abhängig von installierter Spec-Kit-Version
und gewähltem Agent-Integration-Typ. Ein von Hand vorgebautes
`.specify/`-Verzeichnis wäre entweder sofort veraltet oder würde von
`specify init` beim ersten Lauf ohnehin überschrieben. Stattdessen:
**das CLI selbst installieren und die Struktur generieren lassen** —
unten die exakten Schritte.

### 9.2 Installation (einmalig)

Voraussetzungen: Python 3.11+, Git, und entweder
[uv](https://docs.astral.sh/uv/) (empfohlen) oder
[pipx](https://pipx.pypa.io/).

```bash
# Specify CLI installieren -- vX.Y.Z durch den aktuellen Tag aus
# https://github.com/github/spec-kit/releases ersetzen
uv tool install specify-cli --from git+https://github.com/github/spec-kit.git@vX.Y.Z
```

Im bereits existierenden `mcpfrisk/`-Projektordner (NICHT neu anlegen,
da der Code schon da ist):

```bash
cd mcpfrisk
specify init --here --integration claude
```

Das erzeugt `.specify/memory/`, `.specify/scripts/`, `.specify/templates/`
und schaltet die `/speckit.*`-Slash-Commands in Claude Code frei. Mit
`specify check` lässt sich verifizieren, dass alle Tools korrekt
erkannt wurden.

### 9.3 Schritt 1: Constitution erstellen

Das ist der **erste inhaltliche Schritt** nach der Installation. Der
folgende Prompt-Text wurde bereits für mcpfrisk durchdacht (siehe
Entscheidungen unten) — einfach in Claude Code eingeben, nachdem
`/speckit.constitution` verfügbar ist:

```
/speckit.constitution Create governing principles for mcpfrisk, a CLI
security scanner for MCP (Model Context Protocol) server source code
that runs pre-deploy/in CI, not against running servers.

Non-negotiable principles:

1. Strict Test-First Development. For every new check or feature:
   write tests first, get them reviewed/approved by the user, confirm
   they FAIL (red), only then write implementation code. No exceptions,
   including for "obvious" fixes.

2. Plugin Isolation (Library-First). Every security check is a fully
   self-contained, independently testable unit (a class implementing
   BaseCheck) with zero dependencies on other checks. Adding a new
   check must never require modifying existing check files -- only a
   new file plus one registry entry. This isolation must hold even as
   the project grows past 15+ checks.

3. False positives over false negatives. When a detection heuristic is
   ambiguous, the check MUST flag it rather than stay silent. Every
   finding must include a clear-enough description that a human can
   judge for themselves whether it's a false positive.

4. Zero unnecessary dependencies for Tier 1 (static) checks. Static
   checks must work using only the Python standard library (ast, re,
   pathlib) wherever feasible. Do not add a dependency to solve a
   problem the standard library can already solve. Dynamic (Tier 2)
   checks that require a real MCP client/server connection are exempt
   from this rule where the `mcp` SDK itself is genuinely required.

5. Every finding must be evidence-grounded. No check may emit a finding
   based on guesswork; it must cite the offending file, line number,
   and a code snippet. Severity classification must follow the
   established rubric: CRITICAL = direct exploit path with no further
   conditions, HIGH = exploit plausible under realistic conditions,
   MEDIUM = best-practice violation without an immediate exploit path.

6. No security-relevant detection logic ships without a paired
   vulnerable-fixture test AND a paired clean-fixture test. A check
   that has only been tested against vulnerable code is considered
   unverified, regardless of how "obviously correct" the logic looks.

7. Security-research currency. Before implementing a new check class
   (e.g. SSRF, auth boundary, RBAC), a fresh research pass against
   current CVE data and OWASP MCP Top 10 categories is required --
   the MCP ecosystem and its threat landscape change fast, and
   training-data knowledge about it should be treated as stale by
   default.

Use these to also guide: testing standards, code review expectations,
and how /speckit.plan should evaluate proposed implementations for
constitutional compliance.
```

**Was danach passiert:** Claude Code erzeugt/aktualisiert
`.specify/memory/constitution.md` aus diesem Prompt. Lies das Ergebnis
durch — Spec-Kit erwartet, dass du das **prüfst und ggf. nachjustierst**,
bevor du weitermachst (siehe `spec-driven.md` der Quelle: "Open
`.specify/memory/constitution.md` and read what was generated, find
any principle that doesn't match your intentions and ask your agent to
refine it").

### 9.4 Danach: `/speckit.specify` für den nächsten Check

Sobald die Constitution steht, ist der nächste sinnvolle Schritt, den
ersten Tier-2-Check (`AUTH_BOUNDARY`, siehe Abschnitt 6) als Spec-Kit-
Feature zu spezifizieren — bewusst **noch nicht** hier vorbereitet
(siehe Projektentscheidung: erst Constitution, dann den Rest iterativ).
Wenn es so weit ist: `/speckit.specify` beschreibt das WAS/WARUM
(„ein Check, der prüft, ob ein MCP-Server Requests ohne gültige
Authentifizierung ablehnt") — **ohne** Tech-Stack-Details, die kommen
erst in `/speckit.plan`.

### 9.5 Entscheidungen, die für diese Constitution bereits getroffen wurden

Diese drei Fragen wurden im vorherigen Chat explizit geklärt und sind
in den Prompt oben eingearbeitet — falls sich das je ändern soll, muss
die Constitution bewusst neu verhandelt werden, nicht stillschweigend
driften:

- **Test-First wird strikt durchgesetzt** (Spec-Kit Article III, volle
  Strenge: Tests schreiben → User-Review → RED bestätigen → erst dann
  Code). Bewusste Entscheidung für Qualität über Geschwindigkeit,
  gerade weil es ein Security-Tool ist, bei dem ein falsches "passt
  schon" besonders teuer wäre.
- **Library-First/Plugin-Isolation wird strikt durchgesetzt**
  (Spec-Kit Article I). Passt zur bereits bestehenden Architektur
  (siehe Abschnitt 3) — keine Abweichung nötig, nur Formalisierung
  eines Prinzips, das ohnehin schon gelebt wird.
- **Tier-2-Spec wird bewusst NICHT vorab mitgeliefert** — die
  Constitution kommt zuerst und soll erst einmal vom Nutzer geprüft
  werden, bevor das nächste Feature spezifiziert wird. Das entspricht
  auch dem von Spec-Kit empfohlenen Ablauf (Constitution einmalig,
  dann iterativ Feature für Feature).

---



- **Lizenzmodell für eine eventuelle kommerzielle Zukunft:** aktuell
  komplett offen unter Apache 2.0. Falls später ein Hosted-Dashboard
  oder Premium-Checks dazukommen sollen, müsste das Lizenzmodell neu
  überdacht werden (z.B. Open-Core-Modell). Nicht eilig, aber im Hinterkopf.
- **Wie genau `RBAC_CROSS_TENANT` (Tier 2) konkret getestet wird,**
  ist noch nicht im Detail durchdacht — das braucht vermutlich eine Art
  Konfigurationsdatei, in der der Nutzer angibt, welche Rollen/Identitäten
  existieren und welches Tool welcher Rolle zugänglich sein sollte
  (sonst kann das Tool nicht automatisch "falsch" von "richtig"
  unterscheiden). Das ist der komplexeste geplante Check und braucht
  wahrscheinlich die meiste Designarbeit.
- **Ob ein LLM-Judge für Tool-Poisoning-Erkennung integriert wird** —
  aktuell rein pattern-basiert (siehe Tier-2-Punkt oben). Abwägung
  zwischen Erkennungsqualität und "zero dependency"-Anspruch des Tools.
- **Spec-Kit-Versionsstand:** Abschnitt 9 wurde gegen Spec-Kit
  `v0.9.1` (Stand der Recherche: Juni 2026) verifiziert. Spec-Kit
  selbst entwickelt sich schnell weiter (155+ Releases zum
  Recherche-Zeitpunkt) — bei spürbaren Abweichungen vom hier
  beschriebenen Ablauf lohnt sich ein Blick in die aktuelle
  `github.com/github/spec-kit`-README, bevor man rätselt, ob etwas
  in diesem Dokument falsch ist oder sich das Tool weiterentwickelt hat.
