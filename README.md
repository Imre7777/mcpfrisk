# McpFrisk

> **Security linting for MCP servers — before they ship.**

[![CI](https://github.com/Imre7777/mcpfrisk/actions/workflows/ci.yml/badge.svg)](https://github.com/Imre7777/mcpfrisk/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Core deps](https://img.shields.io/badge/core%20deps-stdlib--only-success)](./pyproject.toml)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP%20Top%2010-informational)](https://owasp.org/www-project-mcp-top-10/)

McpFrisk ist ein Pre-Deploy-/CI-Security-Scanner für **MCP-Server-Quellcode**.
Er läuft **vor** dem Release — im Gegensatz zu Tools wie `mcp-scan`, die
*installierte* Server beim Endnutzer prüfen, richtet sich McpFrisk an die
**Server-Autor:innen** und fängt Schwachstellen, bevor sie ausgeliefert werden.

- **Statisch (Tier 1):** AST-basierte Checks für Command-Injection, Path-Traversal,
  Hardcoded Secrets und Tool-Poisoning — für Python *und* JS/TS.
- **Dynamisch (Tier 2):** prüft einen **laufenden** Server (Auth-Boundary, SSRF)
  mit echtem Beweis statt Heuristik.
- **Stdlib-only-Kern:** der Basis-Install bringt keine externen Abhängigkeiten mit —
  kleine Angriffsfläche, triviale Installation. JS/TS-Parsing ist ein optionales Extra.
- **CI-tauglich:** ein Exit-Code, ein optionaler JSON-Report — direkt als Build-Gate nutzbar.

> **Neu im Projekt?** Lies zuerst [`CONTEXT.md`](./CONTEXT.md) — vollständige
> Architektur-Begründung, Lessons Learned, die Sicherheits-Recherche hinter den
> Checks und das [GitHub Spec-Kit](https://github.com/github/spec-kit)-Setup für
> die Weiterentwicklung. Wettbewerbslage und Differenzierung:
> [`MARKET-RESEARCH.md`](./MARKET-RESEARCH.md).

## Inhalt

- [Schnellstart](#schnellstart)
- [JavaScript/TypeScript-Unterstützung](#javascripttypescript-unterstützung-optionales-extra)
- [Verwendung](#verwendung)
- [Checks (Tier 1, statisch)](#aktuell-implementierte-checks-tier-1-statisch)
- [Tier 2 (dynamisch)](#tier-2-dynamisch-braucht-laufenden-server)
- [Roadmap (Tier 3)](#roadmap-tier-3-supply-chain--spec-compliance)
- [Design-Prinzipien](#design-prinzipien)
- [Bekannte Grenzen](#bekannte-grenzen-bewusst-kein-bug)
- [Entwicklung](#entwicklung)

## Schnellstart

```bash
# Im Repo-Root (pyproject.toml liegt hier)
pip install -e .

mcpfrisk scan ./pfad/zum/server
```

Ohne Installation direkt ausführbar:

```bash
python3 -m mcpfrisk.cli scan ./pfad/zum/server
```

### JavaScript/TypeScript-Unterstützung (optionales Extra)

Der Basis-Install bleibt bewusst abhängigkeitsfrei (nur Python-Standardbib).
Für **vollwertige, parser-basierte JS/TS-Analyse** (gleiche Tiefe wie bei
Python) das `jsts`-Extra installieren:

```bash
pip install -e ".[jsts]"
```

Damit analysieren alle Checks `.js/.mjs/.cjs/.jsx` und `.ts/.mts/.cts/.tsx`
über einen echten AST (tree-sitter) statt Zeilen-Regex — mehrzeilen-fest und
immun gegen Treffer in Kommentaren/Strings. **Ohne** das Extra werden JS/TS-
Dateien sauber übersprungen (nie fälschlich als „clean" gewertet);
`CMD_INJECTION` fällt auf eine einfache Regex-Heuristik zurück.

Architektur-Hinweis: Der Parser liegt hinter einem sprach-agnostischen
`SourceModel`-Port (`core/sourcetree`). Die Checks fragen domänennah
(`call_sites()`, `tool_definitions()` …) und sehen `ast`/`tree-sitter` nie —
eine neue Sprache wäre ein neuer Adapter, kein Check-Umbau.

## Verwendung

```bash
# Einfacher Scan, Terminal-Report
mcpfrisk scan ./mein-mcp-server

# JSON-Report für CI-Artefakte/Weiterverarbeitung
mcpfrisk scan ./mein-mcp-server --json report.json

# Build soll erst ab CRITICAL failen (statt Default HIGH)
mcpfrisk scan ./mein-mcp-server --fail-on critical

# Einzelne Checks deaktivieren
mcpfrisk scan ./mein-mcp-server --skip TOOL_POISONING
```

Exit-Code `0` = bestanden, `1` = Findings über der `--fail-on`-Schwelle
gefunden. Direkt als GitHub Action / CI-Gate nutzbar.

## Aktuell implementierte Checks (Tier 1, statisch)

| Check ID | Was wird geprüft | OWASP MCP Top 10 | Anteil an realen CVEs |
|---|---|---|---|
| `CMD_INJECTION` | Shell-Aufrufe mit unsanitiertem Input | MCP05 | ~43% |
| `PATH_TRAVERSAL` | Dateipfad-Konstruktion ohne Sandboxing | MCP05 | ~82% der Implementierungen anfällig |
| `HARDCODED_SECRETS` | API-Keys/Tokens im Quellcode | MCP01 | — |
| `TOOL_POISONING` | Versteckte Instruktionen in Tool-Beschreibungen | MCP04 | 84% Erfolgsrate bei Auto-Approval |

Jeder Check ist eine eigenständige Klasse unter `mcpfrisk/checks/`,
registriert in `checks/registry.py`. Neue Checks hinzufügen heißt: neue
Datei + einen Eintrag in der Registry, kein bestehender Code wird berührt.

## Tier 2 (dynamisch, braucht laufenden Server)

Diese brauchen eine echte Verbindung zum MCP-Server statt nur den Quellcode zu
lesen. Ausgeführt über den `probe`-Befehl gegen einen **laufenden** Server —
wahlweise per HTTP (`--server <url>`) oder über **stdio** (`--stdio "<command>"`),
den Transport, über den die Mehrheit der MCP-Server läuft:

```bash
# HTTP: prüft u.a., ob der Server unauthentifizierte Anfragen ablehnt (401/403)
mcpfrisk probe --server http://localhost:8000/mcp

# stdio: McpFrisk startet den Server als Subprozess und spricht newline-JSON-RPC
mcpfrisk probe --stdio "python -m my_server"
mcpfrisk probe --stdio "npx -y @scope/mcp-server" --timeout 5 --fail-on high
```

> ⚠️ **Sicherheitshinweis:** `--stdio` **führt den angegebenen Befehl aus**
> (Code-Ausführung). Nur gegen Server richten, denen du vertraust bzw. die du
> gerade testest. McpFrisk verhandelt automatisch die Protokoll-Ära
> (modernes stateless `server/discover` mit Fallback auf den Legacy-
> `initialize`-Handshake), spricht reines stdlib-JSON-RPC (kein `mcp`-SDK) und
> beendet den Subprozess zuverlässig wieder.

Ein nicht erreichbarer/timeoutender/nicht startbarer Server wird als
*inconclusive* gemeldet — weder Pass noch Finding, und niemals stillschweigend
als „sicher". **AUTH_BOUNDARY** ist transportbedingt HTTP-spezifisch (stdio hat
keinen Transport-Auth-Boundary) und meldet auf stdio *inconclusive*; die
`call()`-basierten Checks wie **SSRF_CHECK** laufen über beide Transporte.

**Implementiert:**

- **AUTH_BOUNDARY** ✅ — sendet Anfragen ohne/mit falschem Token und prüft,
  ob der Server wirklich 401/403 liefert statt durchzulassen (stdlib-only,
  keine externe Abhängigkeit)
- **SSRF_CHECK** ✅ — entdeckt URL-akzeptierende Tools und beweist *out-of-band*,
  ob der Server zu Requests gegen kontrollierte/interne Ziele gebracht werden
  kann: McpFrisk startet einen einmaligen Loopback-Callback-Listener und wertet
  einen eingehenden Treffer als Beweis (keine Heuristik). Deckt direkte Fetches
  und Redirect-Bypass ab und spricht das Cloud-Metadata-Ziel `169.254.169.254`
  an. Ein korrekt abgesicherter Server (Denylist + Post-DNS-IP-Prüfung) bleibt
  ohne Befund. Stdlib-only (CWE-918).

**Geplant** (Architektur via `BaseDynamicCheck`/`DynamicRunner` vorhanden):

- **RBAC_CROSS_TENANT** — simuliert mehrere Rollen, prüft auf
  Namespace-Leckage zwischen Tools (z.B. Student/Teacher-Trennung)
- **SCHEMA_FUZZING** — malformed/oversized Parameter, prüft auf Crashes
  oder Stacktrace-Leaks
- **ERROR_LEAKAGE** — prüft Fehlerantworten auf Pfade, Stacktraces,
  DB-Schema-Informationen
- **RATE_LIMITING** — parallele Last, prüft auf fehlende Constraints

## Roadmap: Tier 3 (Supply-Chain & Spec-Compliance)

- **DEPENDENCY_SCAN** — Wrapper um `osv-scanner`/`pip-audit` statt
  Neuerfindung
- **TYPOSQUAT_CHECK** — Levenshtein-Distanz des Paketnamens gegen
  bekannte populäre MCP-Server
- **PACKAGE_PROVENANCE** — npm-Provenance/Signatur-Check
- **PROTOCOL_COMPLIANCE** — korrekte JSON-RPC-Error-Codes, Vorbereitung
  auf MCP-Spec-RC (Juli 2026)

## Design-Prinzipien

1. **Lieber False Positives als False Negatives.** Ein übersehener
   Befund ist schlimmer als ein zu vorsichtiger.
2. **Jeder Check ist isoliert testbar.** Siehe `tests/fixtures/` für
   einen absichtlich verwundbaren und einen absichtlich sauberen
   Beispiel-Server — beide dienen als Regressionstests.
3. **Kein Neuerfinden bestehender, guter Tools.** Für Dependency-Scanning
   gibt es `osv-scanner`/Snyk, für generische Secrets `gitleaks`. McpFrisk
   wrappt diese eher, als sie zu duplizieren — der Mehrwert liegt in den
   MCP-*spezifischen* Checks (Tool-Poisoning, RBAC-Cross-Tenant), die
   kein generisches Tool kennt.
4. **Reports zeigen nie das vollständige Secret.** Auch im eigenen
   Output wird redacted — ein Scanner soll kein neues Leck erzeugen.

## Bekannte Grenzen (bewusst, kein Bug)

- Statische Analyse ist eine Heuristik. AST-Matching kann keinen
  vollständigen Datenfluss durch beliebig komplexen Code verfolgen
  (das Taint-Tracking hier ist bewusst simpel: eine Ebene von
  Zwischenvariablen, kein vollständiger Dataflow-Graph). Validiert ein
  Server in einer *separaten* Funktion (z.B. `validatePath()`), meldet
  `PATH_TRAVERSAL` weiterhin (Prinzip: lieber FP als FN), hängt aber einen
  **Triage-Hinweis** auf die existierende Validierungsfunktion an, damit ein
  wahrscheinlicher False Positive schnell einzuordnen ist.
- Severity folgt der Rubrik: eine konstante Argument-Liste mit redundantem
  `subprocess.run(..., shell=True)` ist ein Best-Practice-Verstoß (MEDIUM),
  kein direkter RCE-Pfad (CRITICAL bleibt dem interpolierten Befehl vorbehalten).
- Tool-Poisoning-Erkennung ist Pattern-basiert, kein LLM-Klassifikator
  wie bei `mcp-scan`. Für höhere Präzision wäre ein optionaler
  LLM-Judge-Call eine sinnvolle Tier-2-Erweiterung.
- JS/TS wird mit dem `jsts`-Extra von allen Code-Checks (`CMD_INJECTION`,
  `PATH_TRAVERSAL`, `TOOL_POISONING`, `HARDCODED_SECRETS`) per AST abgedeckt.
  Minifizierte/gebundelte Dateien (`node_modules`, `dist`, `build`) sind
  bewusst ausgeschlossen.

## Entwicklung

```bash
# Dev-Setup (inkl. Tests + tree-sitter für JS/TS)
pip install -e ".[dev]"

# Komplette Testsuite
pytest -q

# Mit Coverage (wie in CI)
pytest --cov=mcpfrisk --cov-report=term-missing
```

Die CI (siehe [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)) läuft
gegen Python 3.10/3.11/3.12 und prüft zusätzlich in einem eigenen Job den
Degradations-Pfad **ohne** das `jsts`-Extra (Basis-Install darf nie crashen).

### Projektstruktur

```text
mcpfrisk/
├── core/
│   ├── models.py          # Finding, Severity, ScanResult + Tier-2-Modelle
│   ├── base_check.py      # BaseCheck (statisch) / BaseDynamicCheck (Tier 2)
│   ├── runner.py          # Statische Orchestrierung
│   ├── dynamic_runner.py  # Tier-2-Orchestrierung + Transport-Port (HTTP-Adapter)
│   ├── stdio_transport.py # stdio-Adapter: Subprozess + newline-JSON-RPC
│   ├── sourcetree/        # SourceModel-Port + Python-/tree-sitter-Adapter
│   └── report.py          # Terminal-Ausgabe + JSON-Export
├── checks/
│   ├── registry.py        # STATIC_CHECKS + DYNAMIC_CHECKS  ← neue Checks hier
│   └── *.py               # je ein Check pro Datei (isoliert testbar)
└── cli.py                 # argparse Entry Point (scan + probe)
```

Ein neuer Check ist eine neue Datei in `checks/` plus ein Eintrag in
`checks/registry.py` — bestehender Code wird nicht angefasst. Jeder Check
braucht ein verwundbares **und** ein sauberes Fixture unter `tests/fixtures/`
als Regressionstest.

## Lizenz

[Apache-2.0](./LICENSE) © Imre Obermueller
