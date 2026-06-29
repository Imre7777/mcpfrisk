# McpFrisk

Pre-Deploy/CI-Security-Scanner für MCP-Server-Quellcode. Läuft **vor** dem
Release — im Gegensatz zu Tools wie `mcp-scan`, die *installierte* Server
beim Endnutzer prüfen, richtet sich McpFrisk an **Server-Autoren**.

> **Neu im Projekt?** Lies zuerst [`CONTEXT.md`](./CONTEXT.md) — das
> enthält die vollständige Architektur-Begründung, bekannte Bugs/Lessons
> Learned, die Sicherheits-Recherche hinter den Checks, und die Anleitung
> zum Einrichten von [GitHub Spec-Kit](https://github.com/github/spec-kit)
> für die weitere Entwicklung (Abschnitt 9).

## Installation

```bash
cd mcpfrisk
pip install -e .   # oder einfach per PYTHONPATH ausführen, siehe unten
```

Ohne Installation direkt ausführbar:

```bash
python3 -m mcpfrisk.cli scan ./pfad/zum/server
```

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

## Roadmap: Tier 2 (dynamisch, braucht laufenden Server)

Diese brauchen eine echte Verbindung zum MCP-Server (stdio/HTTP) statt
nur den Quellcode zu lesen. Architektur dafür ist vorbereitet
(`BaseDynamicCheck` in `core/base_check.py`), aber noch nicht implementiert:

- **AUTH_BOUNDARY** — Requests ohne/mit falschem Token; prüft ob Server
  wirklich 401/403 liefert statt durchzulassen
- **RBAC_CROSS_TENANT** — simuliert mehrere Rollen, prüft auf
  Namespace-Leckage zwischen Tools (z.B. Student/Teacher-Trennung)
- **SCHEMA_FUZZING** — malformed/oversized Parameter, prüft auf Crashes
  oder Stacktrace-Leaks
- **SSRF_CHECK** — prüft, ob URL-fetchende Tools interne/Cloud-Metadata-
  Endpunkte erreichen können (z.B. `169.254.169.254`)
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
  Zwischenvariablen, kein vollständiger Dataflow-Graph).
- Tool-Poisoning-Erkennung ist Pattern-basiert, kein LLM-Klassifikator
  wie bei `mcp-scan`. Für höhere Präzision wäre ein optionaler
  LLM-Judge-Call eine sinnvolle Tier-2-Erweiterung.
- Deckt aktuell nur Python ernsthaft ab (JS/TS nur für
  Command-Injection). Andere Checks für JS/TS sind eine offene
  Erweiterung.
