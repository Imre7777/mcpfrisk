# McpFrisk — Roadmap zur Produktionsreife

> **Zweck:** Vollständige, priorisierte Landkarte von hier bis zum
> öffentlichen Release — und darüber hinaus. Jeder Punkt hat **Priorität**,
> **Aufwand** und **Akzeptanzkriterien**, damit nichts vergessen wird, egal wie
> lange es dauert. Dies ist ein lebendes Dokument: erledigte Punkte abhaken,
> neue ergänzen.

**Stand:** 2026-07-14 · `main @ 1f54621` · Version `0.1.0` (Alpha, nie released)
**Checks:** 19 (12 statisch + 7 dynamisch) · **Tests:** 359 grün · **Coverage-Gate:** 88 % (real ~90 %) · **Lint:** ruff clean

## Legende
- **Prio:** `P0` = blockiert Release / falsch auf korrektem Code · `P1` = sollte vor Release · `P2` = nach Launch / laufend
- **Aufwand:** `S` ≈ ein paar Stunden · `M` ≈ ein Tag · `L` ≈ mehrere Tage
- **Status:** ☐ offen · ◐ in Arbeit · ☑ fertig
- Arbeitsweise unverändert: Spec-Kit (`specs/NNN-name/`), strikt TDD (rot→grün), ein Feature pro Commit, Push, dann CI-Check durch den Nutzer.

---

## Phase 0 — Korrektheits-Bugs (P0, zuerst)

Bugs, die auf **korrektem** Nutzercode falsch anschlagen oder echte Lücken lassen. Das ist das Peinlichste, deshalb zuerst.

### 0.1 ☑ `P0` `S` — spawn-mit-Array False Positive (Feature 023) — **ERLEDIGT** (`main`, 2026-07-15)
- **Problem:** JS/TS `spawn(cmd, [args])` **ohne** `shell:true` ist die *sichere*, empfohlene Form, wird aber als HIGH CMD_INJECTION geflaggt.
- **Ursache:** `checks/command_injection.py::_assess` behandelt `exec` (immer über Shell) und `spawn` (nur bei `shell:true` gefährlich) gleich.
- **Fix:** `exec`/`execSync` = immer Shell → gefährlich bei dynamischem Input. `spawn`/`execFile` = nur gefährlich, wenn `shell:true` im options-Objekt steht. Analog zur bereits existierenden Python-Logik (`subprocess` mit/ohne `shell=True`).
- **Akzeptanz:** roter Test `spawn("git", [userInput])` → **kein** Finding; `spawn("sh", ["-c", userInput])` und `spawn(cmd, args, {shell:true})` → weiterhin Finding. Regressionstest gegen die 13 Real-World-Repos: CMD_INJECTION-Zahl sinkt, keine echte Lücke geht verloren.

### 0.2 ☐ `P1` `M` — TOOL_NAME_COLLISION Server-Scoping (Feature 024)
- **Problem:** Kollisionen werden global über die ganze Codebase gewertet; in SDK-Monorepos kollidieren `echo`/`greet`/`noop` aus **unabhängigen** Beispielservern fälschlich. 022 entschärft per Exclude, behebt aber nicht die **Ursache**.
- **Fix:** Kollision nur innerhalb einer logischen Server-Grenze werten (gleiche Datei bzw. gleiche `FastMCP()`/`Server()`-Instanz / gleiches Verzeichnis-Modul). Recherchieren, welche Heuristik robust ist (Instanz-Tracking vs. Datei-Scope).
- **Akzeptanz:** zwei separate Beispielserver mit je einem `echo`-Tool → **kein** Finding; zwei `echo`-Tools **im selben** Server → Finding bleibt.

### 0.3 ☐ `P2` `S` — `python -m mcpfrisk` funktioniert nicht
- **Problem:** Kein `mcpfrisk/__main__.py`; nur `python -m mcpfrisk.cli` läuft. README nennt korrekt `mcpfrisk.cli`, aber `python -m mcpfrisk` ist die erwartete Konvention.
- **Fix:** `mcpfrisk/__main__.py` mit `from mcpfrisk.cli import main; main()`.
- **Akzeptanz:** `python -m mcpfrisk scan .` läuft; Test deckt es ab.

---

## Phase 1 — „Nicht blamieren"-Härtung (P1) — **ERLEDIGT** (Feature 024, `main`, 2026-07-15)

Der Block, der Vertrauen schafft: Plattform-Nachweis + das Tool muss selbst vorbildlich sein.

### 1.1 ☑ `P1` `S` — CI-Matrix auf Windows + macOS erweitern
- **Warum:** Entwickelt auf Windows, CI läuft nur `ubuntu-latest`. Pfad-Logik (`pathlib`, `fnmatch`, das frische `is_excluded` aus 022) ist auf `\` vs `/` empfindlich — ohne Windows-CI würde ein Pfad-Bug unentdeckt durchrutschen.
- **Umsetzung:** `strategy.matrix.os: [ubuntu-latest, windows-latest, macos-latest]` für den `test`-Job (ggf. Python-Versionen auf den Nicht-Linux-OS reduzieren, um Minuten zu sparen).
- **Akzeptanz:** grüne Suite auf allen drei OS; besonders `test_scan_exclusions.py` auf Windows.

### 1.2 ☑ `P1` `S` — Self-Scan als CI-Gate (Dogfooding auf echtem Code)
- **Warum:** Ein Security-Tool, das seinen eigenen Code scannt und sauber ist, ist das stärkste Vertrauenssignal. Verifiziert: `mcpfrisk scan mcpfrisk/` ist aktuell **clean**.
- **Umsetzung:** CI-Schritt `mcpfrisk scan mcpfrisk/ --fail-on medium` (echter Code, nicht nur Fixtures). Bei künftigem Fund: entweder echter Bug (fixen) oder begründete Baseline.
- **Akzeptanz:** CI-Job schlägt fehl, wenn der eigene Code je ein Finding ≥ MEDIUM bekommt.

### 1.3 ☑ `P1` `S` — Supply-Chain-Sicherheit des eigenen Repos
- **Warum:** Wir predigen DEPENDENCY_SCAN/PACKAGE_PROVENANCE — müssen es vorleben.
- **Umsetzung:**
  - ☑ `pip-audit`-Job auf `.[jsts]` (unsere reale Laufzeit-Lieferkette).
  - ◐ **CodeQL** (`.github/workflows/codeql.yml`) — angelegt, aber **dormant**
    (`workflow_dispatch`), weil das Repo privat **ohne GHAS** ist (Upload würde
    fehlschlagen → CI rot). **TODO beim Public-Gang:** Trigger auf `push`/`pull_request`/`schedule` umstellen (Kommentar in der Datei).
  - ☑ `.github/dependabot.yml`: wöchentlich `pip` + `github-actions`.
- **Akzeptanz:** grüner `pip-audit`-Job ✅; CodeQL-Workflow vorhanden (aktiv ab public) ✅; Dependabot konfiguriert ✅.

### 1.4 ☑ `P1` `S` — GitHub Actions pinnen (eigene Lieferkette härten)
- **Warum:** `uses: actions/checkout@v4` ist ein bewegliches Tag; Best Practice für sicherheitskritische Repos ist SHA-Pinning.
- **Umsetzung:** ☑ alle `uses:` in `ci.yml`/`codeql.yml`/`action.yml` auf vollen Commit-SHA gepinnt (autoritativ via `gh api` aufgelöst, `# vX`-Kommentar); Dependabot hält sie aktuell.
- **Akzeptanz:** keine beweglichen Tags mehr in Workflows ✅.

---

## Phase 2 — Professionelle Repo-Hygiene (P1/P2, schnell)

Standard-Signale für „ernstes Open-Source-Projekt". Größtenteils ein Nachmittag.

### 2.1 ☐ `P1` `S` — Community-Health-Dateien
- ☐ `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1)
- ☐ `.github/ISSUE_TEMPLATE/bug_report.yml` + `feature_request.yml` + `config.yml`
- ☐ `.github/PULL_REQUEST_TEMPLATE.md` (Checkliste: Tests? Doku? Constitution-Prinzipien?)
- **Akzeptanz:** GitHub „Community Standards"-Seite zeigt alle Häkchen grün.

### 2.2 ☐ `P1` `S` — README-Badges + visueller Eindruck
- ☐ Badges: CI-Status, PyPI-Version (nach Release), License, Python-Versionen, evtl. Coverage.
- ☐ CLI-Demo: asciinema-Cast oder animiertes GIF eines echten Scans (verkauft das Tool in 5 Sekunden).
- **Akzeptanz:** Badges rendern; Demo im README sichtbar.

### 2.3 ☐ `P1` `S` — pre-commit-Hook (du wolltest ihn ohnehin)
- ☐ `.pre-commit-config.yaml`: ruff (lint+format), evtl. schneller Smoke-Test, trailing-whitespace/EOF-Fixer.
- ☐ Doku in CONTRIBUTING.md: `pre-commit install`.
- **Akzeptanz:** `pre-commit run --all-files` läuft grün lokal.

### 2.4 ☐ `P2` `S` — Zitier-/Metadaten
- ☐ `CITATION.cff` (Zenodo-kompatibel — falls jemand das Tool in Papern zitiert).
- ☐ `.github/FUNDING.yml` (optional).

---

## Phase 3 — Testtiefe (P1/P2)

Über die reine Zeilen-Coverage hinaus — beweisen, dass die Logik stimmt.

### 3.1 ☐ `P1` `S` — Cross-Platform-Tests real (deckt sich mit 1.1)
- Sicherstellen, dass Pfad-/Ignore-Logik auf Windows getestet wird, nicht nur angenommen.

### 3.2 ☐ `P1` `M` — Property-based / Fuzz auf Parsern & is_excluded
- **Warum:** Zero-Crash-Garantie bei beliebigem Input ist bei einem Security-Tool Pflicht.
- **Umsetzung:** `hypothesis` gegen `is_excluded`, den Ignore-Parser und die AST-Extraktion (`core/sourcetree`). Muster: „darf nie werfen, egal welcher String".
- **Akzeptanz:** Fuzz-Tests in der Suite; keine ungefangenen Exceptions.

### 3.3 ☐ `P2` `M` — Mutation-Testing
- **Warum:** 90 % Coverage ≠ 90 % Aussagekraft. Mutation-Testing zeigt, ob Tests echte Regressionen fangen.
- **Umsetzung:** `mutmut` oder `cosmic-ray` auf `mcpfrisk/checks/` + `core/`. Überlebende Mutanten → Testlücken schließen.
- **Akzeptanz:** dokumentierte Mutation-Score; kritische Check-Logik ohne überlebende Mutanten.

### 3.4 ☐ `P2` `S` — Performance-Regressionstest
- **Warum:** python-sdk (815 Dateien) lief >90 s in Timeout. Nach 022 (Excludes) besser, aber ein Budget-Test verhindert Rückfall.
- **Umsetzung:** großer synthetischer Monorepo-Fixture + Zeit-/Datei-Budget-Assertion (großzügig, gegen katastrophale Regression, nicht Mikro-Benchmark).
- **Akzeptanz:** Test schlägt fehl, wenn ein Check auf N Dateien ein Zeitbudget reißt.

---

## Phase 4 — Benchmarks & empirischer Beweis (P1/P2)

Die Zahlen, an denen Reviewer uns messen. Alles reproduzierbar + provenance-getaggt (bestehende Linie fortführen).

### 4.1 ☐ `P1` `L` — Real-World-Korpus auf 30–50 Server erweitern
- **Warum:** Dein „100 % auf Nummer sicher". Bisher 13, manuell.
- **Umsetzung:** `benchmark/realworld_corpus.py` — Liste echter MCP-Server (offizielles `modelcontextprotocol/servers`-Verzeichnis + glama.ai/smithery-Registries), jeweils auf **Commit-SHA gepinnt**, klonen → scannen → Findings triagieren → als JSON persistieren. Nachvollziehbar, kein Handklonen.
- **Akzeptanz:** Skript reproduziert den Korpus deterministisch; Ergebnisse in `benchmark/REALWORLD.md` mit Provenance.

### 4.2 ☐ `P1` `M` — Harte Precision/Recall/F1-Tabelle
- **Warum:** „Warum euch statt Semgrep?" braucht Zahlen, keine Behauptung.
- **Umsetzung:** über den erweiterten Korpus: Precision, Recall, F1, **FP-Rate pro Check**. Gelabelte Ground-Truth (bekannte Vulns + bekannte Clean).
- **Akzeptanz:** Tabelle in `benchmark/RESULTS.md`; jede Zahl auf Korpus + Commit rückführbar.

### 4.3 ☐ `P1` `S` — Laufzeit-Benchmark vs. Konkurrenz
- **Warum:** Geschwindigkeit ist ein echtes CI-Gate-Verkaufsargument.
- **Umsetzung:** Dateien/Sekunde McpFrisk vs. Semgrep vs. agent-audit auf demselben Korpus.
- **Akzeptanz:** dokumentierte Laufzeit-Tabelle mit Hardware-/Versions-Provenance.

### 4.4 ☐ `P2` `M` — Weitere kuratierte Vuln-Korpora
- appsecco/MCPTox, DVMCP (haben wir teils), weitere — für Recall-Breite.
- **Akzeptanz:** jeder Korpus mit Quelle + Commit dokumentiert.

### 4.5 ☐ `P2` `S` — Benchmark als Nightly-CI-Job
- **Warum:** „jederzeit nachvollziehbar" zementieren; RESULTS.md nie stale.
- **Akzeptanz:** geplanter Workflow regeneriert Ergebnisse + committet/artefaktet sie.

---

## Phase 5 — Security-Research-Currency & neue Checks (P1/P2, laufend)

Prinzip VII: aktuell bleiben. Recherche 2026-07-14 (Quellen unten) bestätigt unsere Abdeckung und liefert Kandidaten.

### Abgleich mit MCP-Bedrohungslage 2026 (bestätigt abgedeckt)
- Tool Poisoning / versteckte Instruktionen in Descriptions → **TOOL_POISONING**, **SCHEMA_DOCSTRING_MISMATCH** ✅
- Rug-Pull (Beschreibung/Verhalten ändert sich nach Vertrauensaufbau; realer Fall: E-Mail-Server BCC an Angreifer) → **TOOL_DESCRIPTION_DRIFT**, **PACKAGE_PROVENANCE**, **DEPENDENCY_SCAN** ✅
- SSRF / interne Endpunkte → **SSRF_CHECK** ✅
- Cross-Tenant / Autorisierung → **RBAC_CROSS_TENANT**, **AUTH_BOUNDARY** ✅

### Kandidaten für neue Checks (recherchieren + spec'en)
- ☐ `P1` — **Cloud-Metadata-SSRF-Härtung:** 2026er-Vektor — bei OAuth-Metadata-Discovery zeigt ein bösartiger Server URLs auf interne/Cloud-Metadata-Endpunkte (`169.254.169.254`, `metadata.google.internal`). Prüfen, ob **SSRF_CHECK** link-local/Metadata-IPs explizit abdeckt; sonst ergänzen.
- ☐ `P1` — **OAuth-/Auth-Discovery-Sicherheit:** MCP überlässt Auth der Implementierung; fehlende Server-Attestation + schwache Session-Bindung → Session-Hijacking/Rogue-Server. Statisch prüfbare Anti-Pattern identifizieren.
- ☐ `P2` — **OX-Security-„SDK-Default"-Flaw (April 2026):** systemischer Design-Default in offiziellen MCP-SDKs (~200k Instanzen betroffen). Recherchieren, was genau der Default ist, und ob statisch erkennbar → eigener Check.
- ☐ `P2` — **Confused-Deputy / Token-Passthrough**, **überbreite OAuth-Scopes**, **fehlende Rate-Limits an Auth-Endpunkten** (teils dynamisch via RATE_LIMITING).
- ☐ `P2` — Laufende Sichtung: OWASP MCP Top 10 Updates, NSA/CISA-MCP-Guidance, neue CVEs.

**Akzeptanz je Check:** Spec-Kit-Doc mit OWASP/CWE-Mapping, gepaarte Fixtures (vuln+clean), TDD, Registry-Eintrag, Doku.

---

## Phase 6 — Release-Mechanik (P0 für „veröffentlicht", bewusst spät)

Die Endstufe. Braucht Nutzer-Entscheidungen (mit **★** markiert).

### 6.1 ☐ ★ `P0` — Vorab-Entscheidungen
- ☐ **PyPI-Paketname** final (ist `mcpfrisk` frei? prüfen). 
- ☐ **Zeitpunkt „public"** (Repo aktuell PRIVAT ohne GHAS).
- ☐ Versions-Schema (SemVer; Start `0.1.0` → erster Release ggf. `0.1.0` oder `0.2.0`).

### 6.2 ☐ `P0` `S` — Build- & Packaging-Verifikation
- ☐ `python -m build` erzeugt sdist + wheel; `twine check dist/*` grün.
- ☐ Install aus dem Wheel in frischer venv testen (`pip install dist/*.whl`, dann `mcpfrisk --version`, ein Scan).
- ☐ `MANIFEST.in` prüfen (kommen `action.yml`, Fixtures nicht ungewollt/erwünscht mit?).
- **Akzeptanz:** sauberes Wheel, funktionierender Install-Smoke-Test.

### 6.3 ☐ `P0` `S` — TestPyPI-Generalprobe
- ☐ Trusted Publishing gegen **TestPyPI** einrichten, einmal veröffentlichen, `pip install -i testpypi` verifizieren.
- **Akzeptanz:** erfolgreicher Test-Upload + Install.

### 6.4 ☐ `P0` `M` — Release-Workflow (PyPI Trusted Publishing / OIDC)
- ☐ `.github/workflows/release.yml`: auf Git-Tag `v*` → `python -m build` → `pypa/gh-action-pypi-publish` mit `permissions: id-token: write`, **ohne** Token/Passwort.
- ☐ **Sigstore-Attestations** (2026 default an bei Trusted Publishing) → passt zu unserem PACKAGE_PROVENANCE-Thema, aktiv lassen.
- ☐ Trust-Config auf PyPI: Repo + Workflow verknüpfen.
- ☐ GitHub Release mit CHANGELOG-Auszug automatisch.
- **Akzeptanz:** Tag `v0.1.0` publiziert tokenlos nach PyPI mit Attestation; `pip install mcpfrisk` funktioniert weltweit.

### 6.5 ☐ `P1` `S` — GitHub Marketplace (Action)
- ☐ `action.yml` mit Branding/Icon; Marketplace-Listing nach public.
- **Akzeptanz:** Action im Marketplace auffindbar; `uses: Imre7777/mcpfrisk@v1` funktioniert.

### 6.6 ☐ `P1` `S` — Release-Doku
- ☐ CHANGELOG „Unreleased" → versioniert; Release-Notes.
- ☐ README-Install auf `pip install mcpfrisk` umstellen (statt `-e .`), sobald live.

---

## Phase 7 — Produkt-/Wettbewerbserweiterung (P2, nach Launch)

### 7.1 ☐ `P2` `M` — Konfig-Datei `.mcpfrisk.toml`
- Severity-Overrides, Per-Check-Tuning, zentrale `--exclude`-Defaults, `--fail-on`-Default. Logischer nächster Schritt nach 022.

### 7.2 ☐ `P2` `M` — CI-native Ausgabeformate
- GitHub-Annotations (`::error file=…::`), JUnit-XML (GitLab/Jenkins), reines JSON-Streaming. Ergänzt SARIF+JSON.

### 7.3 ☐ `P2` `L` — Autofix / Remediation-Hinweise
- Pro Finding ein konkreter „so behebst du das"-Textbaustein; später evtl. echter `--autofix` (wie Semgrep).

### 7.4 ☐ `P2` `L` — Reichweite
- Scan per URL/npm-Name/Registry-Eintrag (nicht nur lokaler Pfad).
- VS-Code-Extension / LSP-Integration (Editor-Feedback in Echtzeit).

### 7.5 ☐ `P2` `M` — Doku-Site
- MkDocs/Material oder GitHub Pages: Check-Katalog (jede Regel mit CWE/OWASP + Beispiel), CI-Rezepte, FAQ.

---

## Anhang A — Aktueller Check-Katalog (19)

**Statisch (12):** CMD_INJECTION, PATH_TRAVERSAL, HARDCODED_SECRETS, TOOL_POISONING, TOOL_NAME_COLLISION, MCP_CONFIG_AUDIT, TOOL_DESCRIPTION_DRIFT, SCHEMA_DOCSTRING_MISMATCH, TYPOSQUAT, DEPENDENCY_SCAN, FALSE_ERROR_ESCALATION, PACKAGE_PROVENANCE.

**Dynamisch (7):** AUTH_BOUNDARY, SSRF_CHECK, RBAC_CROSS_TENANT, SCHEMA_FUZZING, ERROR_LEAKAGE, RATE_LIMITING, PROTOCOL_COMPLIANCE.

## Anhang B — Empfohlene Reihenfolge (kompakt)
1. **0.1** spawn-Array-FP (P0) → 2. **1.1–1.4** Härtung (CI-Matrix, Self-Scan, Supply-Chain) → 3. **2.x** Hygiene → 4. **4.1–4.3** Benchmark-Beweis → 5. **0.2** Collision-Scoping → 6. **5.x** neue Check-Kandidaten → 7. **6.x** Release → 8. **7.x** Produkt-Ausbau.

## Anhang C — Recherche-Quellen (2026-07-14)
- PyPI Trusted Publishing / OIDC / Attestations: docs.pypi.org/trusted-publishers, pypa/gh-action-pypi-publish
- MCP-Bedrohungslage 2026: Wiz „MCP Security in 2026", CSA „MCP Security Crisis" (OX-Security-SDK-Default, ~200k Instanzen), authzed „Timeline of MCP Breaches", NSA/CISA-MCP-Guidance, arXiv MCP-Threat-Modeling
- Ignore-/Exclude-Konventionen (für 022): semgrep `.semgrepignore`, gitleaks Allowlists/Baselines
