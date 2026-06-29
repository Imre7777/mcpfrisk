# MARKET-RESEARCH.md — Wettbewerbs- und Sicherheitslandschaft für mcpfrisk

**Stand der Recherche:** Ende Juni 2026. Das MCP-Sicherheitsökosystem
bewegt sich extrem schnell (mehrere neue Tools/Akquisitionen allein in
den letzten 6 Monaten vor diesem Dokument) — vor jeder größeren
strategischen Entscheidung lohnt sich eine erneute Stichprobe der
aktuellen Lage, nicht nur ein Blick in dieses Dokument.

---

## 1. Executive Summary

Der Kern-Befund dieser Recherche: **mcpfrisks ursprüngliche
Positionierung ("Pre-Deploy-Scanner für MCP-Server-Code") ist real,
aber nicht mehr unbesetzt.** Es gibt mindestens zwei direkte,
ernstzunehmende Konkurrenten in exakt dieser Nische — `agent-audit`
(HeadyZhang, 167 GitHub-Stars, PyPI-Paket, GitHub-Action,
SARIF-Output, 53 Regeln, akademisch validiert) und `mcp-sec-audit`
(akademisches Tool mit Docker/eBPF-Dynamic-Analysis, 100% Detection
auf dem MCPTox-Benchmark). Beide sind weiter fortgeschritten als
mcpfrisk aktuell ist.

Das ist kein Grund, das Projekt aufzugeben — aber ein klares Signal,
dass **"irgendein Pre-Deploy-Scanner sein" nicht reicht.** Um
tatsächlich besser zu sein, muss mcpfrisk sich auf konkrete,
nachweisbare Vorteile fokussieren: höhere Erkennungsgenauigkeit in
spezifischen Kategorien, eine Lücke, die `agent-audit` selbst offen
zugibt (JS/TS-Schwäche, nur Intra-Procedural-Taint-Analyse), oder eine
Nutzererfahrung/Integration, die die Konkurrenz nicht bietet.

Die gute Nachricht: der breitere Markt (Runtime-Gateways wie Lasso,
MintMCP, TrueFoundry, Akto; generische SAST-Tools wie Semgrep/CodeQL
ohne MCP-Support) deckt **eine andere Schicht des Problems** ab und
ist keine direkte Konkurrenz. Die akademische Forschung
(MCPSecBench, MSB, MCPTox, MCP-SafetyBench) liefert eine reiche,
noch nicht vollständig in Produkten umgesetzte Taxonomie von
Angriffstypen — das ist Munition für neue Checks, kein
Konkurrenzprodukt.

---

## 2. Direkte Konkurrenz: Pre-Deploy/Static-Analysis-Scanner für Agent-/MCP-Code

Das ist die Kategorie, in der mcpfrisk tatsächlich konkurriert. Drei
Tools fallen hier hinein, in absteigender Reife:

### 2.1 agent-audit (HeadyZhang) — der ernstzunehmendste Konkurrent

**Was es ist:** Ein statischer Sicherheitsscanner für LLM-Agent-Code
und MCP-Konfigurationen, der academisch fundiert ist (separates
arXiv-Paper, Zhang et al. 2026, "Agent Audit: A Security Analysis
System for LLM Agent Applications") und gleichzeitig als
produktionsreifes Open-Source-Tool existiert.

**Reife-Indikatoren:**
- 167 GitHub-Stars, 17 Forks, 13 Releases, aktiv gepflegt (letztes
  Release März 2026)
- Auf PyPI veröffentlicht (`pip install agent-audit`)
- Eigene GitHub Action (`HeadyZhang/agent-audit@v1`) mit
  SARIF-Upload in den GitHub-Security-Tab
- 1.239 Tests, MIT-lizenziert, 22.009 Zeilen Code über 58 Dateien
- Mehrsprachige Doku (README + README_CN)

**Funktionsumfang:**
- **53 Regeln**, vollständig auf alle 10 Kategorien des **OWASP
  Agentic Top 10 (2026)** gemappt (nicht nur den MCP-spezifischen
  Top 10, sondern den breiteren Agentic-Top-10-Rahmen)
- **Tool-Boundary-aware Taint-Tracking**: verfolgt Datenfluss von
  `@tool`-Funktionsparametern zu gefährlichen Senken (`eval`,
  `subprocess.run`, `cursor.execute`) inklusive
  Sanitization-Erkennung — das ist технически weiter als mcpfrisks
  aktuelles Ein-Ebenen-Taint-Tracking
- **MCP-Konfigurationsauditierung**: parst `claude_desktop_config.json`
  und MCP-Gateway-Configs auf unverifizierte Server-Quellen, zu
  breite Dateisystem-Berechtigungen, fehlende Authentifizierung,
  ungepinnte Paketversionen, Tool-Description-Poisoning,
  Cross-Server-Tool-Shadowing und Baseline-Drift (Rug-Pull) — eine
  Kategorie, die laut eigener Aussage von generischen SAST-Tools
  komplett übersehen wird
- **Dreistufige semantische Credential-Erkennung**: Regex-Kandidaten
  → Entropie-/Format-Scoring → Kontext-Anpassung nach Dateityp und
  Framework — deutlich ausgefeilter als mcpfrisks aktuelle
  Secret-Erkennung
- Framework-spezifische Erkennung für LangChain, CrewAI, AutoGen,
  AgentScope (mcpfrisk deckt das nicht ab, ist aber auch nicht der
  Anspruch)
- Output-Formate: Terminal, JSON, **SARIF** (GitHub Security Tab),
  Markdown
- **Baseline-Scanning**: nur neue Findings zwischen Commits
  reporten — eine UX-Funktion, die mcpfrisk fehlt
- Bereits als **OpenClaw-Skill** verfügbar, validiert gegen 18.899
  ClawHub-Skills

**Validierte Benchmark-Ergebnisse** (eigenes Benchmark
"Agent-Vuln-Bench", 19 Samples, 3 Kategorien):

| Tool | Recall | Precision | F1 |
|---|---|---|---|
| agent-audit | 94,6% | 87,5% | 0,91 |
| Bandit 1.8 | 29,7% | 100% | 0,46 |
| Semgrep 1.x | 27,0% | 100% | 0,43 |

Besonders relevant: bei der Kategorie "MCP Configuration" erreichen
sowohl Bandit als auch Semgrep **0% Recall** — kein generisches
SAST-Tool kann MCP-Configs überhaupt parsen. agent-audit erreicht
hier 100%.

**Bekannte Schwächen (von den Autoren selbst offen dokumentiert):**
- **Nur Intra-Procedural-Taint-Analyse** — kein Cross-Function- oder
  Cross-Module-Tracking. Ein Datenfluss, der über mehrere Funktionen
  hinweg läuft, wird nicht erkannt.
- **Python-fokussiert** — "Limited pattern matching for other
  languages" für JS/TS und andere Sprachen
- Tiefe Framework-Unterstützung nur für LangChain/CrewAI/AutoGen/
  AgentScope, alles andere nur generische `@tool`-Erkennungsregeln
- Reines **statisches** Tool — führt keinen Code aus, kann
  Laufzeit-only-Schwachstellen nicht erkennen

**Pricing:** Komplett kostenlos, MIT-Lizenz, kein kommerzielles
Angebot erkennbar (Stand der Recherche). Das ist sowohl eine
Bedrohung (kein Preisvorteil für mcpfrisk möglich) als auch eine
Entlastung (kein finanzierter Wettbewerber mit Vertriebsdruck).

### 2.2 mcp-sec-audit (akademisch, arXiv 2603.21641)

**Was es ist:** Ein "extensible security assessment toolkit",
explizit für MCP-Server entwickelt, das **statische UND dynamische**
Analyse kombiniert (Docker + eBPF für Sandbox-Fuzzing/Monitoring).

**Funktionsumfang:**
- Statische Pattern-Matching-Analyse für Python-MCP-Server
  (Capability-Erkennung: Command Execution, File I/O, Network)
- Dynamische Sandbox-Ausführung via Docker + eBPF-Monitoring auf
  Syscall-Ebene — das ist eine Fähigkeitsebene, die mcpfrisk (Tier 1,
  rein statisch) aktuell nicht hat und auch laut Roadmap erst in
  Tier 2 grob adressiert (ohne eBPF)
- Risiko-Scoring (0-100) mit Mitigation-Empfehlungen

**Benchmark-Ergebnisse:**
- **100% Detection-Rate** bei vorhandenen Capability-Indikatoren auf
  dem MCPTox-Benchmark (45 reale MCP-Server), aber nur **74,7%**
  Gesamt-Detection (25,3% der Samples hatten keine expliziten
  Indikatoren in den Metadaten)
- Auf dem "Vulnerable MCP Servers Lab" (9 absichtlich verwundbare
  Server, abdeckt RCE via eval(), Path Traversal, Prompt Injection,
  Typosquatting, Secrets, Dependency-CVEs): **100% Detection bei
  Python-Servern (2/2), aber 0% bei JavaScript-Servern (0/7)** —
  explizit wegen "current JavaScript/TypeScript AST parsing
  limitations"

**Wichtigste Erkenntnis für mcpfrisk:** Diese 0%-JS/TS-Schwäche ist
identisch zu agent-audits Python-Fokus. **Beide direkten Konkurrenten
haben dieselbe Lücke.** Wenn mcpfrisk hier signifikant bessere
JS/TS-Abdeckung aufbaut, ist das ein nachweisbarer, konkreter
Vorteil — nicht nur eine vage Behauptung.

**Reife/Verfügbarkeit:** Akademisches Paper, kein erkennbares
produktionsreifes öffentliches GitHub-Repo mit nennenswerter
Community-Aktivität zum Zeitpunkt der Recherche (anders als
agent-audit). Eher ein Forschungsprototyp als ein direkt
einsetzbares Konkurrenzprodukt — aber die Methodik (Docker+eBPF
Dynamic Analysis) ist eine Idee, die ein finanzierter Konkurrent
leicht produktisieren könnte.

### 2.3 Was generische SAST-Tools (Semgrep, CodeQL, Bandit) NICHT abdecken

Wichtige Bestätigung der Markt-Lücke: Ein offenes Feature-Request im
`IBM/mcp-context-forge`-Repo (Issue #2237, Januar 2026) fordert
explizit "MCP-specific security rules - Custom Semgrep/CodeQL for MCP
patterns", weil generische Regeln "Tool Response Injection, unsafe
argument handling, prompt injection vectors, credential exposure in
tool outputs, and MCP protocol misuse" nicht erkennen. Das ist zum
Zeitpunkt der Recherche noch offen — **es gibt keine offiziellen
MCP-Regelsets für Semgrep oder CodeQL.**

Semgrep selbst: $30/Committer/Monat für die Pro-Plattform (Community
Edition kostenlos, LGPL), ~10 Sekunden Scan-Zeit, 2.800+
Community-Regeln + 20.000+ Pro-Regeln, aber **null davon
MCP-spezifisch**.

CodeQL: kostenlos für öffentliche Repos, GHAS-Lizenz für private
Repos nötig, tiefere Taint-Analyse als Semgrep, aber **ebenfalls
keine MCP-Regeln**, 12 unterstützte Sprachen, Scan-Zeit Minuten bis
30+ Minuten.

**Implikation für mcpfrisk:** Diese beiden Tools sind keine direkte
Konkurrenz (sie adressieren MCP-Risiken überhaupt nicht), aber sie
sind eine **latente Bedrohung**: Sollte GitHub oder die Semgrep-Firma
beschließen, ein offizielles MCP-Regelset zu bauen, würde das die
Pre-Deploy-Nische sofort stark verändern — beide haben riesige
bestehende Distribution (CodeQL ist in jedem GitHub-Repo einen Klick
entfernt). Das ist ein Risiko, das im Auge behalten werden sollte,
aber kein Grund, jetzt nicht zu bauen.

---

## 3. Indirekte Konkurrenz: Endnutzer-/Runtime-Scanner

Diese Kategorie scannt **installierte** MCP-Server beim Endnutzer
oder zur Laufzeit — ein anderer Zeitpunkt im Lebenszyklus als
mcpfrisks Pre-Deploy-Fokus. Trotzdem relevant, weil viele Nutzer
diese Tools kennen und mcpfrisk gegen sie erklärt werden muss.

### 3.1 mcp-scan / Snyk Agent Scan (der Platzhirsch)

**Geschichte:** Ursprünglich von **Invariant Labs** (ETH-Zürich-Spinoff,
Co-Gründer Martin Vechev und Florian Tramèr) entwickelt, die den
Begriff "Tool Poisoning Attack" geprägt und die WhatsApp-MCP- und
GitHub-MCP-Exploits öffentlich dokumentiert haben. **Im Juni 2025 von
Snyk akquiriert.** Seitdem schrittweise zu "Snyk Agent Scan"
umgebrandet (aktuell parallel als `invariantlabs-ai/mcp-scan` und
`snyk/agent-scan` auf GitHub existent).

**Reife:** Über 2.000 GitHub-Stars, das mit Abstand am weitesten
verbreitete MCP-Sicherheitstool, aktuelle Version v0.4.13 (April 2026).

**Funktionsumfang:**
- Scannt **lokale Client-Configs** (Claude Desktop, Cursor, Claude
  Code, Gemini CLI, Windsurf) — verbindet sich zu konfigurierten
  Servern und liest Tool-Beschreibungen aus
- Nutzt sowohl lokale Checks als auch die **Invariant/Snyk
  Guardrails API** (Cloud) für Tool-Poisoning-Klassifikation —
  Tool-Namen und -Beschreibungen werden dafür an Snyk übertragen
  (Datenschutz-Implikation, die mcpfrisk als rein-lokales Tool nicht
  hat)
- **Tool Pinning** via Hashing zur Rug-Pull-Erkennung
- **Proxy-Modus**: injiziert temporär ein Invariant-Gateway in die
  Server-Config, um Live-Traffic zu überwachen und Guardrails
  (PII-Detection, Secrets-Detection, Tool-Restriktionen) durchzusetzen
- Erkennt Cross-Origin-Escalation (Tool-Shadowing)

**Snyks größere Strategie (Stand Mai/Juni 2026):** Snyk hat "Agent
Security" als drei-schichtiges Produkt angekündigt: Agent Scan (Open
Preview, Discovery), Agent Guard (Private Preview, Runtime-Enforcement)
und Evo AI-SPM (GA, AI-Security-Posture-Management über 9.700+
Entwicklungsumgebungen hinweg). Das positioniert Snyk klar als
**Enterprise-Plattform-Spieler**, nicht als Pre-Deploy-Dev-Tool — eine
andere Zielgruppe als mcpfrisk, aber mit erheblich mehr Kapital und
Distribution (4.800+ Kunden laut eigener Aussage).

**Pricing:** Das CLI-Tool selbst (`mcp-scan`) ist Open-Source und
kostenlos (Apache 2.0). Snyks generelles Preismodell: Free-Tier
vorhanden, Team-Tier ab ca. $52-98/Entwickler/Monat (je nach
Bundle), Enterprise individuell verhandelt. Agent Scan/Security ist
zum Zeitpunkt der Recherche noch in "Open Preview"/"Private Preview"
— eigenständiges Pricing dafür noch nicht klar etabliert, vermutlich
Teil eines größeren Snyk-Bundles.

**Warum das keine direkte mcpfrisk-Konkurrenz ist:** Anderer
Zeitpunkt (Endnutzer-Installation statt CI/Pre-Deploy), anderer
technischer Ansatz (Cloud-Klassifikator statt rein-lokale
Heuristiken), andere Zielgruppe (Endnutzer von Claude
Desktop/Cursor statt Server-Autoren). mcpfrisk sollte sich in
Dokumentation klar davon abgrenzen, aber nicht versuchen, es zu
ersetzen.

### 3.2 Enterprise-Gateways (Runtime-Governance — eigene Kategorie)

Diese Tools sitzen **zwischen** Agent und MCP-Server zur Laufzeit und
erzwingen Policies. Komplett andere Architektur als ein statischer
Scanner. Kurzüberblick, da relevant für die Gesamteinordnung des
Marktes, aber keine direkte Konkurrenz:

| Tool | Fokus | Besonderheit |
|---|---|---|
| **Lasso Security** | Threat Detection, Echtzeit | 2024 Gartner Cool Vendor, Plugin-Architektur, Tool-Reputation-Scoring |
| **MintMCP** | Compliance-First | SOC 2 Type II zertifiziert, Cursor-Partnerschaft, Role-Based-Endpoints |
| **TrueFoundry** | Performance | 3-4ms Latenz, OAuth-Identity-Injection, VPC-Deployment |
| **Akto** | All-in-One Discovery+Runtime | Gartner-anerkannt, Red-Teaming-Funktion |
| **Peta** | Credential-Isolation | Scoped/time-limited Tokens statt Raw-API-Keys |
| **CyberMCP** | API-Pentesting via LLM-Agenten | Open-Source, fokussiert auf Backend-API-Härtung |
| **Composio** | Integrationsbreite | 500+ verwaltete Integrationen, empfiehlt sich selbst als Default für 90% der Teams |

**Gemeinsamer Nenner:** Alle adressieren **Runtime-Governance für
Unternehmen**, die bereits viele MCP-Server im Einsatz haben — nicht
das "ist mein Server-Code beim Schreiben sicher"-Problem, das
mcpfrisk löst. Diese Tools sind potenzielle **Partner/nachgeschaltete
Empfehlung** für mcpfrisk-Nutzer, die nach dem Pre-Deploy-Scan auch
Runtime-Schutz brauchen — keine Konkurrenten im engeren Sinn.

---

## 4. Die akademische Forschungslandschaft: Taxonomien und Benchmarks

Diese Arbeiten sind keine Konkurrenzprodukte, aber **die Quelle für
neue Check-Ideen** — sie katalogisieren systematisch Angriffstypen,
die noch nicht alle in produktiven Tools abgedeckt sind.

### 4.1 MCPSecBench (arXiv 2508.13220)

Erste systematische Taxonomie der MCP-Sicherheit: **17 Angriffstypen
über 4 Angriffsoberflächen** (Client, Protocol, Server, Host).
Wichtigstes empirisches Ergebnis: **über 85% der identifizierten
Angriffe kompromittieren mindestens eine Plattform** (getestet gegen
Claude, OpenAI, Cursor), und **bestehende Schutzmechanismen erreichen
im Schnitt unter 30% Erfolgsrate** bei der Abwehr — ein deutliches
Signal, dass der Status Quo an Verteidigung schwach ist.

Die vier Surfaces im Detail:
- **Host:** Konfigurationsfehler, DoS, unauthentifizierter Zugriff,
  Command Injection in Host-Operationen
- **Client:** sicheres Prompt-Parsing, Tool-Auswahl-Resistenz gegen
  böswillige Inputs
- **Protocol:** Datenintegrität/Vertraulichkeit gegen Manipulation/
  Abhören
- **Server:** sichere, verifizierte Tool-Ausführung mit konsistenten
  Ergebnissen

### 4.2 MSB — MCP Security Bench (arXiv 2510.15994)

**12 Angriffskategorien** über die drei Phasen Task-Planning,
Tool-Invocation, Response-Handling: Name-Collision, Preference
Manipulation, Prompt Injection in Tool-Beschreibungen,
Out-of-Scope-Parameter-Anfragen, User-Impersonating Responses,
False-Error-Escalation, Tool-Transfer, Retrieval Injection, sowie
gemischte Angriffe. 2.000+ Angriffsinstanzen, 65 reale Aufgaben,
400+ Tools, getestet gegen 9 populäre LLM-Agenten über 10 Domains.
Führt eine neue Metrik ein: **Net Resilient Performance (NRP)**, die
den Trade-off zwischen Sicherheit und Funktionsfähigkeit quantifiziert
(ein Agent, der aus Vorsicht *alles* blockiert, ist auch nicht
nützlich — NRP bestraft das).

### 4.3 MCPTox (arXiv 2508.14925)

Der Benchmark, gegen den `mcp-sec-audit` getestet wurde. Fokus
spezifisch auf **Tool Poisoning Attacks (TPA)** als eigene
Angriffskategorie, die sich fundamental von klassischer Indirect
Prompt Injection unterscheidet: TPA kompromittiert den Agenten **vor
der Ausführung** (über die Tool-Beschreibung selbst), nicht über
nachträglich verarbeitete Tool-Ausgaben. Getestet gegen reale
MCP-Server, nicht nur simulierte Umgebungen.

### 4.4 MCP-SafetyBench

**20 atomare Angriffe**, feingranular nach Protokoll-Layer und Vektor
unterschieden. Mehrstufig, Cross-Server, Execution-based-Evaluation
gegen reale MCP-Server in realistischen Domains — methodisch die
anspruchsvollste der vier Benchmarks.

### 4.5 Was das für mcpfrisk bedeutet

Zusammengenommen katalogisieren diese vier Arbeiten weit mehr
Angriffsmuster, als irgendein einzelnes Produkt (inklusive
agent-audit) heute abdeckt. Konkrete Lücken, die sich daraus für
neue mcpfrisk-Checks ableiten lassen (über die bestehende Tier-2-/
Tier-3-Roadmap hinaus):

- **Name-Collision-Angriffe** (MSB): zwei Tools mit identischem oder
  sehr ähnlichem Namen über verschiedene Server — eine Variante von
  Tool-Shadowing, die spezifisch auf Namenskonflikte statt auf
  Beschreibungs-Manipulation abzielt. Aktuell von keinem der
  betrachteten Produkt-Tools explizit benannt.
- **False-Error-Escalation** (MSB): ein Server, der absichtlich
  Fehler simuliert, um den Agenten zu alternativen (kompromittierten)
  Tools zu drängen — ein Muster, das sich statisch über verdächtige
  Fehlerbehandlungs-Pfade in Tool-Implementierungen erkennen ließe.
- **Out-of-Scope-Parameter-Anfragen** (MSB): ein Tool, das mehr
  Parameter anfordert/akzeptiert, als seine Beschreibung erwarten
  lässt — statisch über einen Abgleich Schema-vs-Docstring-Umfang
  prüfbar, eine Variante, die mcpfrisks aktuelle Checks nicht
  abdecken.

---

## 5. Wo mcpfrisk aktuell steht (ehrliche Selbsteinschätzung)

| Dimension | mcpfrisk (aktuell) | agent-audit | mcp-sec-audit |
|---|---|---|---|
| Regelanzahl | 4 | 53 | "configurable rules", nicht klar quantifiziert |
| OWASP-Mapping | Teilweise (OWASP MCP Top 10, nicht Agentic Top 10) | Vollständig, alle 10 ASI-Kategorien | Nicht erkennbar |
| Taint-Tracking | Eine Ebene (direkte Zuweisungen) | Tool-boundary-aware, aber nur intra-procedural | Nicht spezifiziert |
| JS/TS-Abdeckung | Nur 1 von 4 Checks (Command Injection) | "Limited pattern matching" | 0% (explizit dokumentiert) |
| Dynamische Analyse | Keine (nur Tier-1 statisch) | Keine (rein statisch) | Ja (Docker + eBPF) |
| CI-Integration | Eigener GitHub-Actions-Workflow | Offizielle GitHub Action, SARIF-Upload | Nicht erkennbar |
| Validierung | 17 eigene Unit-Tests gegen 2 Fixtures | 1.239 Tests, externes Benchmark (94,6% Recall) | MCPTox-Benchmark (100%/74,7%) |
| Community/Reife | Neu, 0 Stars | 167 Stars, 17 Forks, 13 Releases | Akademisches Paper, geringe sichtbare Adoption |
| Baseline-Diffing | Nicht vorhanden | Vorhanden (`--baseline`) | Nicht erkennbar |
| Lizenz | Apache 2.0 | MIT | Nicht klar |

**Ehrliches Fazit:** In der direkten Pre-Deploy-Scanner-Kategorie ist
mcpfrisk aktuell der am wenigsten ausgereifte der drei Anbieter.
Das ist keine Überraschung für ein Projekt im Tag-1-Stadium — aber
es bedeutet, dass "einfach weiterbauen wie geplant" nicht reicht, um
"besser und umfangreicher" zu werden. Es braucht eine bewusste
Differenzierungsstrategie (siehe Abschnitt 6).

---

## 6. Differenzierungsstrategie: Wie mcpfrisk tatsächlich besser werden kann

Basierend auf den oben identifizierten Lücken, geordnet nach
Aufwand/Nutzen-Verhältnis:

### 6.1 Kurzfristig erreichbar, hoher Differenzierungswert

**JS/TS-Erstklassigkeit statt Python-Only.** Beide direkten
Konkurrenten haben hier eine dokumentierte Schwäche
(`mcp-sec-audit`: 0% Detection bei JS/TS; agent-audit: "limited
pattern matching" außerhalb Python). MCP-Server werden zu einem
erheblichen Anteil in TypeScript/Node.js gebaut (das offizielle
TypeScript-SDK ist neben Python das primäre SDK). Wenn mcpfrisk hier
echte AST-basierte Analyse (nicht nur Regex wie aktuell bei
`CMD_INJECTION`) für alle vier bestehenden Checks aufbaut, ist das
ein **nachweisbarer, benchmarkbarer Vorteil** gegen beide direkten
Konkurrenten — keine vage Behauptung, sondern eine Zahl, die man
Seite an Seite zeigen kann (z.B. "100% Detection bei JS/TS-Fixtures,
wo mcp-sec-audit 0% erreicht").

**Cross-Function-Taint-Tracking.** agent-audit gibt offen zu, nur
intra-procedural zu verfolgen. Ein mehrstufiges Taint-Tracking, das
auch über Funktionsgrenzen hinweg verfolgt (z.B. via eines simplen
Call-Graphs für den Python-AST), wäre eine konkrete technische
Überlegenheit in exakt der Dimension, die der härteste Konkurrent
selbst als Schwäche benennt.

**Baseline-/Diff-Scanning.** agent-audit hat es, mcpfrisk nicht.
Relativ einfach zu bauen (Findings nach Datei+Zeile+Check-ID hashen,
gegen eine gespeicherte Baseline-JSON vergleichen), aber wichtig für
echte CI-Workflows, wo Teams nicht bei jedem Scan alle historischen
Findings neu sehen wollen.

### 6.2 Mittelfristig, differenziert klar gegen Konkurrenz

**Eigene Checks aus den akademischen Benchmarks, die noch kein
Produkt abdeckt** (siehe Abschnitt 4.5): Name-Collision-Erkennung,
Schema-vs-Docstring-Parameter-Abgleich. Das wäre nicht "das Gleiche
wie agent-audit nachbauen", sondern echte zusätzliche Abdeckung, die
aktuell in **keinem** der untersuchten Produkte existiert.

**Die Tier-2-Roadmap (AUTH_BOUNDARY, RBAC_CROSS_TENANT) konsequent
umsetzen.** Wichtig: `mcp-sec-audit` macht zwar bereits dynamische
Analyse, aber fokussiert auf Capability-Erkennung
(Command-Exec/File-I/O/Network), nicht auf Auth-Boundary-Tests oder
RBAC-Cross-Tenant-Leckage im eigentlichen Sinn. Das ist eine Lücke,
die mcpfrisks ursprüngliche Roadmap bereits richtig identifiziert
hatte — die Recherche bestätigt das, statt es zu widerlegen.

### 6.3 Strategisch, höherer Aufwand

**Ein eigenes, öffentliches Benchmark-Ergebnis gegen ein etabliertes
Set veröffentlichen** (z.B. gegen das öffentlich verfügbare
"Vulnerable MCP Servers Lab" von appsecco, das auch `mcp-sec-audit`
zur Validierung nutzte). Reproduzierbare, vergleichbare Zahlen sind
das, was agent-audit von einem generischen Marketing-Claim
unterscheidet — dieselbe Glaubwürdigkeitsstrategie ist für mcpfrisk
nachvollziehbar und realistisch nachbaubar.

**GitHub Action + SARIF-Output.** agent-audit hat beides, mcpfrisk
aktuell nur einen rohen CI-Workflow im eigenen Repo. SARIF ist der
Standard, den GitHub Code Scanning erwartet — ohne das bleibt
mcpfrisk für GitHub-native Teams eine Stufe unbequemer in der
Integration als die Konkurrenz.

### 6.4 Bewusst NICHT nachbauen

**Framework-spezifische Erkennung (LangChain/CrewAI/AutoGen).** Das
ist agent-audits Spielfeld, nicht MCP-spezifisch, und würde den
Fokus von mcpfrisk verwässern. mcpfrisks Alleinstellungsmerkmal ist
gerade die **MCP-spezifische Tiefe** (Tool-Poisoning-Pattern, MCP-
Protokoll-Eigenheiten) statt allgemeine Agent-Framework-Breite.

**Cloud-Klassifikatoren wie Invariant/Snyk Guardrails.** Das würde
mcpfrisks "zero dependency, läuft komplett lokal"-Versprechen
brechen und eine Abhängigkeit zu einem API-Anbieter schaffen — ein
bewusster Architektur-Tradeoff, den die Konkurrenz eingeht und
mcpfrisk laut bisheriger Constitution-Entscheidung nicht eingehen
sollte (siehe CONTEXT.md, Prinzip 4: Zero Dependencies für Tier 1).

---

## 7. Priorisierte Roadmap-Anpassung (konkrete Reihenfolge)

Basierend auf der Differenzierungsstrategie oben, eine angepasste
Priorisierung relativ zur bisherigen Roadmap aus CONTEXT.md:

1. **JS/TS-AST-Analyse für alle 4 bestehenden Checks** (statt nur
   Regex bei Command Injection) — höchste Priorität, weil es die am
   klarsten nachweisbare, benchmarkbare Lücke beider direkten
   Konkurrenten schließt, bevor überhaupt neue Checks dazukommen.
   *Begründung: Ein Tool, das in seiner Kern-Sprache schwächer ist
   als die Konkurrenz, gewinnt nicht durch mehr Checks — erst die
   Tiefe in den bestehenden Checks sichern, dann in die Breite gehen.*

2. **Baseline-/Diff-Scanning** — vergleichsweise einfach umzusetzen,
   schließt eine konkrete UX-Lücke gegen agent-audit, hoher
   Nutzen für CI-Alltagstauglichkeit.

3. **SARIF-Output + offizielle GitHub Action** — Standard-Erwartung
   für GitHub-native Teams, ohne das wirkt mcpfrisk im direkten
   Vergleich technisch unterlegen, unabhängig von der tatsächlichen
   Erkennungsqualität.

4. **Cross-Function-Taint-Tracking** — technisch anspruchsvoller,
   aber die Dimension, in der sich mcpfrisk am klarsten von
   agent-audits selbst-eingeräumter Schwäche abheben kann.

5. **Tier-2-Checks wie geplant** (AUTH_BOUNDARY zuerst, dann
   RBAC_CROSS_TENANT) — weiterhin relevant und von keinem der
   direkten Konkurrenten in dieser Form abgedeckt, aber zeitlich
   nach den Punkten 1-4, weil die Tiefe in Tier 1 zuerst
   wettbewerbsfähig sein muss.

6. **Eigene Checks aus der akademischen Taxonomie**
   (Name-Collision, Schema-vs-Docstring-Mismatch) — niedrigere
   Priorität, weil Nice-to-have-Differenzierung statt
   Lücken-Schließung gegenüber bestehender Konkurrenz, aber
   langfristig das Argument für "umfangreicher als alle anderen".

7. **Öffentliches Benchmark-Ergebnis** gegen das Vulnerable-MCP-
   Servers-Lab — als Marketing-/Glaubwürdigkeits-Meilenstein, sobald
   Punkte 1-4 stehen und ein fairer Vergleich überhaupt aussagekräftig
   wäre (vorher gegen die eigenen, noch dünnen Checks zu benchmarken,
   würde nur die eigene Unterlegenheit dokumentieren).

---

## 8. Offene Fragen aus dieser Recherche

- **Wie genau ist `mcp-sec-audit` lizenziert und wie aktiv wird es
  weiterentwickelt?** Das Paper ist von März 2026, aber ein klar
  sichtbares, aktiv gepflegtes öffentliches Repo mit Stars/Issues/
  Releases wurde in dieser Recherche nicht gefunden — könnte ein
  reiner Forschungs-Prototyp ohne Produktionsambition sein, oder
  könnte sich das in den nächsten Monaten ändern. Lohnt sich, vor
  größeren strategischen Entscheidungen erneut zu prüfen.
- **Wird Snyk oder GitHub in absehbarer Zeit MCP-spezifische
  CodeQL-/Semgrep-Regeln nachziehen?** Das offene IBM-Issue zeigt
  Nachfrage danach. Sollte das passieren, würde sich die
  Wettbewerbslandschaft für Pre-Deploy-Scanning grundlegend
  verschieben (beide Tools haben riesige bestehende Distribution).
- **Lohnt sich eine Kooperation/Integration statt reiner Konkurrenz
  zu agent-audit?** Beide Tools sind Open-Source unter permissiven
  Lizenzen (Apache 2.0 / MIT) — denkbar wäre z.B., dass mcpfrisk sich
  auf MCP-Tiefe + JS/TS spezialisiert und explizit als Ergänzung zu
  agent-audits breiterer Agent-Framework-Abdeckung positioniert,
  statt als 1:1-Ersatz. Das ist eine strategische Entscheidung, keine
  technische — sollte bewusst getroffen werden, nicht stillschweigend
  passieren.
